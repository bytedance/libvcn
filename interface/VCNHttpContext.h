/*
 * HTTP protocol for ffmpeg client
 * Copyright (c) 2000, 2001 Fabrice Bellard
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 * 
 * This file may have been modified by Bytedance Inc. ("Bytedance Modifications"). 
 * All Bytedance Modifications are Copyright 2023 Bytedance Inc.
 * 
 * This file may have been modified by Bytedance Inc. ("Bytedance Modifications"). 
 * All Bytedance Modifications are Copyright 2023 Bytedance Inc.
 */
#pragma once
#include "VCNBase.h"
#include "VCNSocketInfo.h"
#include <stdint.h>
#include <zlib.h>
#include <string>
#include <map>
extern "C" {
    #include "vcn_url.h"
}

#include "VCNHttpParserBase.h"

NS_VCN_BEGIN
class VCNDNSParserInterface;
enum VCNHttpParserError {
    IsContextNullError = -100000,
    IsExternDNSParseError = -99999,
    IsFileSizeNotMatch = -99998,
    IsLowSpeedError = -99991,
    IsHiJackErrorHeader = -99990,
    IsSandBoxNotAllowError = -99989,
};
#define BUFFER_SIZE 8192
#define HTTP_HEADERS_SIZE 8192
/**
 * Authentication types, ordered from weakest to strongest.
 */
typedef enum HTTPAuthType {
    HTTP_AUTH_NONE = 0,    /**< No authentication specified */
    HTTP_AUTH_BASIC,       /**< HTTP 1.0 Basic auth from RFC 1945
                            *  (also in RFC 2617) */
    HTTP_AUTH_DIGEST,      /**< HTTP 1.1 Digest auth from RFC 2617 */
} HTTPAuthType;

typedef struct DigestParams {
    char nonce[300];       /**< Server specified nonce */
    char algorithm[10];    /**< Server specified digest algorithm */
    char qop[30];          /**< Quality of protection, containing the one
                            *  that we've chosen to use, from the
                            *  alternatives that the server offered. */
    char opaque[300];      /**< A server-specified string that should be
                            *  included in authentication responses, not
                            *  included in the actual digest calculation. */
    char stale[10];        /**< The server indicated that the auth was ok,
                            * but needs to be redone with a new, non-stale
                            * nonce. */
    int nc;                /**< Nonce count, the number of earlier replies
                            *  where this particular nonce has been used. */
} DigestParams;

/**
 * HTTP Authentication state structure. Must be zero-initialized
 * before used with the functions below.
 */
typedef struct HTTPAuthState {
    /**
     * The currently chosen auth type.
     */
    int auth_type;
    /**
     * Authentication realm
     */
    char realm[200];
    /**
     * The parameters specific to digest authentication.
     */
    DigestParams digest_params;
    /**
     * Auth ok, but needs to be resent with a new nonce.
     */
    int stale;
} HTTPAuthState;
typedef enum {
    VCN_LOWER_PROTO,
    VCN_READ_HEADERS,
    VCN_WRITE_REPLY_HEADERS,
    VCN_WRITE_REPLY_DATA,
    VCN_FINISH
}VCNHandshakeState;
typedef struct  VCNHttpContext {
    VCNURLContext *hd;
    int flags;
    char  host_ip[132];
    unsigned char buffer[BUFFER_SIZE], *buf_ptr, *buf_end;
    int line_count;
    int http_code;
    /* Used if "Transfer-Encoding: chunked" otherwise -1. */
    uint64_t chunksize;
    uint64_t off, end_off, filesize;
    uint64_t request_off, request_end_off;
    int64_t bodyReadSize;
    int64_t httpFirstPacketT;
    char *location;
    HTTPAuthState auth_state;
    HTTPAuthState proxy_auth_state;
    char *http_proxy;
    char *headers;
    char *mime_type;
    char *user_agent;
    char *content_type;
    /* Set if the server correctly handles Connection: close and will close
     * the connection after feeding us the content. */
    int willclose;
    int seekable;           /**< Control seekability, 0 = disable, 1 = enable, -1 = probe. */
    int is_streamed;
    int chunked_post;
    /* A flag which indicates if the end of chunked encoding has been sent. */
    int end_chunked_post;
    /* A flag which indicates we have finished to read POST reply. */
    int end_header;
    /* A flag which indicates if we use persistent connections. */
    int multiple_requests;
    uint8_t *post_data;
    int post_datalen;
    int is_akamai;
    int is_mediagateway;
    char *cookies;          ///< holds newline (\n) delimited Set-Cookie header field values (without the "Set-Cookie: " field name)
    /* A dictionary containing cookies keyed by cookie name */
    AVDictionary *cookie_dict;
    int icy;
    /* how much data was read since the last ICY metadata packet */
    uint64_t icy_data_read;
    /* after how many bytes of read data a new metadata packet will be found */
    uint64_t icy_metaint;
    char *icy_metadata_headers;
    char *icy_metadata_packet;
    AVDictionary *metadata;
    /*for zlib*/
    int compressed;
    z_stream inflate_stream;
    uint8_t *inflate_buffer;
    AVDictionary *chained_options;
    int send_expect_100;
    char *method;
    int reconnect;
    int reconnect_count;
    int reconnect_at_eof;
    int reconnect_streamed;
    int reconnect_delay;
    int reconnect_delay_max;
    int listen;
    char *resource;
    int reply_code;
    int is_multi_client;
    VCNHandshakeState handshake_step;
    int is_connected_server;
    int is_redirect;
    int is_err_continue;
    int open_timeout;
    char* valid_http_content_type;
    uint64_t recv_size;
    int64_t log_handle;
    AVNetIOInterruptCB interrupt_callback;
    std::map<std::string, std::string> receivedHeader;
    VCNDNSParserInterface *parser;
    void *wrapper;
    char *connectedIp;
    char *connectedHost;
    char* mRequestAccessCheck;
    char* mResponseAccessCheck;
    int  port;
    int lowerProto;
    int  forceHttps;
    int isttfb;
    int maxIPV6Num;
    int maxIPV4Num;
    int forbidByPassCookie;
    int force_chunk;
    bool chunk_eof;
    VCNSocketInfo socketInfo;
    int reserved_code;
    int isUnlimitHttpHeader;
    char *customHost;
    int dns_type;

    VCNHttpParserNotifyer* parserNotifyer;
    VCNHttpParserHelper*   parserHelper;
    VCNHttpParserStrategy*  parserStrategy;
    VCNHttpParserSocketInfoManager* socketInfoManager;

}VCNHttpContext;


VCNHttpContext* VCN_INTERFACE_EXPORT createHttpContext();
int VCN_INTERFACE_EXPORT releaseHttpContext(VCNHttpContext** context);
NS_VCN_END
