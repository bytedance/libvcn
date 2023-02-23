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
 */

#include "config.h"

#if CONFIG_ZLIB
#include <zlib.h>
#endif /* CONFIG_ZLIB */

#include "libutil/vcn_assert.h"
#include "vcn_avstring.h"
#include "vcn_opt.h"
#include "vcn_time.h"
#include "vcn_internal.h"
#include "vcn_error.h"
#include "vcn_dict.h"
#include "vcn_mem.h"
#include "http.h"
#include "httpauth.h"
#include "network.h"
#include "os_support.h"


#include "vcn_avio.h"
#include "vcn_utils.h"
#include "vcn_format_version.h"

/* XXX: POST protocol is not completely implemented because ffmpeg uses
 * only a subset of it. */

/* The IO buffer size is unrelated to the max URL size in itself, but needs
 * to be large enough to fit the full request headers (including long
 * path names). */
#define BUFFER_SIZE   MAX_URL_SIZE
#define MAX_REDIRECTS 8
#define HTTP_SINGLE   1
#define HTTP_MUTLI    2
#define HTTP_RECONNECT
typedef enum {
    LOWER_PROTO,
    READ_HEADERS,
    WRITE_REPLY_HEADERS,
    FINISH
}HandshakeState;

typedef struct VCNHTTPContext {
    const AVClass *class;
    VCNURLContext *hd;
    int64_t log_handle;
    char  host_ip[132];
    unsigned char buffer[BUFFER_SIZE], *buf_ptr, *buf_end;
    int line_count;
    int http_code;
    /* Used if "Transfer-Encoding: chunked" otherwise -1. */
    uint64_t chunksize;
    uint64_t off, end_off, filesize;
    char *location;
    HTTPAuthState auth_state;
    HTTPAuthState proxy_auth_state;
    char *http_proxy;
    char *headers;
    char *mime_type;
    char *user_agent;
#if FF_API_HTTP_USER_AGENT
    char *user_agent_deprecated;
#endif
    char *content_type;
    /* Set if the server correctly handles Connection: close and will close
     * the connection after feeding us the content. */
    int willclose;
    int seekable;           /**< Control seekability, 0 = disable, 1 = enable, -1 = probe. */
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
#if CONFIG_ZLIB
    int compressed;
    z_stream inflate_stream;
    uint8_t *inflate_buffer;
#endif /* CONFIG_ZLIB */
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
    HandshakeState handshake_step;
    int is_connected_server;
    int is_redirect;
    char* valid_http_content_type;
} VCNHTTPContext;

#define OFFSET(x) offsetof(VCNHTTPContext, x)
#define D AV_OPT_FLAG_DECODING_PARAM
#define E AV_OPT_FLAG_ENCODING_PARAM
#define DEFAULT_USER_AGENT "ttplayer(default)" AV_STRINGIFY(LIBAVFORMAT_VERSION)

static const AVOption options[] = {
    { "seekable", "control seekability of connection", OFFSET(seekable), AV_OPT_TYPE_BOOL, { .i64 = -1 }, -1, 1, D },
    { "log_handle", "set log handle for log", OFFSET(log_handle), AV_OPT_TYPE_UINT64, { .i64 = 0 }, 0, UINT64_MAX, .flags = D|E },
    { "chunked_post", "use chunked transfer-encoding for posts", OFFSET(chunked_post), AV_OPT_TYPE_BOOL, { .i64 = 1 }, 0, 1, E },
    { "http_proxy", "set HTTP proxy to tunnel through", OFFSET(http_proxy), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "headers", "set custom HTTP headers, can override built in default headers", OFFSET(headers), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "content_type", "set a specific content type for the POST messages", OFFSET(content_type), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "user_agent", "override User-Agent header", OFFSET(user_agent), AV_OPT_TYPE_STRING, { .str = DEFAULT_USER_AGENT }, 0, 0, D },
#if FF_API_HTTP_USER_AGENT
    { "user-agent", "override User-Agent header", OFFSET(user_agent_deprecated), AV_OPT_TYPE_STRING, { .str = DEFAULT_USER_AGENT }, 0, 0, D },
#endif
    { "multiple_requests", "use persistent connections", OFFSET(multiple_requests), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D | E },
    { "post_data", "set custom HTTP post data", OFFSET(post_data), AV_OPT_TYPE_BINARY, .flags = D | E },
    { "mime_type", "export the MIME type", OFFSET(mime_type), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, AV_OPT_FLAG_EXPORT | AV_OPT_FLAG_READONLY },
    { "cookies", "set cookies to be sent in applicable future requests, use newline delimited Set-Cookie HTTP field value syntax", OFFSET(cookies), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D },
    { "icy", "request ICY metadata", OFFSET(icy), AV_OPT_TYPE_BOOL, { .i64 = 1 }, 0, 1, D },
    { "icy_metadata_headers", "return ICY metadata headers", OFFSET(icy_metadata_headers), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, AV_OPT_FLAG_EXPORT },
    { "icy_metadata_packet", "return current ICY metadata packet", OFFSET(icy_metadata_packet), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, AV_OPT_FLAG_EXPORT },
    { "metadata", "metadata read from the bitstream", OFFSET(metadata), AV_OPT_TYPE_DICT, {0}, 0, 0, AV_OPT_FLAG_EXPORT },
    { "auth_type", "HTTP authentication type", OFFSET(auth_state.auth_type), AV_OPT_TYPE_INT, { .i64 = HTTP_AUTH_NONE }, HTTP_AUTH_NONE, HTTP_AUTH_BASIC, D | E, "auth_type"},
    { "none", "No auth method set, autodetect", 0, AV_OPT_TYPE_CONST, { .i64 = HTTP_AUTH_NONE }, 0, 0, D | E, "auth_type"},
    { "basic", "HTTP basic authentication", 0, AV_OPT_TYPE_CONST, { .i64 = HTTP_AUTH_BASIC }, 0, 0, D | E, "auth_type"},
    { "send_expect_100", "Force sending an Expect: 100-continue header for POST", OFFSET(send_expect_100), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, E },
    { "location", "The actual location of the data received", OFFSET(location), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "offset", "initial byte offset", OFFSET(off), AV_OPT_TYPE_INT64, { .i64 = 0 }, 0, INT64_MAX, D },
    { "end_offset", "try to limit the request to bytes preceding this offset", OFFSET(end_off), AV_OPT_TYPE_INT64, { .i64 = 0 }, 0, INT64_MAX, D },
    { "method", "Override the HTTP method or set the expected HTTP method from a client", OFFSET(method), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "reconnect", "auto reconnect after disconnect before EOF", OFFSET(reconnect), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "reconnect_at_eof", "auto reconnect at EOF", OFFSET(reconnect_at_eof), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "reconnect_streamed", "auto reconnect streamed / non seekable streams", OFFSET(reconnect_streamed), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "reconnect_count", "reconnect count", OFFSET(reconnect_count), AV_OPT_TYPE_INT, { .i64 = 3 }, 0, 3, D },
    { "reconnect_delay_max", "max reconnect delay in seconds after which to give up", OFFSET(reconnect_delay_max), AV_OPT_TYPE_INT, { .i64 = 120 }, 0, UINT_MAX/1000/1000, D },
    { "listen", "listen on HTTP", OFFSET(listen), AV_OPT_TYPE_INT, { .i64 = 0 }, 0, 2, D | E },
    { "resource", "The resource requested by a client", OFFSET(resource), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, E },
    { "reply_code", "The http status code to return to a client", OFFSET(reply_code), AV_OPT_TYPE_INT, { .i64 = 200}, INT_MIN, 599, E},
    { "valid_http_content_type", "valid http content type", OFFSET(valid_http_content_type), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D },
    { "is_redirect", "is auto redirect", OFFSET(is_redirect), AV_OPT_TYPE_BOOL, { .i64 = 1 }, 0, 1, D },
    { NULL }
};

static int http_connect(VCNURLContext *h, const char *path, const char *local_path,
                        const char *hoststr, const char *auth,
                        const char *proxyauth, int *new_location);
static int http_read_header(VCNURLContext *h, int *new_location);
static int has_header(const char *str, const char *header);

void ff_http_init_auth_state(VCNURLContext *dest, const VCNURLContext *src)
{
    memcpy(&((VCNHTTPContext *)dest->priv_data)->auth_state,
           &((VCNHTTPContext *)src->priv_data)->auth_state,
           sizeof(HTTPAuthState));
    memcpy(&((VCNHTTPContext *)dest->priv_data)->proxy_auth_state,
           &((VCNHTTPContext *)src->priv_data)->proxy_auth_state,
           sizeof(HTTPAuthState));
}
//extern const char *vcn_tcp_get_ip_addr(VCNURLContext *h);
static void http_save_tcp_hostname_of_ip(VCNHTTPContext *s)
{
     const char *ip_str = NULL;

     if(s->hd == NULL) {
         return;
     }

     ip_str = vcn_tcp_get_ip_addr(s->hd);

     if(ip_str != NULL && ip_str[0] != '\0' && strlen(ip_str) <= sizeof(s->host_ip)) {
         memcpy(s->host_ip, ip_str, strlen(ip_str));
     }
     return;
}
static int http_open_cnx_internal(VCNURLContext *h, AVDictionary **options)
{
    const char *path, *proxy_path, *lower_proto = "tcp", *local_path;
    char hostname[1024], hoststr[1024], proto[10];
    char auth[1024], proxyauth[1024] = "";
    char path1[MAX_URL_SIZE];
    char buf[1024], urlbuf[MAX_URL_SIZE];
    int port, use_proxy, err, location_changed = 0;
    VCNHTTPContext *s = h->priv_data;
    if(h->interrupt_callback.callback != NULL && vcn_ff_check_interrupt(&h->interrupt_callback)) {
        return AVERROR_EXIT;
    }
    vcn_av_url_split(proto, sizeof(proto), auth, sizeof(auth),
                 hostname, sizeof(hostname), &port,
                 path1, sizeof(path1), s->location);
    vcn_url_join(hoststr, sizeof(hoststr), NULL, NULL, hostname, port, NULL);

    proxy_path = s->http_proxy ? s->http_proxy : getenv("http_proxy");
    use_proxy  = !vcn_http_match_no_proxy(getenv("no_proxy"), hostname) &&
                 proxy_path && vcn_av_strstart(proxy_path, "http://", NULL);

    if (!strcmp(proto, "https")) {
        lower_proto = "tls";
        use_proxy   = 0;
        if (port < 0)
            port = 443;
    }
    if (port < 0)
        port = 80;

    if (path1[0] == '\0')
        path = "/";
    else
        path = path1;
    local_path = path;
    if (use_proxy) {
        /* Reassemble the request URL without auth string - we don't
         * want to leak the auth to the proxy. */
        vcn_url_join(urlbuf, sizeof(urlbuf), proto, NULL, hostname, port, "%s",
                    path1);
        path = urlbuf;
        vcn_av_url_split(NULL, 0, proxyauth, sizeof(proxyauth),
                     hostname, sizeof(hostname), &port, NULL, 0, proxy_path);
    }

    vcn_url_join(buf, sizeof(buf), lower_proto, NULL, hostname, port, NULL);

    if (!s->hd) {
        err = vcn_url_open_whitelist(&s->hd, buf, AVIO_FLAG_READ_WRITE,
                                   &h->interrupt_callback, options,
                                   h->protocol_whitelist, h->protocol_blacklist, h);
        if (err < 0)
            return err;
    }

    err = http_connect(h, path, local_path, hoststr,
                       auth, proxyauth, &location_changed);
    if (err < 0)
        return err;

    return location_changed;
}

static int http_split_str(const char** str, char splitChar, int* len) {
    const char* begin = *str;
    if (str != NULL && begin != NULL && *begin != 0x0) {
        while(*begin == splitChar) {
            begin++;
        }
        *str = begin;

        *len = 0;
        while (*begin != 0x0 && *begin != splitChar) {
            begin++;
            *len = (*len) + 1;
        }
        if (len > 0) {
            return 0;
        }
    }
    return -1;
}

static int http_get_context_type(const char* header, char* contentType, int bufferSize) {
    int err = 0;
    if (header == NULL || *header == 0x0) {
        return -1;
    }
    int i = 0;
    const size_t bufLen = strlen(header);
    for (i = 0; i<bufLen; i++) {
        const char* cur = header + i;
        if (*cur == 'C' || *cur == 'c') {
            if (strncasecmp("Content-Type:", cur, 13) == 0) {
                const int offset = 14;
                size_t len = strlen(cur);
                if (len > offset && len - offset < MAX_URL_SIZE) {
                    const char* begin = cur + offset;
                    char* dst = contentType;
                    int size = 0;
                    while (*begin != ' ' && *begin != ';' && size < bufferSize && size < MAX_URL_SIZE) {
                        *dst = *begin;
                        dst++;
                        begin++;
                        size++;
                    }
                    *dst = 0x0;
                }
                break;
            }
        }
    }
    return err;
}
static int http_check_content_type(VCNHTTPContext*s) {
    int ret = 0;
    if (s->valid_http_content_type != NULL) {
        const char* str = s->valid_http_content_type;
        int len = 0;
        int find = 0;
        const int contentTypeMaxSize = 128;
        char contentType[128];
        if (http_get_context_type(s->buffer, contentType, contentTypeMaxSize) == 0) {
            int contentSize = strlen(contentType);
            while( http_split_str(&str, ' ', &len) == 0 ) {
                if (contentSize == len) {
                    if( strncasecmp(str, contentType, len) == 0 ) {
                        find = 1;
                        break;
                    }
                }
                str += len;
            }
            if (find == 0) {
                ret = AVERROR_CONTEXT_TYPE_IS_INVALID;
            }
        }
    }
    return ret;
}
/* return non zero if error */
static int http_open_cnx(VCNURLContext *h, AVDictionary **options)
{
    HTTPAuthType cur_auth_type, cur_proxy_auth_type;
    VCNHTTPContext *s = h->priv_data;
    int location_changed, attempts = 0, redirects = 0, ret = 0;
redo:
    vcn_av_dict_copy(options, s->chained_options, 0);

    cur_auth_type       = s->auth_state.auth_type;
    cur_proxy_auth_type = s->auth_state.auth_type;

    location_changed = http_open_cnx_internal(h, options);

    if (location_changed < 0) {
        goto fail;
    }

    attempts++;
    int status_code = s->http_code;
    if (status_code >= 200 && status_code < 300) {
        int ret = http_check_content_type(s);
        if (ret != 0) {
            goto fail;
        }
    }
    if (s->http_code == 401) {
        if ((cur_auth_type == HTTP_AUTH_NONE || s->auth_state.stale) &&
            s->auth_state.auth_type != HTTP_AUTH_NONE && attempts < 4) {
            vcn_url_closep(&s->hd);
            goto redo;
        } else {
            goto fail;
        }
    }
    if (s->http_code == 407) {
        if ((cur_proxy_auth_type == HTTP_AUTH_NONE || s->proxy_auth_state.stale) &&
            s->proxy_auth_state.auth_type != HTTP_AUTH_NONE && attempts < 4) {
            vcn_url_closep(&s->hd);
            goto redo;
        } else {
            goto fail;
        }
    }
    if ((s->http_code == 301 || s->http_code == 302 ||
         s->http_code == 303 || s->http_code == 307 ||
         s->http_code == 308) &&
        location_changed == 1) {
        /* url moved, get next */
        if ( !s->is_redirect) {// redirect
            ret = AVERROR_HTTP_REDIRECT;
            goto fail;
        }

		vcn_url_closep(&s->hd);
        if (redirects++ >= MAX_REDIRECTS){
            //vcn_av_error(h, AVERROR_HTTP_REDIRECT_COUNT_OUT,"http error");
            return AVERROR(EIO);
        }
        /* Restart the authentication process with the new target, which
         * might use a different auth mechanism. */
        memset(&s->auth_state, 0, sizeof(s->auth_state));
        attempts         = 0;
        location_changed = 0;
        goto redo;
    }
    http_save_tcp_hostname_of_ip(s);
    return 0;

fail:
    if (s->hd)
        vcn_url_closep(&s->hd);
    if (location_changed < 0) {
        return location_changed;
    }
    if (ret != 0) {
        //vcn_av_error(h, ret, s->buffer);
	    return ret;
    }
    ret = ff_http_averror(s->http_code, AVERROR(EIO));
	if ( ret == AVERROR(EIO) ) {
		//vcn_av_error(h, AVERROR_HTTP_DEFAULT_ERROR, s->buffer);
	} else {
		//vcn_av_error(h, ret, s->buffer);
	}
    return ret;
}

int ff_http_do_new_request(VCNURLContext *h, const char *uri)
{
    VCNHTTPContext *s = h->priv_data;
    AVDictionary *options = NULL;
    int ret;

    s->off           = 0;
    s->icy_data_read = 0;
    vcn_av_free(s->location);
    s->location = vcn_av_strdup(uri);
    if (!s->location){
        //vcn_av_trace(h,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
        return AVERROR(ENOMEM);
    }

    ret = http_open_cnx(h, &options);
    vcn_av_dict_free(&options);
    return ret;
}

int ff_http_averror(int status_code, int default_averror)
{
    switch (status_code) {
        case 400: return AVERROR_HTTP_BAD_REQUEST;
        case 401: return AVERROR_HTTP_UNAUTHORIZED;
        case 403: return AVERROR_HTTP_FORBIDDEN;
        case 404: return AVERROR_HTTP_NOT_FOUND;
        default: break;
    }
    if (status_code >= 400 && status_code <= 499)
        return AVERROR_HTTP_OTHER_4XX;
    else if (status_code >= 500)
        return AVERROR_HTTP_SERVER_ERROR;
    else
        return default_averror;
}

static int http_write_reply(VCNURLContext* h, int status_code)
{
    int ret, body = 0, reply_code, message_len;
    const char *reply_text, *content_type;
    VCNHTTPContext *s = h->priv_data;
    char message[BUFFER_SIZE];
    content_type = "text/plain";

    if (status_code < 0)
        body = 1;
    switch (status_code) {
    case AVERROR_HTTP_BAD_REQUEST:
    case 400:
        reply_code = 400;
        reply_text = "Bad Request";
        break;
    case AVERROR_HTTP_FORBIDDEN:
    case 403:
        reply_code = 403;
        reply_text = "Forbidden";
        break;
    case AVERROR_HTTP_NOT_FOUND:
    case 404:
        reply_code = 404;
        reply_text = "Not Found";
        break;
    case 200:
        reply_code = 200;
        reply_text = "OK";
        content_type = s->content_type ? s->content_type : "application/octet-stream";
        break;
    case AVERROR_HTTP_SERVER_ERROR:
    case 500:
        reply_code = 500;
        reply_text = "Internal server error";
        break;
    default:
        //vcn_av_trace(h,AVERROR(EINVAL),"AVERROR(EINVAL)");
        return AVERROR(EINVAL);
    }
    if (body) {
        s->chunked_post = 0;
        message_len = snprintf(message, sizeof(message),
                 "HTTP/1.1 %03d %s\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Length: %"SIZE_SPECIFIER"\r\n"
                 "%s"
                 "\r\n"
                 "%03d %s\r\n",
                 reply_code,
                 reply_text,
                 content_type,
                 strlen(reply_text) + 6, // 3 digit status code + space + \r\n
                 s->headers ? s->headers : "",
                 reply_code,
                 reply_text);
    } else {
        s->chunked_post = 1;
        message_len = snprintf(message, sizeof(message),
                 "HTTP/1.1 %03d %s\r\n"
                 "Content-Type: %s\r\n"
                 "Transfer-Encoding: chunked\r\n"
                 "%s"
                 "\r\n",
                 reply_code,
                 reply_text,
                 content_type,
                 s->headers ? s->headers : "");
    }
    vcn_av_log(h, AV_LOG_TRACE, "HTTP reply header: \n%s----\n", message);
    if ((ret = vcn_url_write(s->hd, message, message_len)) < 0)
        return ret;
    return 0;
}

static void handle_http_errors(VCNURLContext *h, int error)
{
    av_assert0(error < 0);
    http_write_reply(h, error);
}

static int vcn_http_handshake(VCNURLContext *c)
{
    int ret, err, new_location;
    VCNHTTPContext *ch = c->priv_data;
    VCNURLContext *cl = ch->hd;
    switch (ch->handshake_step) {
    case LOWER_PROTO:
        vcn_av_log(c, AV_LOG_TRACE, "Lower protocol\n");
        if ((ret = vcn_url_handshake(cl)) > 0)
            return 2 + ret;
        if (ret < 0)
            return ret;
        ch->handshake_step = READ_HEADERS;
        ch->is_connected_server = 1;
        return 2;
    case READ_HEADERS:
        vcn_av_log(c, AV_LOG_TRACE, "Read headers\n");
        if ((err = http_read_header(c, &new_location)) < 0) {
            handle_http_errors(c, err);
            return err;
        }
        ch->handshake_step = WRITE_REPLY_HEADERS;
        return 1;
    case WRITE_REPLY_HEADERS:
        vcn_av_log(c, AV_LOG_TRACE, "Reply code: %d\n", ch->reply_code);
        if ((err = http_write_reply(c, ch->reply_code)) < 0)
            return err;
        ch->handshake_step = FINISH;
        return 1;
    case FINISH:
        return 0;
    }
    // this should never be reached.
    //vcn_av_trace(ch,AVERROR(EINVAL),"AVERROR(EINVAL)");
    return AVERROR(EINVAL);
}

static int http_listen(VCNURLContext *h, const char *uri, int flags,
                       AVDictionary **options) {
    VCNHTTPContext *s = h->priv_data;
    int ret;
    char hostname[1024], proto[10];
    char lower_url[100];
    const char *lower_proto = "tcp";
    int port;
    vcn_av_url_split(proto, sizeof(proto), NULL, 0, hostname, sizeof(hostname), &port,
                 NULL, 0, uri);
    if (!strcmp(proto, "https"))
        lower_proto = "tls";
    vcn_url_join(lower_url, sizeof(lower_url), lower_proto, NULL, hostname, port,
                NULL);
    if ((ret = vcn_av_dict_set_int(options, "listen", s->listen, 0)) < 0){
		//vcn_av_trace(s,ret,"ret:%d", ret);
        goto fail;
	}
    if ((ret = vcn_url_open_whitelist(&s->hd, lower_url, AVIO_FLAG_READ_WRITE,
                                    &h->interrupt_callback, options,
                                    h->protocol_whitelist, h->protocol_blacklist, h
                                   )) < 0)
        goto fail;
    s->handshake_step = LOWER_PROTO;
    if (s->listen == HTTP_SINGLE) { /* single client */
        s->reply_code = 200;
        while ((ret = vcn_http_handshake(h)) > 0);
    }
fail:
    vcn_av_dict_free(&s->chained_options);
    return ret;
}

static int vcn_http_open(VCNURLContext *h, const char *uri, int flags,
                     AVDictionary **options)
{
    VCNHTTPContext *s = h->priv_data;
    int ret;

    if( s->seekable == 1 )
        h->is_streamed = 0;
    else
        h->is_streamed = 1;

    s->filesize = UINT64_MAX;
    s->location = vcn_av_strdup(uri);
    if (!s->location){
        //vcn_av_trace(s,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
        return AVERROR(ENOMEM);
    }
    if (options)
        vcn_av_dict_copy(&s->chained_options, *options, 0);

    if (s->headers) {
        int len = strlen(s->headers);
        if (len < 2 || strcmp("\r\n", s->headers + len - 2)) {
            vcn_av_log(h, AV_LOG_WARNING,
                   "No trailing CRLF found in HTTP header.\n");
            ret = vcn_av_reallocp(&s->headers, len + 3);
            if (ret < 0){
                //vcn_av_trace(s,ret,"ret:%d", ret);
                return ret;
            }
            s->headers[len]     = '\r';
            s->headers[len + 1] = '\n';
            s->headers[len + 2] = '\0';
        }
    }

    if (s->listen) {
        return http_listen(h, uri, flags, options);
    }
    ret = http_open_cnx(h, options);
    if (ret < 0)
        vcn_av_dict_free(&s->chained_options);
    return ret;
}

static int vcn_http_accept(VCNURLContext *s, VCNURLContext **c)
{
    int ret;
    VCNHTTPContext *sc = s->priv_data;
    VCNHTTPContext *cc;
    VCNURLContext *sl = sc->hd;
    VCNURLContext *cl = NULL;

    av_assert0(sc->listen);
    if ((ret = vcn_url_alloc(c, s->filename, s->flags, &sl->interrupt_callback)) < 0)
        goto fail;
    cc = (*c)->priv_data;
    if ((ret = vcn_url_accept(sl, &cl)) < 0)
        goto fail;
    cc->hd = cl;
    cc->is_multi_client = 1;
fail:
    return ret;
}

static int http_getc(VCNHTTPContext *s)
{
    int len;
    if (s->buf_ptr >= s->buf_end) {
        len = vcn_url_read(s->hd, s->buffer, BUFFER_SIZE);
        if (len < 0) {
            return len;
        } else if (len == 0) {
            /*although the connection is closed ordely but the header not be read completely,return EIO error*/
            //vcn_av_trace(s,AVERROR(EIO),"AVERROR(EIO)");
            return AVERROR(EIO);
        } else {
            s->buf_ptr = s->buffer;
            s->buf_end = s->buffer + len;
        }
    }
    return *s->buf_ptr++;
}

static int http_get_line(VCNHTTPContext *s, char *line, int line_size)
{
    int ch;
    char *q;

    q = line;
    for (;;) {
        ch = http_getc(s);
        if (ch < 0)
            return ch;
        if (ch == '\n') {
            /* process line */
            if (q > line && q[-1] == '\r')
                q--;
            *q = '\0';

            return 0;
        } else {
            if ((q - line) < line_size - 1)
                *q++ = ch;
        }
    }
}

static int check_http_code(VCNURLContext *h, int http_code, const char *end)
{
    VCNHTTPContext *s = h->priv_data;
    /* error codes are 4xx and 5xx, but regard 401 as a success, so we
     * don't abort until all headers have been parsed. */
    if (http_code >= 400 && http_code < 600 &&
        (http_code != 401 || s->auth_state.auth_type != HTTP_AUTH_NONE) &&
        (http_code != 407 || s->proxy_auth_state.auth_type != HTTP_AUTH_NONE)) {
        end += strspn(end, SPACE_CHARS);
        vcn_av_log(h, AV_LOG_WARNING, "HTTP error %d %s\n", http_code, end);
        //vcn_av_trace(s,AVERROR(EIO),"AVERROR(EIO)");
        return ff_http_averror(http_code, AVERROR(EIO));
    }
    return 0;
}

static int parse_location(VCNHTTPContext *s, const char *p)
{
    char redirected_location[MAX_URL_SIZE], *new_loc;
    vcn_ff_make_absolute_url(redirected_location, sizeof(redirected_location),
                         s->location, p);
    new_loc = vcn_av_strdup(redirected_location);
    if (!new_loc){
        //vcn_av_trace(s,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
        return AVERROR(ENOMEM);
    }
    vcn_av_free(s->location);
    s->location = new_loc;
    return 0;
}

/* "bytes $from-$to/$document_size" */
static void parse_content_range(VCNURLContext *h, const char *p)
{
    VCNHTTPContext *s = h->priv_data;
    const char *slash;

    if (!strncmp(p, "bytes ", 6)) {
        p     += 6;
        s->off = strtoull(p, NULL, 10);
        if ((slash = strchr(p, '/')) && strlen(slash) > 0)
            s->filesize = strtoull(slash + 1, NULL, 10);
    }
    if (s->seekable == -1 && (!s->is_akamai || s->filesize != 2147483647))
        h->is_streamed = 0; /* we _can_ in fact seek */
}

static int parse_content_encoding(VCNURLContext *h, const char *p)
{
    if (!vcn_av_strncasecmp(p, "gzip", 4) ||
        !vcn_av_strncasecmp(p, "deflate", 7)) {
#if CONFIG_ZLIB
        VCNHTTPContext *s = h->priv_data;

        s->compressed = 1;
        inflateEnd(&s->inflate_stream);
        if (inflateInit2(&s->inflate_stream, 32 + 15) != Z_OK) {
            vcn_av_log(h, AV_LOG_WARNING, "Error during zlib initialisation: %s\n",
                   s->inflate_stream.msg);
            //vcn_av_trace(s,AVERROR(ENOSYS),"AVERROR(ENOSYS)");
            return AVERROR(ENOSYS);
        }
        if (zlibCompileFlags() & (1 << 17)) {
            vcn_av_log(h, AV_LOG_WARNING,
                   "Your zlib was compiled without gzip support.\n");
            //vcn_av_trace(s,AVERROR(ENOSYS),"AVERROR(ENOSYS)");
            return AVERROR(ENOSYS);
        }
#else
        vcn_av_log(h, AV_LOG_WARNING,
               "Compressed (%s) content, need zlib with gzip support\n", p);
        //vcn_av_trace(h,AVERROR(ENOSYS),"AVERROR(ENOSYS)");
        return AVERROR(ENOSYS);
#endif /* CONFIG_ZLIB */
    } else if (!vcn_av_strncasecmp(p, "identity", 8)) {
        // The normal, no-encoding case (although servers shouldn't include
        // the header at all if this is the case).
    } else {
        vcn_av_log(h, AV_LOG_WARNING, "Unknown content coding: %s\n", p);
    }
    return 0;
}

// Concat all Icy- header lines
static int parse_icy(VCNHTTPContext *s, const char *tag, const char *p)
{
    int len = 4 + strlen(p) + strlen(tag);
    int is_first = !s->icy_metadata_headers;
    int ret;

    vcn_av_dict_set(&s->metadata, tag, p, 0);

    if (s->icy_metadata_headers)
        len += strlen(s->icy_metadata_headers);

    if ((ret = vcn_av_reallocp(&s->icy_metadata_headers, len)) < 0)
        return ret;

    if (is_first)
        *s->icy_metadata_headers = '\0';

    vcn_av_strlcatf(s->icy_metadata_headers, len, "%s: %s\n", tag, p);

    return 0;
}

static int parse_cookie(VCNHTTPContext *s, const char *p, AVDictionary **cookies)
{
    char *eql, *name;

    // duplicate the cookie name (dict will dupe the value)
    if (!(eql = strchr(p, '='))) {
        //vcn_av_trace(s,AVERROR(EINVAL),"AVERROR(EINVAL)");
        return AVERROR(EINVAL);
    }
    if (!(name = vcn_av_strndup(p, eql - p))){
        //vcn_av_trace(s,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
        return AVERROR(ENOMEM);
    }

    // add the cookie to the dictionary
    vcn_av_dict_set(cookies, name, eql, AV_DICT_DONT_STRDUP_KEY);

    return 0;
}

static int cookie_string(AVDictionary *dict, char **cookies)
{
    AVDictionaryEntry *e = NULL;
    int len = 1;

    // determine how much memory is needed for the cookies string
    while (e = vcn_av_dict_get(dict, "", e, AV_DICT_IGNORE_SUFFIX))
        len += strlen(e->key) + strlen(e->value) + 1;

    // reallocate the cookies
    e = NULL;
    if (*cookies) vcn_av_free(*cookies);
    *cookies = vcn_av_malloc(len);
    if (!*cookies) {
        //vcn_av_trace(NULL,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
        return AVERROR(ENOMEM);
    }
    *cookies[0] = '\0';

    // write out the cookies
    while (e = vcn_av_dict_get(dict, "", e, AV_DICT_IGNORE_SUFFIX))
        vcn_av_strlcatf(*cookies, len, "%s%s\n", e->key, e->value);

    return 0;
}

static int process_line(VCNURLContext *h, char *line, int line_count,
                        int *new_location)
{
    VCNHTTPContext *s = h->priv_data;
    const char *auto_method =  h->flags & AVIO_FLAG_READ ? "POST" : "GET";
    char *tag, *p, *end, *method, *resource, *version;
    int ret;

    /* end of header */
    if (line[0] == '\0') {
        s->end_header = 1;
        return 0;
    }

    p = line;
    if (line_count == 0) {
        if (s->is_connected_server) {
            // HTTP method
            method = p;
            while (*p && !av_isspace(*p))
                p++;
            *(p++) = '\0';
            vcn_av_log(h, AV_LOG_TRACE, "Received method: %s\n", method);
            if (s->method) {
                if (vcn_av_strcasecmp(s->method, method)) {
                    vcn_av_log(h, AV_LOG_ERROR, "Received and expected HTTP method do not match. (%s expected, %s received)\n",
                           s->method, method);
                    return ff_http_averror(400, AVERROR(EIO));
                }
            } else {
                // use autodetected HTTP method to expect
                vcn_av_log(h, AV_LOG_TRACE, "Autodetected %s HTTP method\n", auto_method);
                if (vcn_av_strcasecmp(auto_method, method)) {
                    vcn_av_log(h, AV_LOG_ERROR, "Received and autodetected HTTP method did not match "
                           "(%s autodetected %s received)\n", auto_method, method);
                    return ff_http_averror(400, AVERROR(EIO));
                }
                if (!(s->method = vcn_av_strdup(method))){
                    //vcn_av_trace(h,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
                    return AVERROR(ENOMEM);
                }
            }

            // HTTP resource
            while (av_isspace(*p))
                p++;
            resource = p;
            while (!av_isspace(*p))
                p++;
            *(p++) = '\0';
            vcn_av_log(h, AV_LOG_TRACE, "Requested resource: %s\n", resource);
            if (!(s->resource = vcn_av_strdup(resource))){
                //vcn_av_trace(h,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
                return AVERROR(ENOMEM);
            }

            // HTTP version
            while (av_isspace(*p))
                p++;
            version = p;
            while (*p && !av_isspace(*p))
                p++;
            *p = '\0';
            if (vcn_av_strncasecmp(version, "HTTP/", 5)) {
                vcn_av_log(h, AV_LOG_ERROR, "Malformed HTTP version string.\n");
                return ff_http_averror(400, AVERROR(EIO));
            }
            vcn_av_log(h, AV_LOG_TRACE, "HTTP version string: %s\n", version);
        } else {
            while (!av_isspace(*p) && *p != '\0')
                p++;
            while (av_isspace(*p))
                p++;
            s->http_code = strtol(p, &end, 10);

            vcn_av_log(h, AV_LOG_TRACE, "http_code=%d\n", s->http_code);

            if ((ret = check_http_code(h, s->http_code, end)) < 0){
                //vcn_av_trace(h,ret,"ret:%d",ret);
                return ret;
            }
        }
    } else {
        while (*p != '\0' && *p != ':')
            p++;
        if (*p != ':')
            return 1;

        *p  = '\0';
        tag = line;
        p++;
        while (av_isspace(*p))
            p++;
        if (!vcn_av_strcasecmp(tag, "Location")) {
            if ((ret = parse_location(s, p)) < 0){
                //vcn_av_trace(h,ret,"ret:%d", ret);
                return ret;
            }
            *new_location = 1;
        } else if (!vcn_av_strcasecmp(tag, "Content-Length") &&
                   s->filesize == UINT64_MAX) {
            s->filesize = strtoull(p, NULL, 10);
        } else if (!vcn_av_strcasecmp(tag, "Content-Range")) {
            parse_content_range(h, p);
        } else if (!vcn_av_strcasecmp(tag, "Accept-Ranges") &&
                   !strncmp(p, "bytes", 5) &&
                   s->seekable == -1) {
            h->is_streamed = 0;
        } else if (!vcn_av_strcasecmp(tag, "Transfer-Encoding") &&
                   !vcn_av_strncasecmp(p, "chunked", 7)) {
            s->filesize  = UINT64_MAX;
            s->chunksize = 0;
        } else if (!vcn_av_strcasecmp(tag, "WWW-Authenticate")) {
            ff_http_auth_handle_header(&s->auth_state, tag, p);
        } else if (!vcn_av_strcasecmp(tag, "Authentication-Info")) {
            ff_http_auth_handle_header(&s->auth_state, tag, p);
        } else if (!vcn_av_strcasecmp(tag, "Proxy-Authenticate")) {
            ff_http_auth_handle_header(&s->proxy_auth_state, tag, p);
        } else if (!vcn_av_strcasecmp(tag, "Connection")) {
            if (!strcmp(p, "close"))
                s->willclose = 1;
        } else if (!vcn_av_strcasecmp(tag, "Server")) {
            if (!vcn_av_strcasecmp(p, "AkamaiGHost")) {
                s->is_akamai = 1;
            } else if (!vcn_av_strncasecmp(p, "MediaGateway", 12)) {
                s->is_mediagateway = 1;
            }
        } else if (!vcn_av_strcasecmp(tag, "Content-Type")) {
            vcn_av_free(s->mime_type);
            s->mime_type = vcn_av_strdup(p);
        } else if (!vcn_av_strcasecmp(tag, "Set-Cookie")) {
            if (parse_cookie(s, p, &s->cookie_dict))
                vcn_av_log(h, AV_LOG_WARNING, "Unable to parse '%s'\n", p);
        } else if (!vcn_av_strcasecmp(tag, "Icy-MetaInt")) {
            s->icy_metaint = strtoull(p, NULL, 10);
        } else if (!vcn_av_strncasecmp(tag, "Icy-", 4)) {
            if ((ret = parse_icy(s, tag, p)) < 0){
                //vcn_av_trace(h,ret,"ret:%d", ret);
                return ret;
            }
        } else if (!vcn_av_strcasecmp(tag, "Content-Encoding")) {
            if ((ret = parse_content_encoding(h, p)) < 0){
                //vcn_av_trace(h,ret,"ret:%d", ret);
                return ret;
            }
        }
    }
    return 1;
}

/**
 * Create a string containing cookie values for use as a HTTP cookie header
 * field value for a particular path and domain from the cookie values stored in
 * the HTTP protocol context. The cookie string is stored in *cookies.
 *
 * @return a negative value if an error condition occurred, 0 otherwise
 */
static int get_cookies(VCNHTTPContext *s, char **cookies, const char *path,
                       const char *domain)
{
    // cookie strings will look like Set-Cookie header field values.  Multiple
    // Set-Cookie fields will result in multiple values delimited by a newline
    int ret = 0;
    char *next, *cookie, *set_cookies = vcn_av_strdup(s->cookies), *cset_cookies = set_cookies;

    if (!set_cookies) {
        //vcn_av_trace(s,AVERROR(EINVAL),"AVERROR(EINVAL)");
        return AVERROR(EINVAL);
    }

    // destroy any cookies in the dictionary.
    vcn_av_dict_free(&s->cookie_dict);

    *cookies = NULL;
    while ((cookie = vcn_av_strtok(set_cookies, "\n", &next))) {
        int domain_offset = 0;
        char *param, *next_param, *cdomain = NULL, *cpath = NULL, *cvalue = NULL;
        set_cookies = NULL;

        // store the cookie in a dict in case it is updated in the response
        if (parse_cookie(s, cookie, &s->cookie_dict))
            vcn_av_log(s, AV_LOG_WARNING, "Unable to parse '%s'\n", cookie);

        while ((param = vcn_av_strtok(cookie, "; ", &next_param))) {
            if (cookie) {
                // first key-value pair is the actual cookie value
                cvalue = vcn_av_strdup(param);
                cookie = NULL;
            } else if (!vcn_av_strncasecmp("path=",   param, 5)) {
                vcn_av_free(cpath);
                cpath = vcn_av_strdup(&param[5]);
            } else if (!vcn_av_strncasecmp("domain=", param, 7)) {
                // if the cookie specifies a sub-domain, skip the leading dot thereby
                // supporting URLs that point to sub-domains and the master domain
                int leading_dot = (param[7] == '.');
                vcn_av_free(cdomain);
                cdomain = vcn_av_strdup(&param[7+leading_dot]);
            } else {
                // ignore unknown attributes
            }
        }
        if (!cdomain)
            cdomain = vcn_av_strdup(domain);

        // ensure all of the necessary values are valid
        if (!cdomain || !cpath || !cvalue) {
            vcn_av_log(s, AV_LOG_WARNING,
                   "Invalid cookie found, no value, path or domain specified\n");
            goto done_cookie;
        }

        // check if the request path matches the cookie path
        if (vcn_av_strncasecmp(path, cpath, strlen(cpath)))
            goto done_cookie;

        // the domain should be at least the size of our cookie domain
        domain_offset = strlen(domain) - strlen(cdomain);
        if (domain_offset < 0)
            goto done_cookie;

        // match the cookie domain
        if (vcn_av_strcasecmp(&domain[domain_offset], cdomain))
            goto done_cookie;

        // cookie parameters match, so copy the value
        if (!*cookies) {
            if (!(*cookies = vcn_av_strdup(cvalue))) {
                //vcn_av_trace(s,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
                ret = AVERROR(ENOMEM);
                goto done_cookie;
            }
        } else {
            char *tmp = *cookies;
            size_t str_size = strlen(cvalue) + strlen(*cookies) + 3;
            if (!(*cookies = vcn_av_malloc(str_size))) {
                //vcn_av_trace(s,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
                ret = AVERROR(ENOMEM);
                goto done_cookie;
            }
            snprintf(*cookies, str_size, "%s; %s", tmp, cvalue);
            vcn_av_free(tmp);
        }

        done_cookie:
        vcn_av_freep(&cdomain);
        vcn_av_freep(&cpath);
        vcn_av_freep(&cvalue);
        if (ret < 0) {
            if (*cookies) vcn_av_freep(cookies);
            vcn_av_free(cset_cookies);
            return ret;
        }
    }

    vcn_av_free(cset_cookies);

    return 0;
}

static inline int has_header(const char *str, const char *header)
{
    /* header + 2 to skip over CRLF prefix. (make sure you have one!) */
    if (!str)
        return 0;
    return vcn_av_stristart(str, header + 2, NULL) || vcn_av_stristr(str, header);
}

static int http_read_header(VCNURLContext *h, int *new_location)
{
    VCNHTTPContext *s = h->priv_data;
    char line[MAX_URL_SIZE];
    int err = 0;

    s->chunksize = UINT64_MAX;

    for (;;) {
        if ((err = http_get_line(s, line, sizeof(line))) < 0)
            return err;

        vcn_av_log(h, AV_LOG_TRACE, "header='%s'\n", line);

        err = process_line(h, line, s->line_count, new_location);
        if (err < 0)
            return err;
        if (err == 0)
            break;
        s->line_count++;
    }

    if (s->seekable == -1 && s->is_mediagateway && s->filesize == 2000000000)
        h->is_streamed = 1; /* we can in fact _not_ seek */

    // add any new cookies into the existing cookie string
    cookie_string(s->cookie_dict, &s->cookies);
    vcn_av_dict_free(&s->cookie_dict);

    return err;
}

static int http_connect(VCNURLContext *h, const char *path, const char *local_path,
                        const char *hoststr, const char *auth,
                        const char *proxyauth, int *new_location)
{
    VCNHTTPContext *s = h->priv_data;
    int post, err;
    char headers[HTTP_HEADERS_SIZE] = "";
    char *authstr = NULL, *proxyauthstr = NULL;
    uint64_t off = s->off;
    int len = 0;
    const char *method;
    int send_expect_100 = 0;

    /* send http header */
    post = h->flags & AVIO_FLAG_WRITE;

    if (s->post_data) {
        /* force POST method and disable chunked encoding when
         * custom HTTP post data is set */
        post            = 1;
        s->chunked_post = 0;
    }

    if (s->method)
        method = s->method;
    else
        method = post ? "POST" : "GET";

    authstr      = ff_http_auth_create_response(&s->auth_state, auth,
                                                local_path, method);
    proxyauthstr = ff_http_auth_create_response(&s->proxy_auth_state, proxyauth,
                                                local_path, method);
    if (post && !s->post_data) {
        send_expect_100 = s->send_expect_100;
        /* The user has supplied authentication but we don't know the auth type,
         * send Expect: 100-continue to get the 401 response including the
         * WWW-Authenticate header, or an 100 continue if no auth actually
         * is needed. */
        if (auth && *auth &&
            s->auth_state.auth_type == HTTP_AUTH_NONE &&
            s->http_code != 401)
            send_expect_100 = 1;
    }

#if FF_API_HTTP_USER_AGENT
    if (strcmp(s->user_agent_deprecated, DEFAULT_USER_AGENT)) {
        vcn_av_log(s, AV_LOG_WARNING, "the user-agent option is deprecated, please use user_agent option\n");
        s->user_agent = vcn_av_strdup(s->user_agent_deprecated);
    }
#endif
    /* set default headers if needed */
    if (!has_header(s->headers, "\r\nUser-Agent: "))
        len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                           "User-Agent: %s\r\n", s->user_agent);
    if (!has_header(s->headers, "\r\nAccept: "))
        len += vcn_av_strlcpy(headers + len, "Accept: */*\r\n",
                          sizeof(headers) - len);
    // Note: we send this on purpose even when s->off is 0 when we're probing,
    // since it allows us to detect more reliably if a (non-conforming)
    // server supports seeking by analysing the reply headers.
    if (!has_header(s->headers, "\r\nRange: ") && !post && (s->off > 0 || s->end_off || s->seekable == -1)) {
        len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                           "Range: bytes=%"PRIu64"-", s->off);
        if (s->end_off)
            len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                               "%"PRId64, s->end_off - 1);
        len += vcn_av_strlcpy(headers + len, "\r\n",
                          sizeof(headers) - len);
    }
    if (send_expect_100 && !has_header(s->headers, "\r\nExpect: "))
        len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                           "Expect: 100-continue\r\n");

    if (!has_header(s->headers, "\r\nConnection: ")) {
        if (s->multiple_requests)
            len += vcn_av_strlcpy(headers + len, "Connection: keep-alive\r\n",
                              sizeof(headers) - len);
        else
            len += vcn_av_strlcpy(headers + len, "Connection: close\r\n",
                              sizeof(headers) - len);
    }

    if (!has_header(s->headers, "\r\nHost: "))
        len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                           "Host: %s\r\n", hoststr);
    if (!has_header(s->headers, "\r\nContent-Length: ") && s->post_data)
        len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                           "Content-Length: %d\r\n", s->post_datalen);

    if (!has_header(s->headers, "\r\nContent-Type: ") && s->content_type)
        len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                           "Content-Type: %s\r\n", s->content_type);
    if (!has_header(s->headers, "\r\nCookie: ") && s->cookies) {
        char *cookies = NULL;
        if (!get_cookies(s, &cookies, path, hoststr) && cookies) {
            len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                               "Cookie: %s\r\n", cookies);
            vcn_av_free(cookies);
        }
    }
    if (!has_header(s->headers, "\r\nIcy-MetaData: ") && s->icy)
        len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                           "Icy-MetaData: %d\r\n", 1);

    /* now add in custom headers */
    if (s->headers)
        vcn_av_strlcpy(headers + len, s->headers, sizeof(headers) - len);

    snprintf(s->buffer, sizeof(s->buffer),
             "%s %s HTTP/1.1\r\n"
             "%s"
             "%s"
             "%s"
             "%s%s"
             "\r\n",
             method,
             path,
             post && s->chunked_post ? "Transfer-Encoding: chunked\r\n" : "",
             headers,
             authstr ? authstr : "",
             proxyauthstr ? "Proxy-" : "", proxyauthstr ? proxyauthstr : "");

    //vcn_av_log(h, AV_LOG_DEBUG, "request: %s\n", s->buffer);

    if ((err = vcn_url_write(s->hd, s->buffer, strlen(s->buffer))) < 0)
        goto done;

    if (s->post_data)
        if ((err = vcn_url_write(s->hd, s->post_data, s->post_datalen)) < 0)
            goto done;

    /* init input buffer */
    s->buf_ptr          = s->buffer;
    s->buf_end          = s->buffer;
    s->line_count       = 0;
    s->off              = 0;
    s->icy_data_read    = 0;
    s->filesize         = UINT64_MAX;
    s->willclose        = 0;
    s->end_chunked_post = 0;
    s->end_header       = 0;
    if (post && !s->post_data && !send_expect_100) {
        /* Pretend that it did work. We didn't read any header yet, since
         * we've still to send the POST data, but the code calling this
         * function will check http_code after we return. */
        s->http_code = 200;
        err = 0;
        goto done;
    }

    /* wait for header */
    err = http_read_header(h, new_location);
    if (err < 0)
        goto done;

    if (*new_location)
        s->off = off;

    err = (off == s->off) ? 0 : -1;
done:
    vcn_av_freep(&authstr);
    vcn_av_freep(&proxyauthstr);
    return err;
}

static int http_buf_read(VCNURLContext *h, uint8_t *buf, int size)
{
    VCNHTTPContext *s = h->priv_data;
    int len;

    if (s->chunksize != UINT64_MAX) {
        if (!s->chunksize) {
            char line[32];
            int err;

            do {
                if ((err = http_get_line(s, line, sizeof(line))) < 0)
                    return err;
            } while (!*line);    /* skip CR LF from last chunk */

            s->chunksize = strtoull(line, NULL, 16);

            vcn_av_log(h, AV_LOG_TRACE,
                   "Chunked encoding data size: %"PRIu64"'\n",
                    s->chunksize);

            if (!s->chunksize)
                return 0;
            else if (s->chunksize == UINT64_MAX) {
                vcn_av_log(h, AV_LOG_ERROR, "Invalid chunk size %"PRIu64"\n",
                       s->chunksize);
                return AVERROR(EINVAL);
            }
        }
        size = FFMIN(size, s->chunksize);
    }

    /* read bytes from input buffer first */
    len = s->buf_end - s->buf_ptr;
    if (len > 0) {
        if (len > size)
            len = size;
        memcpy(buf, s->buf_ptr, len);
        s->buf_ptr += len;
    } else {
        uint64_t target_end = s->end_off ? s->end_off : s->filesize;
        if ((!s->willclose || s->chunksize == UINT64_MAX) && s->off >= target_end)
            return AVERROR_EOF;
        len = vcn_url_read(s->hd, buf, size);
        if (!len && (!s->willclose || s->chunksize == UINT64_MAX) && s->off < target_end) {
            vcn_av_log(h, AV_LOG_ERROR,
                   "Stream ends prematurely at %"PRIu64", should be %"PRIu64"\n",
                   s->off, target_end
                  );
            //vcn_av_trace(h,AVERROR(EIO),"AVERROR(EIO)");
            return AVERROR(EIO);
        }
    }
    if (len > 0) {
        s->off += len;
        if (s->chunksize > 0) {
            av_assert0(s->chunksize >= len);
            s->chunksize -= len;
        }
    }
    return len;
}

#if CONFIG_ZLIB
#define DECOMPRESS_BUF_SIZE (256 * 1024)
static int http_buf_read_compressed(VCNURLContext *h, uint8_t *buf, int size)
{
    VCNHTTPContext *s = h->priv_data;
    int ret;

    if (!s->inflate_buffer) {
        s->inflate_buffer = vcn_av_malloc(DECOMPRESS_BUF_SIZE);
        if (!s->inflate_buffer) {
            //vcn_av_trace(h,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
            return AVERROR(ENOMEM);
        }
    }

    if (s->inflate_stream.avail_in == 0) {
        int read = http_buf_read(h, s->inflate_buffer, DECOMPRESS_BUF_SIZE);
        if (read <= 0)
            return read;
        s->inflate_stream.next_in  = s->inflate_buffer;
        s->inflate_stream.avail_in = read;
    }

    s->inflate_stream.avail_out = size;
    s->inflate_stream.next_out  = buf;

    ret = inflate(&s->inflate_stream, Z_SYNC_FLUSH);
    if (ret != Z_OK && ret != Z_STREAM_END)
        vcn_av_log(h, AV_LOG_WARNING, "inflate return value: %d, %s\n",
               ret, s->inflate_stream.msg);

    return size - s->inflate_stream.avail_out;
}
#endif /* CONFIG_ZLIB */

static int64_t http_seek_internal(VCNURLContext *h, int64_t off, int whence, int force_reconnect);

static int http_read_stream(VCNURLContext *h, uint8_t *buf, int size)
{
    VCNHTTPContext *s = h->priv_data;
    int err, new_location, read_ret;
    int64_t seek_ret;
    int reconnect_index = 0;
    int reconnect_delay_time = 5;
    if (!s->hd){
        return AVERROR_EOF;
    }

    if (s->end_chunked_post && !s->end_header) {
        err = http_read_header(h, &new_location);
        if (err < 0){
            //vcn_av_trace(h,err,"err:%d", err);
            return err;
        }
    }

#if CONFIG_ZLIB
    if (s->compressed)
        return http_buf_read_compressed(h, buf, size);
#endif /* CONFIG_ZLIB */
    read_ret = http_buf_read(h, buf, size);
    if (   (read_ret  < 0 && s->reconnect  && read_ret != AVERROR_EXIT && (!h->is_streamed || s->reconnect_streamed) && s->filesize > 0 && s->off < s->filesize)
        || (read_ret == 0 && s->reconnect_at_eof && (!h->is_streamed || s->reconnect_streamed))) {
        uint64_t target = h->is_streamed ? 0 : s->off;
        int interrupt = 0;
        if (s->reconnect_delay > s->reconnect_delay_max){
            //vcn_av_trace(h,AVERROR(EIO),"AVERRR(EIO)");
            return AVERROR(EIO);
        }

        vcn_av_log(h, AV_LOG_INFO, "Will reconnect at %"PRIu64" error=%s.\n", s->off, av_err2str(read_ret));
#ifdef HTTP_RECONNECT
        seek_ret = -1;
        if (s->reconnect_count > 0) {
            reconnect_delay_time = s->reconnect_delay_max / s->reconnect_count;
            if (reconnect_delay_time <= 0) {
                reconnect_delay_time = 1;
            }
        }
        while( seek_ret < 0 && s->reconnect && reconnect_index < s->reconnect_count ) {
            reconnect_index++;
            vcn_av_log(h, AV_LOG_INFO, "reconnect:%d delay_time:%d", reconnect_index, reconnect_delay_time);
            
            if(h->interrupt_callback.callback!= NULL) {
                int64_t timeout = 1000U*1000*reconnect_delay_time;
                while(timeout > 0  && !h->interrupt_callback.callback(h->interrupt_callback.opaque) ) {
                    vcn_av_usleep(1000);
                    timeout -= 1000;
                }
                interrupt = h->interrupt_callback.callback(h->interrupt_callback.opaque);
            } else {
                vcn_av_usleep(1000U*1000*reconnect_delay_time);
            }
            if(interrupt) {
                return AVERROR_EXIT;
            }
            
            seek_ret = http_seek_internal(h, target, SEEK_SET, 1);
        }
#else
        if(h->interrupt_callback.callback!= NULL) {
            int64_t timeout = 1000U*1000*s->reconnect_delay;
            while(timeout > 0  && !h->interrupt_callback.callback(h->interrupt_callback.opaque) ) {
                vcn_av_usleep(1000);
                timeout -= 1000;
            }
            interrupt = h->interrupt_callback.callback(h->interrupt_callback.opaque);
        } else {
       	    vcn_av_usleep(1000U*1000*s->reconnect_delay);
        }
        if(interrupt) {
            return AVERROR_EXIT;
        }
        s->reconnect_delay = 1 + 2*s->reconnect_delay;
        
        seek_ret = http_seek_internal(h, target, SEEK_SET, 1);
#endif
        if (seek_ret != target) {
            vcn_av_log(h, AV_LOG_ERROR, "Failed to reconnect at %"PRIu64" after %d reconnect.\n", target, reconnect_index);
            return read_ret;
        }
        read_ret = http_buf_read(h, buf, size);
    } else {
#ifndef HTTP_RECONNECT
         s->reconnect_delay = 0;
#endif
    }

    return read_ret;
}

// Like http_read_stream(), but no short reads.
// Assumes partial reads are an error.
static int http_read_stream_all(VCNURLContext *h, uint8_t *buf, int size)
{
    int pos = 0;
    while (pos < size) {
        int len = http_read_stream(h, buf + pos, size - pos);
        if (len < 0)
            return len;
        pos += len;
    }
    return pos;
}

static void update_metadata(VCNHTTPContext *s, char *data)
{
    char *key;
    char *val;
    char *end;
    char *next = data;

    while (*next) {
        key = next;
        val = strstr(key, "='");
        if (!val)
            break;
        end = strstr(val, "';");
        if (!end)
            break;

        *val = '\0';
        *end = '\0';
        val += 2;

        vcn_av_dict_set(&s->metadata, key, val, 0);

        next = end + 2;
    }
}

static int store_icy(VCNURLContext *h, int size)
{
    VCNHTTPContext *s = h->priv_data;
    /* until next metadata packet */
    uint64_t remaining;

    if (s->icy_metaint < s->icy_data_read) {
	    //vcn_av_trace(h,AVERROR_INVALIDDATA,"AVERROR_INVALIDDATA");
        return AVERROR_INVALIDDATA;
	}
    remaining = s->icy_metaint - s->icy_data_read;

    if (!remaining) {
        /* The metadata packet is variable sized. It has a 1 byte header
         * which sets the length of the packet (divided by 16). If it's 0,
         * the metadata doesn't change. After the packet, icy_metaint bytes
         * of normal data follows. */
        uint8_t ch;
        int len = http_read_stream_all(h, &ch, 1);
        if (len < 0)
            return len;
        if (ch > 0) {
            char data[255 * 16 + 1];
            int ret;
            len = ch * 16;
            ret = http_read_stream_all(h, data, len);
            if (ret < 0)
                return ret;
            data[len + 1] = 0;
            if ((ret = vcn_av_opt_set(s, "icy_metadata_packet", data, 0)) < 0)
                return ret;
            update_metadata(s, data);
        }
        s->icy_data_read = 0;
        remaining        = s->icy_metaint;
    }

    return FFMIN(size, remaining);
}

static int vcn_http_read(VCNURLContext *h, uint8_t *buf, int size)
{
    VCNHTTPContext *s = h->priv_data;

    if (s->icy_metaint > 0) {
        size = store_icy(h, size);
        if (size < 0)
            return size;
    }

    size = http_read_stream(h, buf, size);
    if (size > 0)
        s->icy_data_read += size;
    return size;
}

/* used only when posting data */
static int vcn_http_write(VCNURLContext *h, const uint8_t *buf, int size)
{
    char temp[11] = "";  /* 32-bit hex + CRLF + nul */
    int ret;
    char crlf[] = "\r\n";
    VCNHTTPContext *s = h->priv_data;

    if (!s->chunked_post) {
        /* non-chunked data is sent without any special encoding */
        return vcn_url_write(s->hd, buf, size);
    }

    /* silently ignore zero-size data since chunk encoding that would
     * signal EOF */
    if (size > 0) {
        /* upload data using chunked encoding */
        snprintf(temp, sizeof(temp), "%x\r\n", size);

        if ((ret = vcn_url_write(s->hd, temp, strlen(temp))) < 0 ||
            (ret = vcn_url_write(s->hd, buf, size)) < 0          ||
            (ret = vcn_url_write(s->hd, crlf, sizeof(crlf) - 1)) < 0)
            return ret;
    }
    return size;
}

static int vcn_http_shutdown(VCNURLContext *h, int flags)
{
    int ret = 0;
    char footer[] = "0\r\n\r\n";
    VCNHTTPContext *s = h->priv_data;

    /* signal end of chunked encoding if used */
    if (((flags & AVIO_FLAG_WRITE) && s->chunked_post) ||
        ((flags & AVIO_FLAG_READ) && s->chunked_post && s->listen)) {
        ret = vcn_url_write(s->hd, footer, sizeof(footer) - 1);
        ret = ret > 0 ? 0 : ret;
        s->end_chunked_post = 1;
    }

    return ret;
}

static int vcn_http_close(VCNURLContext *h)
{
    int ret = 0;
    VCNHTTPContext *s = h->priv_data;

#if CONFIG_ZLIB
    inflateEnd(&s->inflate_stream);
    vcn_av_freep(&s->inflate_buffer);
#endif /* CONFIG_ZLIB */

    if (!s->end_chunked_post)
        /* Close the write direction by sending the end of chunked encoding. */
        ret = vcn_http_shutdown(h, h->flags);

    if (s->hd)
        vcn_url_closep(&s->hd);
    vcn_av_dict_free(&s->chained_options);
    return ret;
}

static int64_t http_seek_internal(VCNURLContext *h, int64_t off, int whence, int force_reconnect)
{
    VCNHTTPContext *s = h->priv_data;
    VCNURLContext *old_hd = s->hd;
    uint64_t old_off = s->off;
    uint8_t old_buf[BUFFER_SIZE];
    int old_buf_size, ret;
    AVDictionary *options = NULL;

    if (whence == AVSEEK_SIZE)
        return s->filesize;
    else if(whence == AVSEEK_ADDR){
	    return (int64_t)s->host_ip;
    } else if(whence == AVSEEK_SETDUR || whence == AVSEEK_CPSIZE) {
	    return -1;
    }
    else if (!force_reconnect &&
             ((whence == SEEK_CUR && off == 0) ||
              (whence == SEEK_SET && off == s->off)))
        return s->off;
    else if ((s->filesize == UINT64_MAX && whence == SEEK_END)) {
        //vcn_av_trace(h,AVERROR(ENOSYS),"AVERROR(ENOSYS)");
        return AVERROR(ENOSYS);
    }

    if (whence == SEEK_CUR)
        off += s->off;
    else if (whence == SEEK_END)
        off += s->filesize;
    else if (whence != SEEK_SET){
        //vcn_av_trace(h,AVERROR(EINVAL),"AVERROR(EINVAL)");
        return AVERROR(EINVAL);
    }
    if (off < 0){
        //vcn_av_trace(h,AVERROR(EINVAL),"AVERROR(EINVAL)");
        return AVERROR(EINVAL);
    }
    s->off = off;

    if (s->off && h->is_streamed){
        //vcn_av_trace(h,AVERROR(ENOSYS),"AVERROR(ENOSYS)");
        return AVERROR(ENOSYS);
    }

    /* we save the old context in case the seek fails */
    old_buf_size = s->buf_end - s->buf_ptr;
    memcpy(old_buf, s->buf_ptr, old_buf_size);
    s->hd = NULL;

    /* if it fails, continue on old connection */
    if ((ret = http_open_cnx(h, &options)) < 0) {
        vcn_av_dict_free(&options);
        memcpy(s->buffer, old_buf, old_buf_size);
        s->buf_ptr = s->buffer;
        s->buf_end = s->buffer + old_buf_size;
        s->hd      = old_hd;
        s->off     = old_off;
        return ret;
    }
    vcn_av_dict_free(&options);
    vcn_url_close(old_hd);
    return off;
}

static int64_t vcn_http_seek(VCNURLContext *h, int64_t off, int whence)
{
    return http_seek_internal(h, off, whence, 0);
}

static int vcn_http_get_file_handle(VCNURLContext *h)
{
    VCNHTTPContext *s = h->priv_data;
    return vcn_url_get_file_handle(s->hd);
}
static int64_t http_get_log_handle(void * ptr) {
    VCNHTTPContext* s = ptr;
    return s->log_handle;
}
#define HTTP_CLASS(flavor)                          \
static const AVClass flavor ## _context_class = {   \
    .class_name = # flavor,                         \
    .item_name  = vcn_av_default_item_name,             \
    .option     = options,                          \
    .version    = LIBAVUTIL_VERSION_INT,            \
    .get_log_handle = http_get_log_handle,\
}

#if CONFIG_HTTP_PROTOCOL
HTTP_CLASS(http);

const URLProtocol vcn_http_protocol = {
    .name                = "http",
    .url_open2           = vcn_http_open,
    .url_accept          = vcn_http_accept,
    .url_handshake       = vcn_http_handshake,
    .url_read            = vcn_http_read,
    .url_write           = vcn_http_write,
    .url_seek            = vcn_http_seek,
    .url_close           = vcn_http_close,
    .url_get_file_handle = vcn_http_get_file_handle,
    .url_shutdown        = vcn_http_shutdown,
    .priv_data_size      = sizeof(VCNHTTPContext),
    .priv_data_class     = &http_context_class,
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
    .default_whitelist   = "http,https,tls,rtp,tcp,udp,crypto,httpproxy"
};
#endif /* CONFIG_HTTP_PROTOCOL */

#if CONFIG_HTTPS_PROTOCOL
HTTP_CLASS(https);

const URLProtocol vcn_https_protocol = {
    .name                = "https",
    .url_open2           = vcn_http_open,
    .url_read            = vcn_http_read,
    .url_write           = vcn_http_write,
    .url_seek            = vcn_http_seek,
    .url_close           = vcn_http_close,
    .url_get_file_handle = vcn_http_get_file_handle,
    .url_shutdown        = vcn_http_shutdown,
    .priv_data_size      = sizeof(VCNHTTPContext),
    .priv_data_class     = &https_context_class,
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
    .default_whitelist   = "http,https,tls,rtp,tcp,udp,crypto,httpproxy"
};
#endif /* CONFIG_HTTPS_PROTOCOL */

#if CONFIG_HTTPPROXY_PROTOCOL
static int http_proxy_close(VCNURLContext *h)
{
    VCNHTTPContext *s = h->priv_data;
    if (s->hd)
        vcn_url_closep(&s->hd);
    return 0;
}

static int http_proxy_open(VCNURLContext *h, const char *uri, int flags)
{
    VCNHTTPContext *s = h->priv_data;
    char hostname[1024], hoststr[1024];
    char auth[1024], pathbuf[1024], *path;
    char lower_url[100];
    int port, ret = 0, attempts = 0;
    HTTPAuthType cur_auth_type;
    char *authstr;
    int new_loc;

    if( s->seekable == 1 )
        h->is_streamed = 0;
    else
        h->is_streamed = 1;

    vcn_av_url_split(NULL, 0, auth, sizeof(auth), hostname, sizeof(hostname), &port,
                 pathbuf, sizeof(pathbuf), uri);
    vcn_url_join(hoststr, sizeof(hoststr), NULL, NULL, hostname, port, NULL);
    path = pathbuf;
    if (*path == '/')
        path++;

    vcn_url_join(lower_url, sizeof(lower_url), "tcp", NULL, hostname, port,
                NULL);
redo:
    ret = vcn_url_open_whitelist(&s->hd, lower_url, AVIO_FLAG_READ_WRITE,
                               &h->interrupt_callback, NULL,
                               h->protocol_whitelist, h->protocol_blacklist, h);
    if (ret < 0)
        return ret;

    authstr = ff_http_auth_create_response(&s->proxy_auth_state, auth,
                                           path, "CONNECT");
    snprintf(s->buffer, sizeof(s->buffer),
             "CONNECT %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n"
             "%s%s"
             "\r\n",
             path,
             hoststr,
             authstr ? "Proxy-" : "", authstr ? authstr : "");
    vcn_av_freep(&authstr);

    if ((ret = vcn_url_write(s->hd, s->buffer, strlen(s->buffer))) < 0)
        goto fail;

    s->buf_ptr    = s->buffer;
    s->buf_end    = s->buffer;
    s->line_count = 0;
    s->filesize   = UINT64_MAX;
    cur_auth_type = s->proxy_auth_state.auth_type;

    /* Note: This uses buffering, potentially reading more than the
     * HTTP header. If tunneling a protocol where the server starts
     * the conversation, we might buffer part of that here, too.
     * Reading that requires using the proper vcn_url_read() function
     * on this VCNURLContext, not using the fd directly (as the tls
     * protocol does). This shouldn't be an issue for tls though,
     * since the client starts the conversation there, so there
     * is no extra data that we might buffer up here.
     */
    ret = http_read_header(h, &new_loc);
    if (ret < 0)
        goto fail;

    attempts++;
    if (s->http_code == 407 &&
        (cur_auth_type == HTTP_AUTH_NONE || s->proxy_auth_state.stale) &&
        s->proxy_auth_state.auth_type != HTTP_AUTH_NONE && attempts < 2) {
        vcn_url_closep(&s->hd);
        goto redo;
    }

    if (s->http_code < 400)
        return 0;
    //vcn_av_trace(h,AVERROR(EIO),"AVERROR(EIO)");
    ret = ff_http_averror(s->http_code, AVERROR(EIO));

fail:
    http_proxy_close(h);
    return ret;
}

static int http_proxy_write(VCNURLContext *h, const uint8_t *buf, int size)
{
    VCNHTTPContext *s = h->priv_data;
    return vcn_url_write(s->hd, buf, size);
}

const URLProtocol ff_httpproxy_protocol = {
    .name                = "httpproxy",
    .url_open            = http_proxy_open,
    .url_read            = http_buf_read,
    .url_write           = http_proxy_write,
    .url_close           = http_proxy_close,
    .url_get_file_handle = vcn_http_get_file_handle,
    .priv_data_size      = sizeof(VCNHTTPContext),
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
};
#endif /* CONFIG_HTTPPROXY_PROTOCOL */
