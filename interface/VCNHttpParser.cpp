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
#include "VCNHttpContext.h"
#include "VCNSocketInfo.h"
#include "VCNDNSParserInterface.h"
#if defined(__IOS__)
#include <sys/socket.h>
#include <netinet/tcp.h>
#elif defined __ANDROID__
#include <netinet/tcp.h>
#endif

#include "VCNUtils.h"
#include "VCNTime.h"
#include "VCNLogger.h"
#include <zlib.h>
#include <sstream>
#include <vector>
extern "C" {
#include "vcn_url.h"
#include "vcn_utils.h"
#include "vcn_avstring.h"
#include "vcn_opt.h"
#include "vcn_time.h"
#include "vcn_error.h"
}
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include<sys/ioctl.h>
NS_VCN_BEGIN

#define AVSEEK_DATASIZE 0x7000

#define MAX_URL_SIZE 4096
#define MAX_REDIRECTS 8
#define HTTP_SINGLE   1
#define HTTP_MUTLI    2
#define MAX_EXPIRY    19
#define WHITESPACES " \n\t\r"
#define HTTP_AUTO_RECONNECT 1
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#define SANDBOX_CHECK_URL_PROCEED 1
//extern const char *vcn_tcp_get_ip_addr(VCNURLContext *h);
static void httpCheckSocket(VCNHttpContext *s, int isCheckHttpCode);
static char* httpInitSocket(VCNHttpContext *s, const char* host, int port, int lowerProto);
static int httpConnect(VCNHttpContext *s, const char *path, const char *local_path,
                        const char *hoststr, const char *auth,
                        const char *proxyauth, int *new_location);
static int httpReadHeader(VCNHttpContext *s, int *new_location);
static int httpReadHeaderUnlimit(VCNHttpContext *s, int *new_location);

static int httpWriteHeaderUnlimit(VCNHttpContext *s, int post, int send_expect_100,
                                const char *hoststr, const char *path, const char *method,
                                const char *authstr, const char *proxyauthstr);

static int hasHeader(const char *str, const char *header);
static bool hostnameIsIpAddress(const char *s);
static void httpNotifySockInfo(VCNHttpContext *s);
static bool checkHiJack(VCNHttpContext *s);
static void httpNotifyError(VCNHttpContext *s, VCNHttpParserErrorType err_type, int error_code, const char* extra);

int sandbox_check_url(const char *url, const char *param, const char *header) {
    typedef int (*Sender)(const char*, const char*, const char*);
    Sender proceed = NULL;
    int ret = SANDBOX_CHECK_URL_PROCEED;

    char* sandboxbuf = getenv("orbuculumIsProceedRequest");
    if (sandboxbuf) {
        size_t address = strtoull(sandboxbuf, NULL, 16);
        if (address != 0) {
            proceed = (Sender) address;
        }
    }
    ret = proceed == NULL ? SANDBOX_CHECK_URL_PROCEED : proceed(url, param, header);
    VCN_LOGWD("sandbox check ret:%d url:%s", ret, url);
    return ret == SANDBOX_CHECK_URL_PROCEED ? 0 : IsSandBoxNotAllowError;
}
static int httpParserChangeHostname(VCNHttpContext *s) {
    int host_len = 0;
    int new_header_len = 0;
    int new_host_len = 0;
    char* new_header = NULL;
    int host_position = 0;
    char hostname[256], hoststr[256+12];
    int port;
    int cur_len = 0;
    const char* begin = vcn_av_strnstr(s->headers, "Host: ", strlen(s->headers));
    if (begin == NULL) {
        return 0;
    }
    vcn_av_url_split_hostname(hostname, sizeof(hostname), &port, s->location);
    vcn_url_join(hoststr, sizeof(hoststr), NULL, NULL, hostname, port, NULL);
   VCN_LOGI("hostname %s",hostname);

    new_host_len = strlen(hoststr);
    host_position = begin - s->headers;
    const char* end = vcn_av_strnstr(begin, "\r\n", strlen(s->headers)-host_position);
    if (end != NULL) {
        host_len = end - begin + 2;
    } else {
        host_len = sizeof(s->headers) - host_position;
    }
    new_header_len = strlen(s->headers) - host_len + new_host_len + 8;
    new_header_len += 1;

    new_header = (char*)vcn_av_malloc(new_header_len);
    if(host_len != 0 && host_position != 0) {
        memcpy(new_header,s->headers,host_position);
        cur_len += host_position;
    }
    memcpy(new_header + cur_len, "Host: ", 6);
    cur_len += 6;
    memcpy(new_header + cur_len, hoststr, new_host_len);
    cur_len += new_host_len;
    memcpy(new_header + cur_len, "\r\n", 2);
    cur_len += 2;
    if (s->headers) {
        memcpy(new_header + cur_len, s->headers + host_position + host_len,  strlen(s->headers) - host_position - host_len);
        vcn_av_free(s->headers);
    }
    *(new_header + new_header_len - 1) = 0x0;
    VCN_LOGI("new_header=%s", new_header);
    s->headers = new_header;
    return 0;
}
static char* dnsParse(VCNHttpContext *s, const char* hostname) {
    if(s->parserNotifyer != nullptr) {
        s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsRequestHost, 0, hostname);
    }

    if (s->parser == nullptr) {
        return nullptr;
    }
    char * result = nullptr;
    if(hostnameIsIpAddress(hostname)) {
        VCN_LOGWD("is ipaddress not need do parse:%s", hostname);
        VCN_MEMCPY_STRING(result, hostname)
        if (s->parserNotifyer != nullptr) {
            s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsDNSParseStart, 0, nullptr);
            s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsDNSParseEnd, 0, nullptr);
            s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsParsedIpList, 0, result);
            s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsDNSType, -1, hostname);
        }
        return result;
    }
    int type = -1;
    int err = 0;
    if (s->parserNotifyer != nullptr) {
        s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsDNSParseStart, 0, nullptr);
    }
    result = s->parser->parse(hostname,s->open_timeout, type, err, s->reserved_code, s->dns_type);
    if (!(VCN_IS_EMPTY_STRING(result))) {
        if (s->parserNotifyer != nullptr) {
            s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsDNSParseEnd, 0, nullptr);
            s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsParsedIpList, 0, result);
            s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsDNSType, type, hostname);
        }
    }

    return result;
}

static int httpOpenCnxInternal(VCNHttpContext *s, AVDictionary **options)
{
    const char *path, *proxy_path, *lower_proto = "tcp", *local_path;
    char hostname[1024], hoststr[1024], proto[10];
    char auth[1024], proxyauth[1024] = "";
    char path1[MAX_URL_SIZE];
    char buf[1024], urlbuf[MAX_URL_SIZE];
    int port, use_proxy, err, location_changed = 0;
    int is_tls = 0;
    if(s->interrupt_callback.callback != NULL && vcn_ff_check_interrupt(&s->interrupt_callback)) {
        return AVERROR_EXIT;
    }
    if(sandbox_check_url(s->location, NULL, NULL)) {
        VCN_LOGW("sand box check err, path:%s",s->location);
        return IsSandBoxNotAllowError;
    }
    vcn_av_url_split(proto, sizeof(proto), auth, sizeof(auth),
                 hostname, sizeof(hostname), &port,
                 path1, sizeof(path1), s->location);
    vcn_url_join(hoststr, sizeof(hoststr), NULL, NULL, hostname, port, NULL);


    proxy_path = NULL;//s->http_proxy ? s->http_proxy : getenv("http_proxy");
    use_proxy  = 0;
#ifdef __ALLOW_PROXY__
    VCN_LOGW("try to get proxy");
    if(s->parserHelper != nullptr) {
        VCN_DELETE_STRING(s->http_proxy)
        s->http_proxy = s->parserHelper->getStringValue(VCNHttpParserHelperKey::VCNHttpParserHelperKeyIsProxyUrl, 0, nullptr);
        proxy_path = s->http_proxy;
        VCN_LOGW("try to get proxy,result:%s",proxy_path?proxy_path:"null");
        use_proxy = proxy_path && (vcn_av_strstart(proxy_path, "http://", NULL) || vcn_av_strstart(proxy_path, "https://", NULL));
    }
#endif

    if (!strcmp(proto, "https") || s->forceHttps) {
        lower_proto = "tls";
        is_tls = 1;
//        use_proxy   = 0;


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
        lower_proto = "tcp";
        is_tls = 0;
        VCN_LOGW("parse from proxy host:%s port:%d", hostname, port);
    }

    s->lowerProto = is_tls ? LowerProtoIsTLS : LowerProtoIsTcp;
    s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsLowerProto, s->lowerProto == LowerProtoIsTLS ? 1 : 0,
                              nullptr);

    char *sniHost = hostname;
    if (!VCN_IS_EMPTY_STRING(s->customHost)) {
        sniHost = s->customHost;
    }
    vcn_url_join(buf, sizeof(buf), lower_proto, NULL, sniHost, port, NULL);

    
    std::string settedIpList;

    if (!s->hd) {
        if (s->parserNotifyer != nullptr) {
            s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsConnectedPort, port, nullptr);
        }
        char* ipList = httpInitSocket(s, hostname, port, s->lowerProto);

    
        if (!s->hd) {
            if (s->parser != nullptr && VCN_IS_EMPTY_STRING(ipList)) {
                VCN_LOGI("dns parse err!!!");
				VCN_DELETE_STRING(ipList)
                return IsExternDNSParseError;
            }
            if (ipList != nullptr) {
                int setRet = vcn_av_dict_set(options,"ip_list",ipList,0);
                settedIpList = std::string(ipList);
                VCN_LOGI("ip_list set ret:%d, ip_list:%s",setRet, ipList);
            }
            /*clear old info*/
            VCN_DELETE_STRING(ipList)
            VCN_DELETE_STRING(s->connectedIp)
            VCN_DELETE_STRING(s->connectedHost)
            s->port = 0;
            s->socketInfo.createT = vcnGetCurrentTime();
            VCN_LOGI("sessioin call back for cb opaque:%p fun:%p", s->interrupt_callback.session_opaque, s->interrupt_callback.session_callback);
            err = vcn_url_open_whitelist(&s->hd, buf, AVIO_FLAG_READ_WRITE,
                                       &s->interrupt_callback, options,
                                       NULL, NULL, NULL);
            VCN_LOGI("after open sessioin call back for cb opaque:%p fun:%p", s->interrupt_callback.session_opaque, s->interrupt_callback.session_callback);

            if (err < 0) {
                if (err != AVERROR_EOF && err != AVERROR_EXIT) {
                    VCN_MEMCPY_STRING(s->connectedHost, hostname)
                    s->port = port;
                    httpNotifyError(s, VCNHttpParserErrorType::VCNHttpParserErrorTypeIsTCP, err, settedIpList.c_str());
                }
                return err;
            }
           
            VCN_LOGI("socket new:%p location:%s port:%d protocol:%s",s->hd, s->location, port, lower_proto);
//            sockNumRecord(s, 1);
            /*set new info*/
            if (!is_tls) {
                VCN_MEMCPY_STRING(s->connectedIp, vcn_tcp_get_ip_addr(s->hd))
            }
            else if(is_tls){
                VCN_MEMCPY_STRING(s->connectedIp, vcn_tls_get_ip_addr(s->hd))
            }
            VCN_MEMCPY_STRING(s->connectedHost, hostname)
            s->port = port;
            s->lowerProto = is_tls ? LowerProtoIsTLS : LowerProtoIsTcp;
            VCN_LOGI("connected ip is:%s",s->connectedIp);
            if (s->parserNotifyer != nullptr) {
                char socketId[1024];
                memset(socketId, 0, sizeof(socketId));
                snprintf(socketId, sizeof(socketId), "%" PRId64"_%p", s->socketInfo.createT, s->socketInfo.socketHd);
                s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsSocketReuseFlag, 0, socketId);
            }
        }
        VCN_DELETE_STRING(ipList)
        
    }

    err = httpConnect(s, path, local_path, hoststr,
                       auth, proxyauth, &location_changed);
    if (err < 0) {
        if (err != AVERROR_EOF && err != AVERROR_EXIT) {
            httpNotifyError(s, VCNHttpParserErrorType::VCNHttpParserErrorTypeIsHTTP,
                    err, settedIpList.c_str());
        }
        return err;
    }

    return location_changed;
}

static int httpSplitStr(const char** str, char splitChar, int* len) {
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
        if (*len > 0) {
            return 0;
        }
    }
    return -1;
}

static int httpGetContextType(const char* header, char* contentType, int bufferSize) {
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
static int httpCheckContentType(VCNHttpContext*s) {
    int ret = 0;
    if (s->valid_http_content_type != NULL) {
        const char* str = s->valid_http_content_type;
        int len = 0;
        int find = 0;
        const int contentTypeMaxSize = 128;
        char contentType[128];
        if (httpGetContextType((char*)s->buffer, contentType, contentTypeMaxSize) == 0) {
            int contentSize = strlen(contentType);
            while( httpSplitStr(&str, ' ', &len) == 0 ) {
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

VCN_INTERFACE_EXPORT int httpParserHttpAVError(int status_code, int default_averror)
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

/* return non zero if error */
static int httpOpenCnx(VCNHttpContext *s, AVDictionary **options)
{
    HTTPAuthType cur_auth_type, cur_proxy_auth_type;
    int location_changed, attempts = 0, redirects = 0, ret = 0;
    int status_code = -1;
    if (s->parserNotifyer != nullptr) {
        s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsOriginUrl, 0, s->location);
    }
redo:
    vcn_av_dict_copy(options, s->chained_options, 0);

    cur_auth_type       = (HTTPAuthType)s->auth_state.auth_type;
    cur_proxy_auth_type = (HTTPAuthType)s->auth_state.auth_type;

    if(s && s->parserNotifyer) {
        s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsRequestEffectiveUrl, 0, s->location);
    }

    location_changed = httpOpenCnxInternal(s, options);

    if (location_changed < 0) {
        goto fail;
    }

    attempts++;
    status_code = s->http_code;
    if (status_code >= 200 && status_code < 300) {
        ret = httpCheckContentType(s);
        if (ret != 0) {
            goto fail;
        }
    }
    if (s->http_code == 401) {
        if ((cur_auth_type == HTTP_AUTH_NONE || s->auth_state.stale) &&
            s->auth_state.auth_type != HTTP_AUTH_NONE && attempts < 4) {
            VCN_LOGI("401 err close socket:%p",s->hd);
            vcn_url_closep(&s->hd);
//            sockNumRecord(s, 0);
            goto redo;
        } else {
            goto fail;
        }
    }
    if (s->http_code == 407) {
        if ((cur_proxy_auth_type == HTTP_AUTH_NONE || s->proxy_auth_state.stale) &&
            s->proxy_auth_state.auth_type != HTTP_AUTH_NONE && attempts < 4) {
            VCN_LOGI("407 err close socket:%p",s->hd);
            vcn_url_closep(&s->hd);
//            sockNumRecord(s, 0);
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
        httpCheckSocket(s, 1);
        VCN_LOGI("3xx,try to close socket:%p",s->hd);
        vcn_url_closep(&s->hd);
//        sockNumRecord(s, 0);
        if (redirects++ >= MAX_REDIRECTS){
            //av_fatal(h, AVERROR_HTTP_REDIRECT_COUNT_OUT,"http error");
            return AVERROR(EIO);
        }
        if(s && s->parserNotifyer) {
            s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsRedirectUrl, 0, s->location);
        }
        /* Restart the authentication process with the new target, which
         * might use a different auth mechanism. */
        memset(&s->auth_state, 0, sizeof(s->auth_state));
        attempts         = 0;
        location_changed = 0;
        goto redo;
    }
    if(s->is_err_continue && s->http_code == 404) {
        VCN_LOGI( "return http not found");
        return AVERROR_HTTP_NOT_FOUND;
    }
    //http_save_tcp_hostname_of_ip(s);
    return 0;

fail:
    if (s->hd){
        VCN_LOGI("http open fail;%d close socket:%p",ret,s->hd);
        vcn_url_closep(&s->hd);
//        sockNumRecord(s, 0);
    }
    if (location_changed < 0) {
        return location_changed;
    }
    if (ret != 0) {
        //av_fatal(h, ret, s->buffer);
        return ret;
    }
    ret = httpParserHttpAVError(s->http_code, AVERROR(EIO));
    if ( ret == AVERROR(EIO) ) {
        //av_fatal(h, AVERROR_HTTP_DEFAULT_ERROR, s->buffer);
    } else {
        //av_fatal(h, ret, s->buffer);
    }
    return ret;
}

int ffHttpDoNewRequest(VCNHttpContext *s, const char *uri)
{
    AVDictionary *options = NULL;
    int ret;
    if (s->willclose == 1) {
        vcn_url_closep(&s->hd);
        s->willclose = 0;
    }
    s->off           = 0;
    s->icy_data_read = 0;
    vcn_av_free(s->location);
    s->location = vcn_av_strdup(uri);
    if (!s->location){
        //av_trace(h,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
        return AVERROR(ENOMEM);
    }
    ret = httpOpenCnx(s, &options);
    vcn_av_dict_free(&options);
    return ret;
}

static int httpWriteReply(VCNHttpContext* s, int status_code, int isUseChunk)
{
    int ret, body = 0, reply_code, message_len;
    const char *reply_text, *content_type;
    char message[BUFFER_SIZE];
    content_type = "text/plain";

    if (status_code < 0)
        body = 1;
    //status_code = AVERROR_HTTP_BAD_REQUEST;
    switch (status_code) {
        case AVERROR_HTTP_BAD_REQUEST:
        case 400:
            reply_code = 400;
            reply_text = "Bad Request";
            break;
        case 401:
            reply_code = 401;
            reply_text = "Unauthorized";
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
        case 408:
            reply_code = 408;
            reply_text = "Timeout";
            break;
        case 416:
            reply_code = 416;
            reply_text = "Range Error";
            break;
        case 429:
            reply_code = 429;
            reply_text = "Too Many Requests";
            break;
        case 451:
            reply_code = 451;
            reply_text = "For Legal Reasons";
            break;
        case 200:
            reply_code = 200;
            reply_text = "OK";
            content_type = s->content_type ? s->content_type : "application/octet-stream";
            break;
        case 206:
            reply_code = 206;
            reply_text = "Partial Content";
            break;
        case AVERROR_HTTP_SERVER_ERROR:
        case 500:
            reply_code = 500;
            reply_text = "Internal server error";
            break;
        default:
            //av_trace(h,AVERROR(EINVAL),"AVERROR(EINVAL)");
            if(status_code>=400 && status_code<500){
                reply_code = status_code;
                reply_text = "Http Other 4XX";
                break;
            }else if(status_code<600){
                reply_code = status_code;
                reply_text = "Http Server Error";
                break;
            }else{
                return AVERROR(EINVAL);
            }
    }
    if (body || (!isUseChunk)) {
        s->chunked_post = 0;
        if(reply_code >= 200 && reply_code < 300) {
            message_len = snprintf(message, sizeof(message),
                                   "HTTP/1.1 %03d %s\r\n"
                                   "%s"
                                   "\r\n",
                                   reply_code,
                                   reply_text,
                                   s->headers ? s->headers : "");
        }
        else {
            message_len = snprintf(message, sizeof(message),
                               "HTTP/1.1 %03d %s\r\n"
                               "Content-Type: %s\r\n"
                               "Content-Length: %" SIZE_SPECIFIER"\r\n"
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
        }
        
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
    VCN_LOGI( "HTTP reply header: \n%s----\n", message);
    if ((ret = vcn_url_write(s->hd, (unsigned char*)message, message_len)) < 0)
        return ret;
    return 0;
}

static void handleHttpErrors(VCNHttpContext *s, int error)
{
    //av_assert0(error < 0);
    httpWriteReply(s, error,0);
}

VCN_INTERFACE_EXPORT int httpParserHandshake(VCNHttpContext *c)
{
    if (!c) {
        return VCNHttpParserError::IsContextNullError;
    }
    int ret, err, new_location;
    VCNURLContext *cl = c->hd;
    switch (c->handshake_step) {
        case VCN_LOWER_PROTO:
           VCN_LOGI( "Lower protocol\n");
            if ((ret = vcn_url_handshake(cl)) > 0)
                return 2 + ret;
            if (ret < 0)
                return ret;
            c->handshake_step = VCN_READ_HEADERS;
            c->is_connected_server = 1;
            return 2;
        case VCN_READ_HEADERS:
           VCN_LOGI( "Read headers\n");
            if ((err = httpReadHeader(c, &new_location)) < 0) {
                handleHttpErrors(c, err);
                return err;
            }
            c->handshake_step = VCN_WRITE_REPLY_HEADERS;
            return 1;
        case VCN_WRITE_REPLY_HEADERS:
            VCN_LOGI( "Reply code: %d, header: %s\n", c->reply_code, c->headers ? c->headers : "null");
            if ((err = httpWriteReply(c, c->reply_code, c->force_chunk)) < 0)
                return err;
            c->handshake_step = VCN_FINISH;
            return 1;
        case VCN_WRITE_REPLY_DATA:
            return 0;
        case VCN_FINISH:
            return 0;
    }
    // this should never be reached.
    //av_trace(ch,AVERROR(EINVAL),"AVERROR(EINVAL)");
    return AVERROR(EINVAL);
}

static int httpListen(VCNHttpContext *s, const char *uri, int flags,
                       AVDictionary **options) {
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
        //av_trace(s,ret,"ret:%d", ret);
        goto fail;
    }
    if ((ret = vcn_url_open_whitelist(&s->hd, lower_url, AVIO_FLAG_READ_WRITE,
                                    &s->interrupt_callback, options,
                                   NULL, NULL, NULL
                                    )) < 0)
        goto fail;
    s->handshake_step = VCN_LOWER_PROTO;
    if (s->listen == HTTP_SINGLE) { /* single client */
        s->reply_code = 200;
        while ((ret = httpParserHandshake(s)) > 0);
    }
fail:
    vcn_av_dict_free(&s->chained_options);
    return ret;
}

VCN_INTERFACE_EXPORT int httpParserOpen(VCNHttpContext *s, const char *uri, int flags,
                     AVDictionary **options)
{
    if (!s) {
        return VCNHttpParserError::IsContextNullError;
    }

    int ret;
    if( s->seekable == 1 )
        s->is_streamed = 0;
    else
        s->is_streamed = 1;

    s->filesize = UINT64_MAX;
    s->location = vcn_av_strdup(uri);
    if (!s->location){
        //av_trace(s,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
        return AVERROR(ENOMEM);
    }
    if (options)
        vcn_av_dict_copy(&s->chained_options, *options, 0);

    if (s->headers) {
        int len = strlen(s->headers);
        if (len < 2 || strcmp("\r\n", s->headers + len - 2)) {
            VCN_LOGI(
                   "No trailing CRLF found in HTTP header.\n");
            ret = vcn_av_reallocp(&s->headers, len + 3);
            if (ret < 0){
                //av_trace(s,ret,"ret:%d", ret);
                return ret;
            }
            s->headers[len]     = '\r';
            s->headers[len + 1] = '\n';
            s->headers[len + 2] = '\0';
        }
    }

    if (s->listen) {
        return httpListen(s, uri, flags, options);
    }
    ret = httpOpenCnx(s, options);
    if (ret < 0)
        vcn_av_dict_free(&s->chained_options);
    s->bodyReadSize = 0;
    return ret;
}

VCN_INTERFACE_EXPORT int httpParserAccept(VCNURLContext *sl, VCNHttpContext **c, const AVNetIOInterruptCB *int_cb,AVDictionary **options)
{
    if (!sl || !c || !(*c)) {
        return VCNHttpParserError::IsContextNullError;
    }
    int ret;
    VCNURLContext *cl = NULL;
    VCNHttpContext *cc = *c;
    if ((ret = vcn_url_accept(sl, &cl)) < 0)
        goto fail;
    if (int_cb != NULL) {
        cl->interrupt_callback = (*int_cb);
    }
    
    if (options &&
        (ret = vcn_av_opt_set_dict(cl, options)) < 0) {
        goto fail;
    }
    cc->hd = cl;
    cc->is_multi_client = 1;
fail:
    return ret;
}
static int low_proto_read(VCNHttpContext *s, unsigned char* buf, int size) {
    if(!s->parserStrategy) {
        return vcn_url_read(s->hd, buf, size);
    }
    if(s->parserStrategy->getStrategyIntValue(VCNHttpParserStrategyKey::VCNHttpParserStrategyKeyIsMinAllowLoadSpeed) <= 0) {
        return vcn_url_read(s->hd, buf, size);
    }
    int64_t startT = vcnGetCurrentTime();
    int len = vcn_url_read(s->hd, buf, size);
    if(len <= 0) {
        return len;
    }
    int64_t endT = vcnGetCurrentTime();
    /*when len > 0, try to check if exception*/
    if(s->parserStrategy->isSpeedException(s->socketInfo, endT - startT, len)) {
        VCN_LOGWD("socket exception");
        s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsLowSpeedCheckErr, endT - startT, nullptr, len);
        return IsLowSpeedError;
    }

    if(s->parserStrategy->isSpeedException(s->socketInfo, endT - startT, len)) {
        VCN_LOGWD("socket exception");
        s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsLowSpeedCheckErr, endT - startT, nullptr ,len);
        return IsLowSpeedError;
    }
    return len;
}
static int httpGetc(VCNHttpContext *s)
{
    int len;
    if (s->buf_ptr >= s->buf_end) {
//        len = vcn_url_read(s->hd, s->buffer, BUFFER_SIZE);
        len = low_proto_read(s, s->buffer,  BUFFER_SIZE);
        if (len < 0) {
            return len;
        } else if (len == 0) {
            /*although the connection is closed ordely but the header not be read completely,return EIO error*/
            //av_trace(s,AVERROR(EIO),"AVERROR(EIO)");
            VCN_LOGD("read nothing");
			if(vcn_ff_check_interrupt(&s->interrupt_callback)) {
                return AVERROR_EXIT;
            }
            return AVERROR(EIO);
        } else {
            s->recv_size += len;
            s->buf_ptr = s->buffer;
            s->buf_end = s->buffer + len;
            if (s->httpFirstPacketT == 0) {
                s->httpFirstPacketT = vcnGetCurrentTime();
            }
        }
    }
    return *s->buf_ptr++;
}

VCN_INTERFACE_EXPORT int httpParsrGetLine(VCNHttpContext *s, char *line, int line_size)
{
    int ch;
    char *q;

    q = line;
    for (;;) {
        ch = httpGetc(s);
        if (ch < 0) {
            VCN_LOGD("read failed, total: %d", q - line);
            return ch;
        }

        if ((!s->isttfb) && s->parserNotifyer != nullptr) {
            s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsCDNttfb, 0, nullptr);
            s->isttfb = 1;
        }

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

static int httpGetHeaderLineUnlimit(VCNHttpContext *s, char **line)
{
    char ch;
    size_t length = 0;
    std::vector<char> lineChars;
    
    for (;;) {
        ch = httpGetc(s);
        if (ch < 0) {
            VCN_LOGD("read failed, total: %d", lineChars.size());
            return ch;
        }
        if ((!s->isttfb) && s->parserNotifyer != nullptr) {
            s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsCDNttfb, 0, nullptr);
            s->isttfb = 1;
        }

        if (ch == '\n') {
            /* process line */
            length = lineChars.size() + 1;
            char* header = (char*)vcn_av_malloc(length);
            if (header == nullptr) {
                //av_trace(NULL,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
                return AVERROR(ENOMEM);
            }
            
            std::copy(lineChars.begin(), lineChars.end(), header);
            header[length - 1] = 0;
            
            if (lineChars.size() > 0 && lineChars.back() == '\r') {
                header[length - 2] = 0;
            }
        
            *line = header;
            
            return 0;
        } else {
            lineChars.push_back(ch);
        }
    }
}

static int checkHttpCode(VCNHttpContext *s, int http_code, const char *end)
{
    /* error codes are 4xx and 5xx, but regard 401 as a success, so we
     * don't abort until all headers have been parsed. */
    if (http_code >= 400 && http_code < 600 &&
        (http_code != 401 || s->auth_state.auth_type != HTTP_AUTH_NONE) &&
        (http_code != 407 || s->proxy_auth_state.auth_type != HTTP_AUTH_NONE)) {
        end += strspn(end, SPACE_CHARS);
        //VCN_LOGI( "HTTP error %d %s\n", http_code, end);
        //av_trace(s,AVERROR(EIO),"AVERROR(EIO)");
        return httpParserHttpAVError(http_code, AVERROR(EIO));
    }
    return 0;
}

static int parseLocation(VCNHttpContext *s, const char *p)
{
    char redirected_location[MAX_URL_SIZE], *new_loc;
    vcn_ff_make_absolute_url(redirected_location, sizeof(redirected_location),
                         s->location, p);
    new_loc = vcn_av_strdup(redirected_location);
    if (!new_loc){
        //av_trace(s,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
        return AVERROR(ENOMEM);
    }
    vcn_av_free(s->location);
    s->location = new_loc;

    if (s->parserNotifyer != nullptr) {
        s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsFinalUrl, 0, s->location);
    }
    if (s->headers != NULL && hasHeader(s->headers, "\r\nHost:")) {
        httpParserChangeHostname(s);
    }
    return 0;
}

/* "bytes $from-$to/$document_size" */
VCN_INTERFACE_EXPORT void httpParserParseContentRange(VCNHttpContext *s, const char *p)
{
    const char *slash;

    if (!strncmp(p, "bytes ", 6)) {
        p     += 6;
        s->off = strtoull(p, NULL, 10);
        if ((slash = strchr(p, '/')) && strlen(slash) > 0)
            s->filesize = strtoull(slash + 1, NULL, 10);
    }
    if (s->seekable == -1 && (!s->is_akamai || s->filesize != 2147483647))
        s->is_streamed = 0; /* we _can_ in fact seek */
}

static void parseRequestRange(VCNHttpContext *s, const char *p)
{
    const char *slash;
    
    if (!strncmp(p, "bytes=", 6)) {
        p     += 6;
        s->request_off = strtoull(p, NULL, 10);
        if ((slash = strchr(p, '-')) && strlen(slash) > 1) {
            s->request_end_off = strtoll(slash + 1, NULL, 10);
        }
        else {
            s->request_end_off = 0;
        }
    }
}

int parseContentEncoding(VCNHttpContext *s, const char *p)
{
    if (!vcn_av_strncasecmp(p, "gzip", 4) ||
        !vcn_av_strncasecmp(p, "deflate", 7)) {

        s->compressed = 1;
        inflateEnd(&s->inflate_stream);
        if (inflateInit2(&s->inflate_stream, 32 + 15) != Z_OK) {
            VCN_LOGI( "Error during zlib initialisation: %s\n",
                   s->inflate_stream.msg);
            //av_trace(s,AVERROR(ENOSYS),"AVERROR(ENOSYS)");
            return AVERROR(ENOSYS);
        }
        if (zlibCompileFlags() & (1 << 17)) {
            VCN_LOGI(
                   "Your zlib was compiled without gzip support.\n");
            //av_trace(s,AVERROR(ENOSYS),"AVERROR(ENOSYS)");
            return AVERROR(ENOSYS);
        }
    } else if (!vcn_av_strncasecmp(p, "identity", 8)) {
        // The normal, no-encoding case (although servers shouldn't include
        // the header at all if this is the case).
    } else {
        VCN_LOGI( "Unknown content coding: %s\n", p);
    }
    return 0;
}

// Concat all Icy- header lines
int parseIcy(VCNHttpContext *s, const char *tag, const char *p)
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

static int parseSetCookieExpiryTime(const char *exp_str, struct tm *buf)
{
    char exp_buf[MAX_EXPIRY];
    int i, j, exp_buf_len = MAX_EXPIRY-1;
    char *expiry;

    // strip off any punctuation or whitespace
    for (i = 0, j = 0; exp_str[i] != '\0' && j < exp_buf_len; i++) {
        if ((exp_str[i] >= '0' && exp_str[i] <= '9') ||
            (exp_str[i] >= 'A' && exp_str[i] <= 'Z') ||
            (exp_str[i] >= 'a' && exp_str[i] <= 'z')) {
            exp_buf[j] = exp_str[i];
            j++;
        }
    }
    exp_buf[j] = '\0';
    expiry = exp_buf;

    // move the string beyond the day of week
    while ((*expiry < '0' || *expiry > '9') && *expiry != '\0')
        expiry++;

    return vcn_av_small_strptime(expiry, "%d%b%Y%H%M%S", buf) ? 0 : AVERROR(EINVAL);
}

static int parse_set_cookie(const char *set_cookie, AVDictionary **dict)
{
    char *param, *next_param, *cstr, *back;

    if (!(cstr = vcn_av_strdup(set_cookie)))
        return AVERROR(EINVAL);

    // strip any trailing whitespace
    back = &cstr[strlen(cstr)-1];
    while (strchr(WHITESPACES, *back)) {
        *back='\0';
        back--;
    }

    next_param = cstr;
    while ((param = vcn_av_strtok(next_param, ";", &next_param))) {
        char *name, *value;
        param += strspn(param, WHITESPACES);
        if ((name = vcn_av_strtok(param, "=", &value))) {
            if (vcn_av_dict_set(dict, name, value, 0) < 0) {
                vcn_av_free(cstr);
                return -1;
            }
        }
    }

    vcn_av_free(cstr);
    return 0;
}

int parseCookie(VCNHttpContext *s, const char *p, AVDictionary **cookies)
{
    AVDictionary *new_params = NULL;
    AVDictionaryEntry *e, *cookie_entry;
    const char *eql;
    char *name;

    // ensure the cookie is parsable
    if (parse_set_cookie(p, &new_params))
        return -1;

    // if there is no cookie value there is nothing to parse
    cookie_entry = vcn_av_dict_get(new_params, "", NULL, AV_DICT_IGNORE_SUFFIX);
    if (!cookie_entry || !cookie_entry->value) {
        vcn_av_dict_free(&new_params);
        return -1;
    }

    // ensure the cookie is not expired or older than an existing value
    if ((e = vcn_av_dict_get(new_params, "expires", NULL, 0)) && e->value) {
        struct tm new_tm = {0};
        if (!parseSetCookieExpiryTime(e->value, &new_tm)) {
            AVDictionaryEntry *e2;

            // if the cookie has already expired ignore it
            if (vcn_av_timegm(&new_tm) < vcn_av_gettime() / 1000000) {
                vcn_av_dict_free(&new_params);
                return -1;
            }

            // only replace an older cookie with the same name
            e2 = vcn_av_dict_get(*cookies, cookie_entry->key, NULL, 0);
            if (e2 && e2->value) {
                AVDictionary *old_params = NULL;
                if (!parse_set_cookie(p, &old_params)) {
                    e2 = vcn_av_dict_get(old_params, "expires", NULL, 0);
                    if (e2 && e2->value) {
                        struct tm old_tm = {0};
                        if (!parseSetCookieExpiryTime(e->value, &old_tm)) {
                            if (vcn_av_timegm(&new_tm) < vcn_av_timegm(&old_tm)) {
                                vcn_av_dict_free(&new_params);
                                vcn_av_dict_free(&old_params);
                                return -1;
                            }
                        }
                    }
                }
                vcn_av_dict_free(&old_params);
            }
        }
    }
    
    vcn_av_dict_free(&new_params);
    
    // duplicate the cookie name (dict will dupe the value)
    if (!(eql = strchr(p, '='))) {
        //av_trace(s,AVERROR(EINVAL),"AVERROR(EINVAL)");
        return AVERROR(EINVAL);
    }
    if (!(name = vcn_av_strndup(p, eql - p))) {
        //av_trace(s,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
        return AVERROR(ENOMEM);
    }

    // add the cookie to the dictionary
    vcn_av_dict_set(cookies, name, eql, AV_DICT_DONT_STRDUP_KEY);

    return 0;
}

static int cookieString(AVDictionary *dict, char **cookies)
{
    AVDictionaryEntry *e = NULL;
    int len = 1;

    // determine how much memory is needed for the cookies string
    while ((e = vcn_av_dict_get(dict, "", e, AV_DICT_IGNORE_SUFFIX)))
        len += strlen(e->key) + strlen(e->value) + 1;

    // reallocate the cookies
    e = NULL;
    if (*cookies) vcn_av_free(*cookies);
    *cookies = (char*)vcn_av_malloc(len);
    if (!*cookies) {
        //av_trace(NULL,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
        return AVERROR(ENOMEM);
    }
    *cookies[0] = '\0';

    // write out the cookies
    while ((e = vcn_av_dict_get(dict, "", e, AV_DICT_IGNORE_SUFFIX)))
        vcn_av_strlcatf(*cookies, len, "%s%s\n", e->key, e->value);

    return 0;
}
static int processLineErrContinue(VCNHttpContext *s, char *line, int line_count,
                                     int *new_location)
{
    const char *auto_method =  s->flags & AVIO_FLAG_READ ? "POST" : "GET";
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
            VCN_LOGI( "Received method: %s\n", method);
            if (s->method) {
                if (vcn_av_strcasecmp(s->method, method)) {
                    VCN_LOGI( "Received and expected HTTP method do not match. (%s expected, %s received)\n",
                           s->method, method);
                    return httpParserHttpAVError(400, AVERROR(EIO));
                }
            } else {
                // use autodetected HTTP method to expect
                VCN_LOGI( "Autodetected %s HTTP method\n", auto_method);
                if (vcn_av_strcasecmp(auto_method, method)) {
                    VCN_LOGI( "Received and autodetected HTTP method did not match "
                           "(%s autodetected %s received)\n", auto_method, method);
                    return httpParserHttpAVError(400, AVERROR(EIO));
                }
                if (!(s->method = vcn_av_strdup(method))){
                    //av_trace(h,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
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
            VCN_LOGI( "Requested resource: %s\n", resource);
            if (!(s->resource = vcn_av_strdup(resource))){
                //av_trace(h,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
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
                VCN_LOGI( "Malformed HTTP version string.\n");
                return httpParserHttpAVError(400, AVERROR(EIO));
            }
            VCN_LOGI( "HTTP version string: %s\n", version);
        } else {
            while (!av_isspace(*p) && *p != '\0')
                p++;
            while (av_isspace(*p))
                p++;
            s->http_code = strtol(p, &end, 10);

            VCN_LOGI( "http_code=%d\n", s->http_code);

            if ((ret = checkHttpCode(s, s->http_code, end)) < 0){
                if(s->http_code == 404) {
                    VCN_LOGI( "http_code 404\n");
                    return 1;
                }
                //av_trace(h,ret,"ret:%d",ret);
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
        while (av_isspace(*p)) {
            p++;
        }

        if(s->parserNotifyer != nullptr) {
            VCN_LOGWD("notify other onresponse header key:%s value:%s", tag, p);
            s->parserNotifyer->onResponseHeader(tag, p);
        }
        if (!vcn_av_strcasecmp(tag, "Location")) {
            if ((ret = parseLocation(s, p)) < 0){
                //av_trace(h,ret,"ret:%d", ret);
                return ret;
            }
            *new_location = 1;
        } else if (!vcn_av_strcasecmp(tag, "Content-Length") &&
                   s->filesize == UINT64_MAX) {
            s->filesize = strtoull(p, NULL, 10);
        } else if (!vcn_av_strcasecmp(tag, "Content-Range")) {
            httpParserParseContentRange(s, p);
        }else if (!vcn_av_strcasecmp(tag, "Range")) {
            parseRequestRange(s, p);
        }else if (!vcn_av_strcasecmp(tag, "Accept-Ranges") &&
                   !strncmp(p, "bytes", 5) &&
                   s->seekable == -1) {
            s->is_streamed = 0;
        } else if (!vcn_av_strcasecmp(tag, "Transfer-Encoding") &&
                   !vcn_av_strncasecmp(p, "chunked", 7)) {
            s->filesize  = UINT64_MAX;
            s->chunksize = 0;
        } else if (!vcn_av_strcasecmp(tag, "WWW-Authenticate")) {
            //ff_http_auth_handle_header(&s->auth_state, tag, p);
        } else if (!vcn_av_strcasecmp(tag, "Authentication-Info")) {
            //ff_http_auth_handle_header(&s->auth_state, tag, p);
        } else if (!vcn_av_strcasecmp(tag, "Proxy-Authenticate")) {
            //ff_http_auth_handle_header(&s->proxy_auth_state, tag, p);
        } else if (!vcn_av_strcasecmp(tag, "Connection")) {
            if (!vcn_av_strcasecmp(p, "close")) {
                s->willclose = 1;
                VCN_LOGI( "conn is to be closed");
            }
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
            if (parseCookie(s, p, &s->cookie_dict)) {
                VCN_LOGI( "Unable to parse '%s'\n", p);
            }
        } else if (!vcn_av_strcasecmp(tag, "Icy-MetaInt")) {
            s->icy_metaint = strtoull(p, NULL, 10);
        } else if (!vcn_av_strncasecmp(tag, "Icy-", 4)) {
            if ((ret = parseIcy(s, tag, p)) < 0){
                //av_trace(h,ret,"ret:%d", ret);
                return ret;
            }
        } else if (!vcn_av_strcasecmp(tag, "Content-Encoding")) {

            if ((ret = parseContentEncoding(s, p)) < 0){
                //av_trace(h,ret,"ret:%d", ret);
                return ret;
            }
        }
    }
    return 1;
}

static int processLineOriginal(VCNHttpContext *s, char *line, int line_count,
                                 int *new_location)
{
    const char *auto_method =  s->flags & AVIO_FLAG_READ ? "POST" : "GET";
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
            VCN_LOGI( "Received method: %s\n", method);
            if (s->method) {
                if (vcn_av_strcasecmp(s->method, method)) {
                    VCN_LOGI( "Received and expected HTTP method do not match. (%s expected, %s received)\n",
                           s->method, method);
                    return httpParserHttpAVError(400, AVERROR(EIO));
                }
            } else {
                // use autodetected HTTP method to expect
                VCN_LOGI( "Autodetected %s HTTP method\n", auto_method);
                if (vcn_av_strcasecmp(auto_method, method)) {
                    VCN_LOGI( "Received and autodetected HTTP method did not match "
                           "(%s autodetected %s received)\n", auto_method, method);
                    return httpParserHttpAVError(400, AVERROR(EIO));
                }
                if (!(s->method = vcn_av_strdup(method))){
                    //av_trace(h,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
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
            VCN_LOGI( "Requested resource: %s\n", resource);
            if (!(s->resource = vcn_av_strdup(resource))){
                //av_trace(h,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
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
                VCN_LOGI( "Malformed HTTP version string.\n");
                return httpParserHttpAVError(400, AVERROR(EIO));
            }
            VCN_LOGI( "HTTP version string: %s\n", version);
        } else {
            while (!av_isspace(*p) && *p != '\0')
                p++;
            while (av_isspace(*p))
                p++;
            s->http_code = strtol(p, &end, 10);
            if (s->parserNotifyer!= nullptr) {
                s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsCDNStatusCode, s->http_code, nullptr);
            }

            VCN_LOGI( "http_code=%d\n", s->http_code);

            if ((ret = checkHttpCode(s, s->http_code, end)) < 0){
                //av_trace(h,ret,"ret:%d",ret);
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
        
        if (s->is_connected_server) {
            if (vcn_av_strcasecmp(tag, "Range") &&
                vcn_av_strcasecmp(tag, "Connection") &&
                vcn_av_strcasecmp(tag, "Host")) {
                s->receivedHeader.insert(std::make_pair(std::string(tag), std::string(p)));
            }
        }
        if(s->parserNotifyer != nullptr) {
            VCN_LOGWD("notify other onresponse header key:%s value:%s", tag, p);
            s->parserNotifyer->onResponseHeader(tag, p);
        }
        if (!vcn_av_strcasecmp(tag, "Location")) {
            if ((ret = parseLocation(s, p)) < 0){
                //av_trace(h,ret,"ret:%d", ret);
                return ret;
            }
            *new_location = 1;
        } else if (!vcn_av_strcasecmp(tag, "Content-Length") &&
                   s->filesize == UINT64_MAX) {
            s->filesize = strtoull(p, NULL, 10);
        } else if (!vcn_av_strcasecmp(tag, "Content-Range")) {
            httpParserParseContentRange(s, p);
        } else if (!vcn_av_strcasecmp(tag, "Range")) {
            if (s->is_connected_server) {
                VCN_LOGI("recevice req:%s",p);
            }
            parseRequestRange(s, p);
        } else if (!vcn_av_strcasecmp(tag, "Accept-Ranges") &&
                   !strncmp(p, "bytes", 5) &&
                   s->seekable == -1) {
            s->is_streamed = 0;
        } else if (!vcn_av_strcasecmp(tag, "Transfer-Encoding") &&
                   !vcn_av_strncasecmp(p, "chunked", 7)) {
            s->filesize  = UINT64_MAX;
            s->chunksize = 0;
        } else if (!vcn_av_strcasecmp(tag, "WWW-Authenticate")) {
           // ff_http_auth_handle_header(&s->auth_state, tag, p);
        } else if (!vcn_av_strcasecmp(tag, "Authentication-Info")) {
            //ff_http_auth_handle_header(&s->auth_state, tag, p);
        } else if (!vcn_av_strcasecmp(tag, "Proxy-Authenticate")) {
            //ff_http_auth_handle_header(&s->proxy_auth_state, tag, p);
        } else if (!vcn_av_strcasecmp(tag, "Connection")) {
            if (!vcn_av_strcasecmp(p, "close")) {
                s->willclose = 1;
                VCN_LOGI( "conn is to be closed");
            }
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
            if (parseCookie(s, p, &s->cookie_dict)) {
                VCN_LOGI( "Unable to parse '%s'\n", p);
            }
        } else if (!vcn_av_strcasecmp(tag, "Icy-MetaInt")) {
            s->icy_metaint = strtoull(p, NULL, 10);
        } else if (!vcn_av_strncasecmp(tag, "Icy-", 4)) {
            if ((ret = parseIcy(s, tag, p)) < 0){
                //av_trace(h,ret,"ret:%d", ret);
                return ret;
            }
        } else if (!vcn_av_strcasecmp(tag, "Content-Encoding")) {
            if ((ret = parseContentEncoding(s, p)) < 0){
                //av_trace(h,ret,"ret:%d", ret);
                return ret;
            }
        }
    }
    return 1;
}

static bool checkHiJack(VCNHttpContext *s){
    VCN_LOGI("begin checkHiJack");
    size_t len = strlen(s->mRequestAccessCheck);
    char * checksum = nullptr;
    checksum = new char[len + 10];
    memset(checksum, 0, len + 10);
    snprintf(checksum,len+10,"%s_%s","checksum",s->mRequestAccessCheck);
    VCN_LOGI("mRequestAccessCheck:%s and mResponseAccessCheck:%s",checksum,s->mResponseAccessCheck);
    bool hiJackFlag = false;
    if (strcmp(checksum,s->mResponseAccessCheck)) {
        hiJackFlag = true;
    }
    VCN_DELETE_STRING(checksum)
    VCN_LOGI("hiJack result:%d",hiJackFlag);
    return hiJackFlag;
}

static int processLine(VCNHttpContext *s, char *line, int line_count,
                        int *new_location) {
    if(s->is_err_continue) {
        return processLineErrContinue(s, line, line_count, new_location);
    }
    return processLineOriginal(s, line, line_count, new_location);
}

/**
 * Create a string containing cookie values for use as a HTTP cookie header
 * field value for a particular path and domain from the cookie values stored in
 * the HTTP protocol context. The cookie string is stored in *cookies.
 *
 * @return a negative value if an error condition occurred, 0 otherwise
 */
static int getCookies(VCNHttpContext *s, char **cookies, const char *path,
                       const char *domain)
{
    // cookie strings will look like Set-Cookie header field values.  Multiple
    // Set-Cookie fields will result in multiple values delimited by a newline
    int ret = 0;
    char *cookie, *set_cookies = vcn_av_strdup(s->cookies), *next = set_cookies;

    if (!set_cookies) {
        //av_trace(s,AVERROR(EINVAL),"AVERROR(EINVAL)");
        return AVERROR(EINVAL);
    }

    // destroy any cookies in the dictionary.
    vcn_av_dict_free(&s->cookie_dict);

    *cookies = NULL;
    while ((cookie = vcn_av_strtok(next, "\n", &next))) {
        AVDictionary *cookie_params = NULL;
        AVDictionaryEntry *cookie_entry, *e;

        // store the cookie in a dict in case it is updated in the response
        if (parseCookie(s, cookie, &s->cookie_dict))
            //av_log(s, AV_LOG_WARNING, "Unable to parse '%s'\n", cookie);

        // continue on to the next cookie if this one cannot be parsed
        if (parse_set_cookie(cookie, &cookie_params))
            continue;

        // if the cookie has no value, skip it
        cookie_entry = vcn_av_dict_get(cookie_params, "", NULL, AV_DICT_IGNORE_SUFFIX);
        if (!cookie_entry || !cookie_entry->value) {
            vcn_av_dict_free(&cookie_params);
            continue;
        }

        // if the cookie has expired, don't add it
        if ((e = vcn_av_dict_get(cookie_params, "expires", NULL, 0)) && e->value) {
            struct tm tm_buf = {0};
            if (!parseSetCookieExpiryTime(e->value, &tm_buf)) {
                if (vcn_av_timegm(&tm_buf) < vcn_av_gettime() / 1000000) {
                    vcn_av_dict_free(&cookie_params);
                    continue;
                }
            }
        }

        // if no domain in the cookie assume it appied to this request
        if ((e = vcn_av_dict_get(cookie_params, "domain", NULL, 0)) && e->value) {
            // find the offset comparison is on the min domain (b.com, not a.b.com)
            int domain_offset = strlen(domain) - strlen(e->value);
            if (domain_offset < 0) {
                vcn_av_dict_free(&cookie_params);
                continue;
            }

            // match the cookie domain
            if (vcn_av_strcasecmp(&domain[domain_offset], e->value)) {
                vcn_av_dict_free(&cookie_params);
                continue;
            }
        }

        // ensure this cookie matches the path
        e = vcn_av_dict_get(cookie_params, "path", NULL, 0);
        if (!e || vcn_av_strncasecmp(path, e->value, strlen(e->value))) {
            vcn_av_dict_free(&cookie_params);
            continue;
        }

        // cookie parameters match, so copy the value
        if (!*cookies) {
            if (!(*cookies = vcn_av_asprintf("%s=%s", cookie_entry->key, cookie_entry->value))) {
                //av_trace(s,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
                ret = AVERROR(ENOMEM);
                break;
            }
        } else {
            char *tmp = *cookies;
            size_t str_size = strlen(cookie_entry->key) + strlen(cookie_entry->value) + strlen(*cookies) + 4;
            if (!(*cookies = (char*)vcn_av_malloc(str_size))) {
                //av_trace(s,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
                ret = AVERROR(ENOMEM);
                vcn_av_free(tmp);
                break;
            }
            snprintf(*cookies, str_size, "%s; %s=%s", tmp, cookie_entry->key, cookie_entry->value);
            vcn_av_free(tmp);
        }
    }

    vcn_av_free(set_cookies);

    return ret;
}

static inline int hasHeader(const char *str, const char *header)
{
    /* header + 2 to skip over CRLF prefix. (make sure you have one!) */
    if (!str)
        return 0;
    return vcn_av_stristart(str, header + 2, NULL) || vcn_av_stristr(str, header);
}

static int httpReadHeader(VCNHttpContext *s, int *new_location)
{
    if (s->isUnlimitHttpHeader == 1) {
        return httpReadHeaderUnlimit(s, new_location);
    }
    char line[MAX_URL_SIZE];
    int err = 0;

    s->receivedHeader.clear();

    s->chunksize = UINT64_MAX;

    for (;;) {
        if ((err = httpParsrGetLine(s, line, sizeof(line))) < 0)
            return err;
        if(s->is_multi_client) {
            VCN_LOGWD( "[socket reuse flag] local server header='%s'\n", line);
        } else {
            VCN_LOGWD( "http request header='%s'\n", line);
        }

        err = processLine(s, line, s->line_count, new_location);
        if (err < 0) {
            //av_fatal(h, err, line);
            return err;
        }
        if (err == 0)
            break;
        s->line_count++;
    }

    if (s->seekable == -1 && s->is_mediagateway && s->filesize == 2000000000)
        s->is_streamed = 1; /* we can in fact _not_ seek */

    // add any new cookies into the existing cookie string
    cookieString(s->cookie_dict, &s->cookies);
    vcn_av_dict_free(&s->cookie_dict);
    return err;
}

static int httpReadHeaderUnlimit(VCNHttpContext *s, int *new_location) {
    char *header = nullptr;
    int err = 0;

    s->receivedHeader.clear();

    s->chunksize = UINT64_MAX;

    for (;;) {
        if ((err = httpGetHeaderLineUnlimit(s, &header)) < 0)
            return err;
        if (header == nullptr) {
            return AVERROR(ENOMEM);
        }
        if(s->is_multi_client) {
            VCN_LOGWD( "[socket reuse flag] local server header='%s'\n", header);
        } else {
            VCN_LOGWD( "http request header='%s'\n", header);
        }

        err = processLine(s, header, s->line_count, new_location);
        vcn_av_free(header);
        if (err < 0) {
            //av_fatal(h, err, line);
            return err;
        }
        if (err == 0)
            break;
        s->line_count++;
    }

    if (s->seekable == -1 && s->is_mediagateway && s->filesize == 2000000000)
        s->is_streamed = 1; /* we can in fact _not_ seek */

    // add any new cookies into the existing cookie string
    cookieString(s->cookie_dict, &s->cookies);
    vcn_av_dict_free(&s->cookie_dict);
    return err;
}

static int httpConnect(VCNHttpContext *s, const char *path, const char *local_path,
                        const char *hoststr, const char *auth,
                        const char *proxyauth, int *new_location)
{
    int post, err;
    char headers[HTTP_HEADERS_SIZE] = "";
    char *authstr = NULL, *proxyauthstr = NULL;
    uint64_t off = s->off;
    int len = 0;
    const char *method;
    int send_expect_100 = 0;
    int ret;
    int reWrite = 0;

    /* send http header */
    post = 0;//h->flags & AVIO_FLAG_WRITE;

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

    authstr      = NULL; //ff_http_auth_create_response(&s->auth_state, auth,
                                                //local_path, method);
    proxyauthstr = NULL;//ff_http_auth_create_response(&s->proxy_auth_state, proxyauth,
                                               // local_path, method);
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
    
    if (s->isUnlimitHttpHeader == 1) {
        goto write;
    }



    /* set default headers if needed */
    if (!hasHeader(s->headers, "\r\nUser-Agent: "))
        len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                           "User-Agent: %s\r\n", s->user_agent);
    if (!hasHeader(s->headers, "\r\nAccept: "))
        len += vcn_av_strlcpy(headers + len, "Accept: */*\r\n",
                          sizeof(headers) - len);
    // Note: we send this on purpose even when s->off is 0 when we're probing,
    // since it allows us to detect more reliably if a (non-conforming)
    // server supports seeking by analysing the reply headers.
    if (!hasHeader(s->headers, "\r\nRange: ") && !post && (s->off > 0 || s->end_off || s->seekable == -1)) {
        len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                           "Range: bytes=%" PRIu64"-", s->off);
        if (s->end_off)
            len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                               "%" PRIu64, s->end_off - 1);
        len += vcn_av_strlcpy(headers + len, "\r\n",
                          sizeof(headers) - len);
    }
    if (send_expect_100 && !hasHeader(s->headers, "\r\nExpect: "))
        len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                           "Expect: 100-continue\r\n");

    if (!hasHeader(s->headers, "\r\nConnection: ")) {
        if (s->multiple_requests)
            len += vcn_av_strlcpy(headers + len, "Connection: keep-alive\r\n",
                              sizeof(headers) - len);
        else
            len += vcn_av_strlcpy(headers + len, "Connection: close\r\n",
                              sizeof(headers) - len);
    }

    if (!hasHeader(s->headers, "\r\nHost: "))
        len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                           "Host: %s\r\n", hoststr);
    if (!hasHeader(s->headers, "\r\nContent-Length: ") && s->post_data)
        len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                           "Content-Length: %d\r\n", s->post_datalen);

    if (!hasHeader(s->headers, "\r\nContent-Type: ") && s->content_type)
        len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                           "Content-Type: %s\r\n", s->content_type);
    if (!hasHeader(s->headers, "\r\nCookie: ") && s->cookies) {
        char *cookies = NULL;
        if (!getCookies(s, &cookies, path, hoststr) && cookies) {
            len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                               "Cookie: %s\r\n", cookies);
            vcn_av_free(cookies);
        }
    }
    if (!hasHeader(s->headers, "\r\nIcy-MetaData: ") && s->icy)
        len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                           "Icy-MetaData: %d\r\n", 1);
    
    if (s->parserHelper != nullptr) {

        if(s->forbidByPassCookie) {
            char* customHeader = s->parserHelper->getStringValue(VCNHttpParserHelperKey::VCNHttpParserHelperKeyIsCustomHeader, s->reserved_code, s->location);
            VCN_LOGWD("bypass cookie:%d customheader:%s", s->forbidByPassCookie, customHeader);
            if(!(VCN_IS_EMPTY_STRING(customHeader))) {
                len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                                   "%s", customHeader);
            }
            VCN_DELETE_STRING(customHeader)
        }

    }

    /* now add in custom headers */
    if (s->headers)
        vcn_av_strlcpy(headers + len, s->headers, sizeof(headers) - len);

    if (s->parserNotifyer != nullptr) {
        s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsEventInfo, 0, headers);
    }


    ret = snprintf((char*)s->buffer, sizeof(s->buffer),
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

    VCN_LOGWD( "request: %s\n", s->buffer);

    if (strlen(headers) + 1 == sizeof(headers) ||
        ret >= sizeof(s->buffer)) {
        VCN_LOGI( "overlong headers\n");
        err = AVERROR(EINVAL);
        goto done;
    }

write:
    reWrite = reWrite + 1;
    
    if (s->isUnlimitHttpHeader == 1) {
        if ((err = httpWriteHeaderUnlimit(s, post, send_expect_100, hoststr, path, method, authstr, proxyauthstr) < 0)) {
            goto done;
        }
    } else {
        if ((err = vcn_url_write(s->hd, s->buffer, strlen((char*)s->buffer))) < 0)
            goto done;
    }

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
    s->httpFirstPacketT = 0;
    s->compressed       = 0;
    s->isttfb           = 0;

    if (post && !s->post_data && !send_expect_100) {
        /* Pretend that it did work. We didn't read any header yet, since
         * we've still to send the POST data, but the code calling this
         * function will check http_code after we return. */
        s->http_code = 200;
        err = 0;
        goto done;
    }

    /* wait for header */
    err = httpReadHeader(s, new_location);
    VCN_LOGWD("rewrite num:%d read header:%d", reWrite, err);
    if(err == AVERROR_EARLY_DATA_REJECTED) {
        VCN_LOGWD("earlydata rejected try rewrite");
        goto write;
    }
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
static void httpCheckSocket(VCNHttpContext *s, int isCheckHttpCode) {
    if ((!s->multiple_requests) || s->socketInfoManager == nullptr || s->willclose) {
        VCN_LOGI("****add socket fail!");
        return;
    }
    VCN_LOGI("---try to add socket");
    bool isNeedReuse = false;
    if (isCheckHttpCode &&
        (s->http_code == 301 || s->http_code == 302 ||
         s->http_code == 303 || s->http_code == 307 ||
         s->http_code == 308)) {
            if (s->chunksize != UINT64_MAX) {
                VCN_LOGI("[socket reuse] when 302 chunk, not enable resue socket");
                return;
            }
            int len = s->buf_end - s->buf_ptr;
            if (s->filesize != UINT64_MAX && (len != s->filesize)) {
                VCN_LOGI("[socket reuse] filesize;%llu len:%d not match, socket has body data, can not be used",s->filesize, len);
                return;
            }
            isNeedReuse = true;
    }
    uint64_t target_end = s->end_off ? s->end_off : s->filesize;
    if ((s->chunksize == UINT64_MAX && s->off >= target_end) || isNeedReuse) {
        VCN_LOGI("[socket reuse] http request is finish, socket can be reuse, isneeduse flag:%d",isNeedReuse);
        VCNSocketInfo *info = new VCNSocketInfo(s->hd, s->connectedHost, s->connectedIp, s->port,0, s->lowerProto,
                                                nullptr);
        VCN_LOGWD("[socket reuse flag] socket add socket for info:%p host:%s ip:%s port:%d",info->socketHd,info->host, info->ip,info->port);
        s->hd = nullptr;
        info->isUsed = 1;
        info->useCount = ++s->socketInfo.useCount;
        info->createT = s->socketInfo.createT;
        VCN_MEMCPY_STRING(info->tlsVersion, s->socketInfo.tlsVersion)
        s->socketInfoManager->setSocketInfo(info);
        VCN_DELETE_OBJECT(info)
    }
    VCN_LOGI("**** try to add socket end");
    return;
}
static char* httpInitSocket(VCNHttpContext *s, const char* host, int port, int lowerProto) {
    s->socketInfo.reset();
    if (s->socketInfoManager == nullptr) {
        return nullptr;
    }
    if (!s->multiple_requests) {
        return dnsParse(s, host);
    }
    
    VCN_LOGI("[socket reuse]----socket get socket for host:%s port:%d",host, port);
    VCNSocketInfo *info = nullptr;
    char* ipList = nullptr;
    if (s->parserStrategy && !s->parserStrategy->getStrategyIntValue(VCNHttpParserStrategyKey::VCNHttpParserStrategyKeyIsEnablePreconnect)) {
        VCN_LOGI("[socket reuse]get socket info by ip and port, first dns parse");
        ipList = dnsParse(s, host);
//        VCN_LOGI("parse result ip is:%s host:%s",ipList,host);
        info = s->socketInfoManager->getSocketInfoByIp(host, ipList, port, lowerProto);
    } else {
        VCN_LOGI("[socket reuse]get socket info by host and port first");
        info = s->socketInfoManager->getSocketInfoByHost(host, port, lowerProto, s->customHost, s->dns_type);
        if (info == nullptr) {
            VCN_LOGI("[socket reuse]get socket info by host and port null, later do dns parse");
            ipList = dnsParse(s, host);
//            VCN_LOGI("parse result ip is:%s host:%s",ipList,host);
        }
    }
    
    
    
    if (info != nullptr) {
        s->hd = info->socketHd;
        s->hd->interrupt_callback = s->interrupt_callback;
        s->hd->log_handle = s->log_handle;
        if (info->port == 443 || info->lowerProto == LowerProtoIsTLS) {
            vcn_tls_reset_interrupt_callback(s->hd);
        }
        VCN_MEMCPY_STRING(s->connectedIp, info->ip)
        VCN_MEMCPY_STRING(s->connectedHost, info->host)
        s->port = info->port;
        if (s->parserNotifyer != nullptr) {
            s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsConnectedIp, 0, s->connectedIp);
            s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsParsedIpList, 0, ipList);
            char socketId[1024];
            memset(socketId, 0, sizeof(socketId));
            snprintf(socketId, sizeof(socketId), "%" PRId64"_%p", info->createT, info->socketHd);
            s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsSocketReuseFlag, 1, socketId);
            s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsRequestHost, 0, info->host);
            s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsSocketInfoTlsVersion, 0, info->tlsVersion);
            s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsSocketInfoUsedCout, info->useCount, nullptr);
            s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsSocketInfoCreateTimeInternal, vcnGetCurrentTime() - info->createT, nullptr);
            s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsSocketInfoIdleTimeInternal, vcnGetCurrentTime() - info->idleStartT, nullptr);
            VCN_LOGWD("parser reuse socket hd:%p tls version:%s usecount:%d create time:%lld idleTime:%lld",
                  info->socketHd, info->tlsVersion, info->useCount, info->createT, vcnGetCurrentTime() - info->idleStartT);
        }
        s->socketInfo = *info;
    }
    else {
        VCN_LOGI("fail");
    }
    VCN_LOGWD("[socket reuse flag]****get socket info:%s  host:%s port:%d lowerproto:%d ipList is:%s", info==nullptr?"fail":"suc", host, port, lowerProto, ipList);
    VCN_DELETE_OBJECT(info)
    return ipList;
}
static int httpBufRead(VCNHttpContext *s, uint8_t *buf, int size)
{
    int len;

    if (!s || !s->hd) {
        return AVERROR(EIO);
    }
    if (s->chunksize != UINT64_MAX) {
        if (!s->chunksize) {
            if(s->chunk_eof) {
                return 0;
            }
            char line[32];
            int err;

            do {
                if ((err = httpParsrGetLine(s, line, sizeof(line))) < 0)
                    return err;
            } while (!*line);    /* skip CR LF from last chunk */

            s->chunksize = strtoull(line, NULL, 16);

            VCN_LOGI("Chunked encoding data size: %" PRIu64"'\n",
                   s->chunksize);

            if (!s->chunksize) {
                s->chunk_eof = true;
                return 0;
            }
            else if (s->chunksize == UINT64_MAX) {
                VCN_LOGI( "Invalid chunk size %" PRIu64"\n",
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
//        len = vcn_url_read(s->hd, buf, size);
        len = low_proto_read(s, buf,  size);
        if (!len && (!s->willclose || s->chunksize == UINT64_MAX) && s->off < target_end) {
            VCN_LOGI(
                   "Stream ends prematurely at %" PRIu64", should be %" PRIu64"\n",
                   s->off, target_end
                   );
            //av_trace(h,AVERROR(EIO),"AVERROR(EIO)");
            if(vcn_ff_check_interrupt(&s->interrupt_callback)) {
                return AVERROR_EXIT;
            }
            return AVERROR(EIO);
        }
    }
    if (len > 0) {
        s->recv_size += len;
        s->off += len;
        if (s->chunksize > 0 && s->chunksize != UINT64_MAX) {
            //av_assert0(s->chunksize >= len);
            s->chunksize -= len;
        }
        httpCheckSocket(s, 0);
        httpNotifySockInfo(s);
    }
    return len;
}

#define DECOMPRESS_BUF_SIZE (256 * 1024)
static int httpBufReadCompressed(VCNHttpContext *s, uint8_t *buf, int size)
{
    int ret;

    if (!s->inflate_buffer) {
        s->inflate_buffer = (uint8_t*)vcn_av_malloc(DECOMPRESS_BUF_SIZE);
        if (!s->inflate_buffer) {
            //av_trace(h,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
            return AVERROR(ENOMEM);
        }
    }

    if (s->inflate_stream.avail_in == 0) {
        int read = httpBufRead(s, s->inflate_buffer, DECOMPRESS_BUF_SIZE);
        if (read <= 0)
            return read;
        s->inflate_stream.next_in  = s->inflate_buffer;
        s->inflate_stream.avail_in = read;
    }

    s->inflate_stream.avail_out = size;
    s->inflate_stream.next_out  = buf;

    ret = inflate(&s->inflate_stream, Z_SYNC_FLUSH);
    if (ret != Z_OK && ret != Z_STREAM_END)
        VCN_LOGI( "inflate return value: %d, %s\n",
               ret, s->inflate_stream.msg);

    return size - s->inflate_stream.avail_out;
}

static int64_t httpSeekInternal(VCNHttpContext *s, int64_t off, int whence, int force_reconnect);

static int httpReadStream(VCNHttpContext *s, uint8_t *buf, int size)
{
    int err, new_location, read_ret;
    int64_t seek_ret;

    if (!s->hd){
        return AVERROR_EOF;
    }

    if (s->end_chunked_post && !s->end_header) {
        err = httpReadHeader(s, &new_location);
        if (err < 0){
            //av_trace(h,err,"err:%d", err);
            return err;
        }
    }

    if (s->compressed)
        return httpBufReadCompressed(s, buf, size);

    read_ret = httpBufRead(s, buf, size);
    if (   (read_ret  < 0 && s->reconnect  && read_ret != AVERROR_EXIT && (!s->is_streamed || s->reconnect_streamed) && s->filesize > 0 && s->off < s->filesize)
        || (read_ret == 0 && s->reconnect_at_eof && (!s->is_streamed || s->reconnect_streamed))) {
        uint64_t target = s->is_streamed ? 0 : s->off;
#if !defined(HTTP_AUTO_RECONNECT)
        VCN_LOGK("no define http auto reconnect");
        int interrupt = 0;
        if (s->reconnect_delay > s->reconnect_delay_max){
            ////av_trace(h,AVERROR(EIO),"AVERRR(EIO)");
            return AVERROR(EIO);
        }
#endif
//        VCN_LOGI( "Will reconnect at %" PRIu64" error=%s.\n", s->off, av_err2str(read_ret));
#if defined(HTTP_AUTO_RECONNECT)
        seek_ret = httpSeekInternal(s, target, SEEK_SET, 1);
#else
        if(s->interrupt_callback.callback!= NULL) {
            int64_t timeout = 1000U*1000*s->reconnect_delay;
            while(timeout > 0  && !s->interrupt_callback.callback(h->interrupt_callback.opaque) ) {
                vcn_av_usleep(1000);
                timeout -= 1000;
            }
            interrupt = s->interrupt_callback.callback(h->interrupt_callback.opaque);
        } else {
            vcn_av_usleep(1000U*1000*s->reconnect_delay);
        }
        if(interrupt) {
            return AVERROR_EXIT;
        }
        s->reconnect_delay = 1 + 2*s->reconnect_delay;

        seek_ret = httpSeekInternal(s, target, SEEK_SET, 1);
#endif
        if (seek_ret != target) {
            VCN_LOGI( "Failed to reconnect at %" PRIu64".\n", target);
            return read_ret;
        }
        read_ret = httpBufRead(s, buf, size);

        if (read_ret < 0) {
            if (read_ret != AVERROR_EOF && read_ret != AVERROR_EXIT) {
                httpNotifyError(s, VCNHttpParserErrorType::VCNHttpParserErrorTypeIsTCP,
                                        read_ret, "");
            }
        }

    } else {
#if !defined(HTTP_AUTO_RECONNECT)
        s->reconnect_delay = 0;
#endif
    }

    if (read_ret < 0) {
        if (read_ret != AVERROR_EOF && read_ret != AVERROR_EXIT) {
            httpNotifyError(s, VCNHttpParserErrorType::VCNHttpParserErrorTypeIsTCP, read_ret, "");
        }
    }

    return read_ret;
}

static void httpNotifyError(VCNHttpContext *s, VCNHttpParserErrorType err_type, int error_code, const char* extra) {
    if (s == nullptr || s->parserStrategy == nullptr) {
        return;
    }
    
    if (error_code == AVERROR_EOF && error_code == AVERROR_EXIT) {
        return;
    }
    
    if (s->socketInfo.isUsed && error_code == AVERROR(EIO)) {
        return;
    }
    s->parserStrategy->onError(s, err_type, error_code, extra);
}

// Like httpReadStream(), but no short reads.
// Assumes partial reads are an error.
static int httpReadStreamAll(VCNHttpContext *s, uint8_t *buf, int size)
{
    int pos = 0;
    while (pos < size) {
        int len = httpReadStream(s, buf + pos, size - pos);
        if (len < 0)
            return len;
        pos += len;
    }
    return pos;
}

static void updateMetadata(VCNHttpContext *s, char *data)
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

static int storeIcy(VCNHttpContext *s, int size)
{
    /* until next metadata packet */
    uint64_t remaining;

    if (s->icy_metaint < s->icy_data_read) {
        //av_trace(h,AVERROR_INVALIDDATA,"AVERROR_INVALIDDATA");
        return AVERROR_INVALIDDATA;
    }
    remaining = s->icy_metaint - s->icy_data_read;

    if (!remaining) {
        /* The metadata packet is variable sized. It has a 1 byte header
         * which sets the length of the packet (divided by 16). If it's 0,
         * the metadata doesn't change. After the packet, icy_metaint bytes
         * of normal data follows. */
        uint8_t ch;
        int len = httpReadStreamAll(s, &ch, 1);
        if (len < 0)
            return len;
        if (ch > 0) {
            char data[255 * 16 + 1];
            int ret;
            len = ch * 16;
            ret = httpReadStreamAll(s, (uint8_t *)data, len);
            if (ret < 0)
                return ret;
            data[len + 1] = 0;
            if ((ret = vcn_av_opt_set(s, "icy_metadata_packet", data, 0)) < 0)
                return ret;
            updateMetadata(s, data);
        }
        s->icy_data_read = 0;
        remaining        = s->icy_metaint;
    }

    return FFMIN(size, remaining);
}

VCN_INTERFACE_EXPORT int httpParserRead(VCNHttpContext *s, uint8_t *buf, int size)
{

    if (!s) {
        return VCNHttpParserError::IsContextNullError;
    }
    
    if (s->icy_metaint > 0) {
        size = storeIcy(s, size);
        if (size < 0)
            return size;
    }

    size = httpReadStream(s, buf, size);
    if (size > 0) {
        s->icy_data_read += size;
        s->bodyReadSize  += size;
    }
    return size;
}

/* used only when posting data */
VCN_INTERFACE_EXPORT int httpParserWrite(VCNHttpContext *s, const uint8_t *buf, int size)
{
    if (!s || !s->hd) {
        return VCNHttpParserError::IsContextNullError;
    }
    char temp[11] = "";  /* 32-bit hex + CRLF + nul */
    int ret;
    char crlf[] = "\r\n";

    
    if (!s->chunked_post) {
        /* non-chunked data is sent without any special encoding */
        return vcn_url_write(s->hd, buf, size);
    }

    /* silently ignore zero-size data since chunk encoding that would
     * signal EOF */
    if (size > 0) {
        /* upload data using chunked encoding */
        snprintf(temp, sizeof(temp), "%x\r\n", size);

        if ((ret = vcn_url_write(s->hd, (unsigned char*)temp, strlen(temp))) < 0 ||
            (ret = vcn_url_write(s->hd, (unsigned char*)buf, size)) < 0          ||
            (ret = vcn_url_write(s->hd, (unsigned char*)crlf, sizeof(crlf) - 1)) < 0)
            return ret;
    } else if(size == 0) {
        // eof
        snprintf(temp, sizeof(temp), "%x\r\n", size);

        if ((ret = vcn_url_write(s->hd, (unsigned char*)temp, strlen(temp))) < 0 ||
            (ret = vcn_url_write(s->hd, (unsigned char*)crlf, sizeof(crlf) - 1)) < 0)
            return ret;
    }
    return size;
}

static int httpShutDown(VCNHttpContext *s, int flags)
{
    int ret = 0;
    if (!s || !s->hd) {
        return 0;
    }
//    if(flags == AVIO_FLAG_STOP) {
//        av_waiter_wakeup(&s->waiter);
//        if(pthread_mutex_trylock(&s->mutex) == 0) {
//            if(s->hd != NULL && s->hd->prot->url_shutdown != NULL){
//                s->hd->prot->url_shutdown(s->hd,flags);
//            }
//            pthread_mutex_unlock(&s->mutex);
//        }
//        return 0;
//    }
    /* signal end of chunked encoding if used */
    if (((flags & AVIO_FLAG_WRITE) && s->chunked_post) ||
        ((flags & AVIO_FLAG_READ) && s->chunked_post && s->listen)) {
        char footer[] = "0\r\n\r\n";
        ret = vcn_url_write(s->hd, (unsigned char*)footer, sizeof(footer) - 1);
        ret = ret > 0 ? 0 : ret;
        s->end_chunked_post = 1;
    }

    return ret;
}

VCN_INTERFACE_EXPORT int httpParserClose(VCNHttpContext *s)
{
    if (!s) {
        return 0;
    }
    int ret = 0;

    inflateEnd(&s->inflate_stream);
    vcn_av_freep(&s->inflate_buffer);

    if (!s->end_chunked_post)
    /* Close the write direction by sending the end of chunked encoding. */
        ret = httpShutDown(s, s->flags);

    if (s->hd) {
        VCN_LOGI("try close hd:%p is_connected_server:%d",s->hd,s->is_connected_server);
        if (!s->is_connected_server) {
            VCN_LOGI("http call close socket:%p",s->hd);
//            sockNumRecord(s, 0);
        }
        vcn_url_closep(&s->hd);
    }
//    av_waiter_destroy(&s->waiter);
//    pthread_mutex_destroy(&s->mutex);
    vcn_av_dict_free(&s->chained_options);
    return ret;
}

static int64_t httpSeekInternal(VCNHttpContext *s, int64_t off, int whence, int force_reconnect)
{
    VCNURLContext *old_hd = s->hd;
    uint64_t old_off = s->off;
    uint8_t old_buf[BUFFER_SIZE];
    int old_buf_size, ret;
    int reconnect_index = 0,reconnect_delay_time = 5;
    int interrupt = 0;
    AVDictionary *options = NULL;

    if (whence == AVSEEK_SIZE)
        return s->filesize;
    else if(whence == AVSEEK_ADDR){
        return (int64_t)s->host_ip;
    } else if(whence == AVSEEK_SETDUR) {
        return -1;
    } else if(whence == AVSEEK_CPSIZE) {
        return s->recv_size;
    }
    else if(whence == AVSEEK_DATASIZE) {
        return s->buf_end - s->buf_ptr;
    }
    else if (!force_reconnect &&
             ((whence == SEEK_CUR && off == 0) ||
              (whence == SEEK_SET && off == s->off)))
        return s->off;
    else if ((s->filesize == UINT64_MAX && whence == SEEK_END)) {
        //av_trace(h,AVERROR(ENOSYS),"AVERROR(ENOSYS)");
        return AVERROR(ENOSYS);
    }

    if (whence == SEEK_CUR)
        off += s->off;
    else if (whence == SEEK_END)
        off += s->filesize;
    else if (whence != SEEK_SET){
        //av_trace(h,AVERROR(EINVAL),"AVERROR(EINVAL)");
        return AVERROR(EINVAL);
    }
    if (off < 0){
        //av_trace(h,AVERROR(EINVAL),"AVERROR(EINVAL)");
        return AVERROR(EINVAL);
    }
    s->off = off;

    if (s->off && s->is_streamed){
        //av_trace(h,AVERROR(ENOSYS),"AVERROR(ENOSYS)");
        return AVERROR(ENOSYS);
    }

    /* we save the old context in case the seek fails */
    old_buf_size = s->buf_end - s->buf_ptr;
    memcpy(old_buf, s->buf_ptr, old_buf_size);
    s->hd = NULL;

    /* if it fails, continue on old connection */
#if defined(HTTP_AUTO_RECONNECT)
    ret = -1;
    if (s->reconnect_count > 0) {
        reconnect_delay_time = s->reconnect_delay_max / s->reconnect_count;
        if (reconnect_delay_time <= 0) {
            reconnect_delay_time = 1;
        }
    }
    do {
        s->off = off;
        ret = httpOpenCnx(s, &options);
        if(ret >= 0 ||
           ret == AVERROR_HTTP_BAD_REQUEST ||
           ret == AVERROR_HTTP_UNAUTHORIZED ||
           ret == AVERROR_HTTP_FORBIDDEN ||
           ret == AVERROR_HTTP_NOT_FOUND ||
           ret == AVERROR_HTTP_OTHER_4XX ||
           ret == AVERROR_HTTP_SERVER_ERROR)
            break;
        reconnect_index++;
        VCN_LOGI( "reconnect:%d delay_time:%d", reconnect_index, reconnect_delay_time);

        if(s->interrupt_callback.callback!= NULL) {
#if defined(__ANDROID__) || defined(__APPLE__)
            //av_waiter_wait(&s->waiter,1000 * reconnect_index);
#else
            int64_t timeout = 1000U*1000*1;//reconnect_delay_time;
            while(timeout > 0  && !h->interrupt_callback.callback(h->interrupt_callback.opaque) ) {
                vcn_av_usleep(1000);
                timeout -= 1000;
            }
#endif
            interrupt = s->interrupt_callback.callback(s->interrupt_callback.opaque);
        } else {
            vcn_av_usleep(1000U*1000*reconnect_delay_time);
        }
        if(interrupt) {
            ret = AVERROR_EXIT;
            break;
        }
    } while( ret < 0 && s->reconnect && (s->reconnect_count  == 0 || reconnect_index < s->reconnect_count) );
    if ( ret < 0) {
        //av_trace(h,ret,"reconnect:%d delay_time:%d,fail:%d", reconnect_index, reconnect_delay_time);
        vcn_av_dict_free(&options);
        memcpy(s->buffer, old_buf, old_buf_size);
        s->buf_ptr = s->buffer;
        s->buf_end = s->buffer + old_buf_size;
        s->hd      = old_hd;
        s->off     = old_off;
        return ret;
    }
    //------
#else
    if ((ret = httpOpenCnx(s, &options)) < 0) {
        vcn_av_dict_free(&options);
        memcpy(s->buffer, old_buf, old_buf_size);
        s->buf_ptr = s->buffer;
        s->buf_end = s->buffer + old_buf_size;
        s->hd      = old_hd;
        s->off     = old_off;
        return ret;
    }
#endif
    vcn_av_dict_free(&options);
    vcn_url_close(old_hd);
    return off;
}

static int64_t httpParserSeek(VCNHttpContext *s, int64_t off, int whence)
{
    return httpSeekInternal(s, off, whence, 0);
}

VCN_INTERFACE_EXPORT int httpParserGetfileHandle(VCNHttpContext *s)
{
    if (!s || !s->hd) {
        return VCNHttpParserError::IsContextNullError;
    }
    return vcn_url_get_file_handle(s->hd);
}

VCN_INTERFACE_EXPORT int httpParserGetShortSeek(VCNHttpContext *s)
{
    if (!s || !s->hd) {
        return VCNHttpParserError::IsContextNullError;
    }
#ifdef __ANDROID__
    return vcn_url_get_short_seek(s->hd);
#endif
    return -1;
}

static bool hostnameIsIpAddress(const char *s)
{
    if (VCN_IS_EMPTY_STRING(s)) {
        return false;
    }
    
    struct in_addr  v4;
    struct in6_addr v6;
    return (inet_pton(AF_INET, s, &v4) == 1 || inet_pton(AF_INET6, s, &v6) == 1);
}

void httpNotifySockInfo(VCNHttpContext *s) {
    if (!s || !s->parserStrategy || !s->hd) {
        return;
    }
    

    if (!s->parserStrategy->getStrategyIntValue(VCNHttpParserStrategyKey::VCNHttpParserStrategyKeyIsEnableNetScheduler)) {
        return;
    }

    s->parserStrategy->onInfo(s);
}

static int httpWriteHeaderUnlimit(VCNHttpContext *s, int post, int send_expect_100,
                                const char *hoststr, const char *path, const char *method,
                                const char *authstr, const char *proxyauthstr)
                                {
    std::stringstream ss;
    char headers[HTTP_HEADERS_SIZE] = "";
    int len = 0;
    
    ss << method << " " << path << " HTTP/1.1\r\n";

    if (post && s->chunked_post) {
        ss << "Transfer-Encoding: chunked\r\n";
    }
    
    /* set default headers if needed */
    if (!hasHeader(s->headers, "\r\nUser-Agent: "))
        len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                           "User-Agent: %s\r\n", s->user_agent);
    if (!hasHeader(s->headers, "\r\nAccept: "))
        len += vcn_av_strlcpy(headers + len, "Accept: */*\r\n",
                          sizeof(headers) - len);
    // Note: we send this on purpose even when s->off is 0 when we're probing,
    // since it allows us to detect more reliably if a (non-conforming)
    // server supports seeking by analysing the reply headers.
    if (!hasHeader(s->headers, "\r\nRange: ") && !post && (s->off > 0 || s->end_off || s->seekable == -1)) {
        len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                           "Range: bytes=%" PRIu64"-", s->off);
        if (s->end_off)
            len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                               "%" PRIu64, s->end_off - 1);
        len += vcn_av_strlcpy(headers + len, "\r\n",
                          sizeof(headers) - len);
    }
    if (send_expect_100 && !hasHeader(s->headers, "\r\nExpect: "))
        len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                           "Expect: 100-continue\r\n");

    if (!hasHeader(s->headers, "\r\nConnection: ")) {
        if (s->multiple_requests)
            len += vcn_av_strlcpy(headers + len, "Connection: keep-alive\r\n",
                              sizeof(headers) - len);
        else
            len += vcn_av_strlcpy(headers + len, "Connection: close\r\n",
                              sizeof(headers) - len);
    }

    if (!hasHeader(s->headers, "\r\nHost: "))
        len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                           "Host: %s\r\n", hoststr);
    if (!hasHeader(s->headers, "\r\nContent-Length: ") && s->post_data)
        len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                           "Content-Length: %d\r\n", s->post_datalen);

    if (!hasHeader(s->headers, "\r\nContent-Type: ") && s->content_type)
        len += vcn_av_strlcatf(headers + len, sizeof(headers) - len,
                           "Content-Type: %s\r\n", s->content_type);
    
    ss << headers;
    /* set default headers if needed end */
    
    // dynamic http header
    if (!hasHeader(s->headers, "\r\nCookie: ") && s->cookies) {
        char *cookies = NULL;
        if (!getCookies(s, &cookies, path, hoststr) && cookies) {
            ss << "Cookie: " << cookies << "\r\n";
            vcn_av_free(cookies);
        }
    }
    if (!hasHeader(s->headers, "\r\nIcy-MetaData: ") && s->icy) {
        ss << "Icy-MetaData: 1\r\n";
    }
    
    if (s->parserHelper != nullptr) {
        if(s->forbidByPassCookie) {
            char* customHeader = s->parserHelper->getStringValue(VCNHttpParserHelperKey::VCNHttpParserHelperKeyIsCustomHeader, s->reserved_code, s->location);
            VCN_LOGWD("bypass cookie:%d customheader:%s", s->forbidByPassCookie, customHeader);
            if(!(VCN_IS_EMPTY_STRING(customHeader))) {
                ss << customHeader;
            }
            VCN_DELETE_STRING(customHeader)
        }

    }

    /* now add in custom headers */
    if (s->headers) {
        ss << s->headers;
    }
    
    if (s->parserNotifyer != nullptr) {
        s->parserNotifyer->notify(VCNHttpParserNotifyKey::VCNHttpParserNotifyKeyIsEventInfo, 0, headers);
    }

    if (authstr) {
        ss << authstr;
    }
    if (proxyauthstr) {
        ss << "Proxy-" << proxyauthstr;
    }
    
    ss << "\r\n";
    
    std::string httpHeader = ss.str();

    VCN_LOGW( "request: %s\n", httpHeader.c_str());

    int ret = vcn_url_write(s->hd, reinterpret_cast<const unsigned char *>(httpHeader.c_str()), (int)httpHeader.length());
    return ret;
}

VCN_INTERFACE_EXPORT int httpParserGetSocketBufferAvailableSize(VCNHttpContext *s) {
    if (!s || !s->hd) {
        VCN_LOGWD("context null get fioread value 0");
        return -1;
    }
    int fd = vcn_url_get_file_handle(s->hd);
    if(fd <= 0) {
        VCN_LOGWD("fd invalid get fioread value 0");
        return -1;
    }
    size_t size = 0;
    if(ioctl(fd, FIONREAD, &size) < 0) {
        VCN_LOGWD("get fioread fail");
        return -1;
    }
    VCN_LOGW("get fioread value:%d off:%lld endoff:%lld filesize:%lld", size, s->off, s->end_off, s->filesize);
    return size;
}
NS_VCN_END
