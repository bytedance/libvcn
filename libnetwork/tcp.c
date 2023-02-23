/*
 * TCP protocol
 * Copyright (c) 2002 Fabrice Bellard
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
#include "vcn_time.h"
#include "vcn_error.h"
#include "vcn_assert.h"
#include "vcn_avstring.h"
#include <sys/socket.h>
#include "network.h"
#include "os_support.h"
#include "vcn_utils.h"


#if HAVE_POLL_H
#include <poll.h>
#endif
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#define OFFSET(x) offsetof(VCNTCPContext, x)
#define D AV_OPT_FLAG_DECODING_PARAM
#define E AV_OPT_FLAG_ENCODING_PARAM

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif


typedef struct VCNTCPContext {
    const AVClass *class;
    int fd;
    int listen;
    int open_timeout;
    int rw_timeout;
    int listen_timeout;
    int respone_timeout;
    int64_t send_over_time;
    int recv_buffer_size;
    int send_buffer_size;
    int tcp_nodelay;
    int reuse_addr;
    int connect_parallel;
    int64_t log_handle;
    int64_t wrapper_handle;
    int64_t sumReadSize;
    char ip_addr[256];
    char *ip_list;
#if !HAVE_WINSOCK2_H
    int tcp_mss;
#endif /* !HAVE_WINSOCK2_H */
    int64_t net_id;
    int max_ip_num;
} VCNTCPContext;

static const AVOption options[] = {
    { "listen",          "Listen for incoming connections",  OFFSET(listen),         AV_OPT_TYPE_INT, { .i64 = 0 },     0,       2,       .flags = D|E },
    { "timeout",     "set timeout (in microseconds) of socket I/O operations", OFFSET(rw_timeout),     AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "open_timeout",     "set open timeout", OFFSET(open_timeout),     AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "listen_timeout",  "Connection awaiting timeout (in milliseconds)",      OFFSET(listen_timeout), AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "respone_timeout",     "set timeout of wait respone timeout", OFFSET(respone_timeout),
        AV_OPT_TYPE_INT, { .i64 = -1 },     -1, INT_MAX, .flags = D|E },
    { "send_buffer_size", "Socket send buffer size (in bytes)",                OFFSET(send_buffer_size), AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "recv_buffer_size", "Socket receive buffer size (in bytes)",             OFFSET(recv_buffer_size), AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "reuse_addr", "reuse addr flag",             OFFSET(reuse_addr), AV_OPT_TYPE_BOOL, { .i64 = 0 },             0, 1, .flags = D|E },
    { "connect_parallel", "parallel connect",             OFFSET(connect_parallel), AV_OPT_TYPE_BOOL, { .i64 = 0 },             0, 1, .flags = D|E },
    { "tcp_nodelay", "Use TCP_NODELAY to disable nagle's algorithm",           OFFSET(tcp_nodelay), AV_OPT_TYPE_BOOL, { .i64 = 0 },             0, 1, .flags = D|E },
    { "log_handle", "set log handle for log", OFFSET(log_handle), AV_OPT_TYPE_UINT64, { .i64 = 0 }, 0, UINT64_MAX, .flags = D|E },
    { "wrapper_handle", "set handle for wrapper", OFFSET(wrapper_handle), AV_OPT_TYPE_UINT64, { .i64 = 0 }, 0, UINT64_MAX, .flags = D|E },
#if !HAVE_WINSOCK2_H
    { "tcp_mss",     "Maximum segment size for outgoing TCP packets",          OFFSET(tcp_mss),     AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
#endif /* !HAVE_WINSOCK2_H */
    { "ip_list", "set ip list", OFFSET(ip_list), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "net_id", "set netid", OFFSET(net_id), AV_OPT_TYPE_INT64, { .i64 = 0 }, 0, INT64_MAX, .flags = D|E },
    { "max_ip_num", "control max ip num when connext", OFFSET(max_ip_num), AV_OPT_TYPE_INT, { .i64 = 256 }, 0, 256, .flags = D|E },
    { NULL } 
};

static const AVClass tcp_class = {
    .class_name = "tcp",
    .item_name  = vcn_av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};
const char *vcn_tcp_get_ip_addr(VCNURLContext *h);

static void vcn_customize_fd(void *ctx, int fd)
{
    VCNURLContext *h = ctx;
    VCNTCPContext *s = h->priv_data;
    /* Set the socket's send or receive buffer sizes, if specified.
     If unspecified or setting fails, system default is used. */
    if (s->recv_buffer_size > 0) {
        if (setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &s->recv_buffer_size, sizeof (s->recv_buffer_size))) {
            //ff_log_net_error(ctx, AV_LOG_WARNING, "setsockopt(SO_RCVBUF)");
        }
    }
    if (s->send_buffer_size > 0) {
        if (setsockopt (fd, SOL_SOCKET, SO_SNDBUF, &s->send_buffer_size, sizeof (s->send_buffer_size))) {
            //ff_log_net_error(ctx, AV_LOG_WARNING, "setsockopt(SO_SNDBUF)");
        }
    }
    if (s->tcp_nodelay > 0) {
        if (setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &s->tcp_nodelay, sizeof (s->tcp_nodelay))) {
            //ff_log_net_error(ctx, AV_LOG_WARNING, "setsockopt(TCP_NODELAY)");
        }
    }
#if !HAVE_WINSOCK2_H
    if (s->tcp_mss > 0) {
        if (setsockopt (fd, IPPROTO_TCP, TCP_MAXSEG, &s->tcp_mss, sizeof (s->tcp_mss))) {
            //ff_log_net_error(ctx, AV_LOG_WARNING, "setsockopt(TCP_MAXSEG)");
        }
    }
#endif /* !HAVE_WINSOCK2_H */
    if(s->net_id != 0) {
        int value = fd;
        vcn_av_log(h, AV_LOG_DEBUG, "begin bind to netid:%"PRId64" for fd:%d",s->net_id, value);
        vcn_av_net_info(h, netlog_bind_netid, s->net_id, (char*)(&value));
        vcn_av_log(h, AV_LOG_DEBUG, "end bind to netid:%"PRId64" for fd:%d",s->net_id, value);
    }
}
static int vcn_dns_parse(VCNURLContext *h,struct addrinfo **ptr,char* hostname,char* portstr) {
    struct addrinfo hints = { 0 };
    struct addrinfo *ai1 = NULL, *cur_ai1 = NULL, *cur_ai2 = NULL;
    
    
    char *ls          = NULL;
    char *param       = NULL;
    char *next_param  = NULL;
    int resolve = 0;

    

    int ret = 0;
    VCNTCPContext *s = h->priv_data;
    int maxIpNum = s->max_ip_num >= 0 ? s->max_ip_num : 0;

    vcn_av_log(h, AV_LOG_DEBUG, "max ip num is:%d",maxIpNum);

    ls = s->ip_list;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    

    if (s->listen)
        hints.ai_flags |= AI_PASSIVE;
    
    
    if (s->ip_list != NULL && strlen(s->ip_list) > 0) {
        vcn_av_log(h, AV_LOG_DEBUG, "ip list is:%s",s->ip_list);
        while ((param = vcn_av_strtok(ls, ",", &next_param))) {
            if (strlen(param) > 0) {
                ret = getaddrinfo(param, portstr, &hints, &cur_ai2);
                vcn_av_log(h, AV_LOG_TRACE, "ip is:%s getaddrret:%d",param,ret);
                if (ret == 0) {
                    resolve++;
                    if (ai1 == NULL) {
                        ai1 = cur_ai2;
                    }
                    else {
                        cur_ai1->ai_next = cur_ai2;
                    }
                    cur_ai1 = cur_ai2;
                    if(maxIpNum > 0 && resolve >= maxIpNum) {
                        vcn_av_log(h, AV_LOG_DEBUG, "max ip num:%d resolve num:%d reach max", maxIpNum, resolve);
                        break;
                    }
                }
            }
            ls = next_param;
        }
        if (ai1 != NULL) {
            *ptr = ai1;
            vcn_av_log(h, AV_LOG_DEBUG, "ip list resolve suc num:%d",resolve);
            return 0;
        }
        if (ai1 == NULL) {
            vcn_av_log(h, AV_LOG_ERROR, "use ip list get addr fail num:%d",resolve);
            return AVERROR(EIO);
        }
    }
    
    if(h->interrupt_callback.callback == NULL || hostname[0] == 0 || vcn_support_getaddrinfo_a(h) == 0 || s->wrapper_handle == 0) {
        vcn_av_net_info(h, netlog_dns_begin, vcn_av_gettime()/1000, NULL);
        if (!hostname[0])
            ret = getaddrinfo(NULL, portstr, &hints, ptr);
        else
            ret = getaddrinfo(hostname, portstr, &hints, ptr);
        
        if (ret) {
            vcn_av_error(h, h->interrupt_callback.info_callback, netlog_err_info,"%d&%d Failed to resolve hostname. %s\n",ff_neterrno(), AVERROR_GET_ADDR_INFO_FAILED, gai_strerror(ret));
            return AVERROR(EIO);
        }
        vcn_av_net_info(h, netlog_dns_end, vcn_av_gettime()/1000, NULL);
    }
    else {
        void* ctx = NULL;
        int timelost = 0;
        int timeout = s->open_timeout;
        if(timeout == -1) {
            timeout = 10*1000000;
        }
        //av_log(NULL, AV_LOG_ERROR, "timeout is:%d",s->open_timeout);
        vcn_av_net_info(h, netlog_dns_begin, vcn_av_gettime()/1000, NULL);
        ctx = vcn_getaddrinfo_a_start(h,s->wrapper_handle,hostname);
        if(ctx == NULL) {
            vcn_av_error(h, h->interrupt_callback.info_callback,  netlog_err_info, "%d&%d Failed to resolve hostname.ctx is null.", ff_neterrno(),AVERROR_GET_ADDR_INFO_START_FAILED);
            return AVERROR(EIO);
        }
        ret = 0;
        while(!h->interrupt_callback.callback(h->interrupt_callback.opaque)) {
            ret = vcn_getaddrinfo_a_result(h,ctx,hostname,1024);
            if(ret != 0) {
                break;
            }
            vcn_av_usleep (100000);
            timelost += 100000;
            if(timelost >= timeout) {
                ret = -2;
                break;
            }
        }
        if(ctx != NULL) {
            vcn_getaddrinfo_a_free(h,ctx);
            ctx  = NULL;
        }
        if(ret > 0) {
            ret = getaddrinfo(hostname, portstr, &hints, ptr);
            if (ret) {
                hostname[1023] = 0;
                vcn_av_error(h, h->interrupt_callback.info_callback,  netlog_err_info,"%d&%d Failed to resolve hostname:%s,error:%s\n" , ff_neterrno(), AVERROR_FAILED_TO_RESOLVE_HOSTNAME,hostname,gai_strerror(ret));
                return AVERROR(EIO);
            }
            if(strlen(hostname) <= sizeof(s->ip_addr)) {
                memcpy(s->ip_addr, hostname, strlen(hostname));
            }
            vcn_av_net_info(h, netlog_dns_end, vcn_av_gettime()/1000, NULL);
            vcn_av_net_info(h, netlog_single_ip, vcn_av_gettime()/1000, s->ip_addr);
            vcn_av_log(h, AV_LOG_VERBOSE, "Successfully connected to %s port:%s\n",
                   s->ip_addr, portstr);
            goto resovle_success;
        } else if(ret == -1) {
            vcn_av_error(h, h->interrupt_callback.info_callback,  netlog_err_info, "%d&%d Failed to resolve hostname.", -EFAULT,AVERROR_FAILED_TO_RESOLVE_HOSTNAME);
            return AVERROR(EIO);
            
        } else if(ret == -2) {
            vcn_av_error(h, h->interrupt_callback.info_callback,  netlog_err_info, "%d&%d Failed to resolve hostname time out.", -ETIMEDOUT, AVERROR_FAILED_TO_RESOLVE_HOSTNAME_TIMEOUT);
        } else {
            vcn_av_error(h, h->interrupt_callback.info_callback,  netlog_err_info, "%d&%d Failed to resolve hostname.", ret, AVERROR_FAILED_TO_RESOLVE_HOSTNAME);
        }
        //vcn_av_net_info(h, netlog_errorType, 1, NULL);
        return AVERROR(EIO);
    }
resovle_success:
    return 0;
}
/* return non zero if error */
static int vcn_tcp_open(VCNURLContext *h, const char *uri, int flags)
{
    struct addrinfo *ai = NULL, *cur_ai = NULL;
    int port, fd = -1;
    VCNTCPContext *s = h->priv_data;
    const char *p;
    char buf[256];
    int ret;
    char hostname[1024],proto[1024],path[1024];
    char portbuf[20];
    
    char portstr[10];
    if(s->open_timeout < 0) {
        s->open_timeout = 5000000;
    }

    vcn_av_url_split(proto, sizeof(proto), NULL, 0, hostname, sizeof(hostname),
                 &port, path, sizeof(path), uri);
    if (strcmp(proto, "tcp")){
        vcn_av_error(h, h->interrupt_callback.info_callback, netlog_err_info,"%d&%d", AVERROR(EINVAL), AVERROR_PROTO_IS_NOT_TCP);
        return AVERROR(EINVAL);
    }
    if (port <= 0 || port >= 65536) {
        vcn_av_error(h, h->interrupt_callback.info_callback, netlog_err_info,"%d&%d", AVERROR(EINVAL), AVERROR_INVALID_PORT);
        return AVERROR(EINVAL);
    }
    p = strchr(uri, '?');
    if (p) {
        if (vcn_av_find_info_tag(buf, sizeof(buf), "listen", p)) {
            char *endptr = NULL;
            s->listen = strtol(buf, &endptr, 10);
            /* assume if no digits were found it is a request to enable it */
            if (buf == endptr)
                s->listen = 1;
        }
        if (vcn_av_find_info_tag(buf, sizeof(buf), "timeout", p)) {
            s->rw_timeout = strtol(buf, NULL, 10);
        }
        if (vcn_av_find_info_tag(buf, sizeof(buf), "listen_timeout", p)) {
            s->listen_timeout = strtol(buf, NULL, 10);
        }
    }
    if (s->rw_timeout >= 0) {
        //s->open_timeout = s->rw_timeout;
        h->rw_timeout   = s->rw_timeout;
    }
    snprintf(portstr, sizeof(portstr), "%d", port);
    
    if((ret = vcn_dns_parse(h, &ai, hostname, portstr)) < 0) {
        return AVERROR(EIO);
    }
    
    cur_ai = ai;
#if HAVE_STRUCT_SOCKADDR_IN6
    // workaround for IOS9 getaddrinfo in IPv6 only network use hardcode IPv4 address can not resolve port number.
    if (cur_ai->ai_family == AF_INET6){
        struct sockaddr_in6 * sockaddr_v6 = (struct sockaddr_in6 *)cur_ai->ai_addr;
        if (!sockaddr_v6->sin6_port){
            sockaddr_v6->sin6_port = htons(port);
        }
    }
#endif
    
    if (s->listen > 0) {
        while (cur_ai && fd < 0) {
            fd = vcn_socket(cur_ai->ai_family,
                           cur_ai->ai_socktype,
                           cur_ai->ai_protocol);
            if (fd < 0) {
                ret = ff_neterrno();
                cur_ai = cur_ai->ai_next;
            }
        }
        if (fd < 0) {
            ret = ff_neterrno();
            vcn_av_error(h, h->interrupt_callback.info_callback,  netlog_err_info, "%d&%d,listen mode:%d", ret, AVERROR_FF_SOCKET_FAILED,s->listen);
            goto fail1;
        }
        vcn_customize_fd(h, fd);
    }

    if (s->listen == 2) {
        if (s->reuse_addr == 1) {
            if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,(const void *)&s->reuse_addr , sizeof(s->reuse_addr)) < 0) {
               vcn_av_log(s, AV_LOG_ERROR, "set reuse addr error");
            }
        }
        // multi-client
        if ((ret = vcn_listen(fd, cur_ai->ai_addr, cur_ai->ai_addrlen)) < 0) {
            vcn_av_error(h, h->interrupt_callback.info_callback,  netlog_err_info, "%d&%d ret:%d", ff_neterrno(), AVERROR_FF_LISTEN_FAILED,ret);
            goto fail1;
        }
    } else if (s->listen == 1) {
        // single client
        if ((ret = vcn_listen_bind(fd, cur_ai->ai_addr, cur_ai->ai_addrlen,
                                  s->listen_timeout, h)) < 0) {
            vcn_av_error(h, h->interrupt_callback.info_callback,  netlog_err_info, "%d&%d ret:%d", ff_neterrno(), AVERROR_FF_LISTEN_BIND_FAILED,ret);
            goto fail1;
        }
        // Socket descriptor already closed here. Safe to overwrite to client one.
        fd = ret;
    } else {
        cur_ai = NULL;
        ret = vcn_connect_parallel(ai, s->open_timeout / 1000, 3, h, &fd, vcn_customize_fd, h, &cur_ai);
        if (ret < 0) {
            vcn_av_error(h, h->interrupt_callback.info_callback,  netlog_err_info, "%d&%d,connect parallel fail ret:%d", ff_neterrno(),  AVERROR_FF_LISTEN_CONNECTION_FAILED,ret);
            goto fail1;
        }
        if (cur_ai != NULL) {
            getnameinfo(cur_ai->ai_addr, cur_ai->ai_addrlen,
                        s->ip_addr, sizeof(s->ip_addr), portbuf, sizeof(portbuf),
                        NI_NUMERICHOST | NI_NUMERICSERV);
            //snprintf(s->ip_addr, sizeof(s->ip_addr),"%s",hostbuf);
        }
    }
    h->is_streamed = 1;
    s->fd = fd;

    freeaddrinfo(ai);
    return 0;

fail1:
    if (fd >= 0)
        closesocket(fd);
    freeaddrinfo(ai);
    //vcn_av_net_info(h, netlog_errorType, 2, NULL);//建联阶段发生错误，则为2
    return ret;
}

static int vcn_tcp_accept(VCNURLContext *s, VCNURLContext **c)
{
    VCNTCPContext *sc = s->priv_data;
    VCNTCPContext *cc;
    int ret;
    av_assert0(sc->listen);
    if ((ret = vcn_url_alloc(c, s->filename, s->flags, &s->interrupt_callback)) < 0)
        return ret;
    cc = (*c)->priv_data;
    ret = vcn_accept(sc->fd, sc->listen_timeout, s);
    if (ret < 0) {
        int errs = ff_neterrno();
        vcn_av_log(s,AV_LOG_ERROR,"ret is:%d errno:%d",ret,errs);
//        vcn_av_error(h, h->interrupt_callback.info_callback, netlog_err_info, "%d&%d", errs, AVERROR_FF_ACCPET_FAILED);
        return errs >= 0 ? ret : errs;
    }
    cc->fd = ret;
    return 0;
}

static int vcn_tcp_read(VCNURLContext *h, uint8_t *buf, int size)
{
    VCNTCPContext *s = h->priv_data;
    int ret;

    if (!(h->flags & AVIO_FLAG_NONBLOCK)) {
        ret = vcn_network_wait_fd_timeout(h, s->fd, 0, h->rw_timeout, s->respone_timeout, &(s->send_over_time),&h->interrupt_callback);
        if (ret) {
            //av_log(s,AV_LOG_ERROR,"read timeout happen,err:%d,timeout:%"PRId64"\n",ff_neterrno(),h->rw_timeout);
            vcn_av_error(h, h->interrupt_callback.info_callback, netlog_err_info, "%d&%d ip:%s", ff_neterrno(), AVERROR_READ_NETWORK_WAIT_TIMEOUT, s->ip_addr);
			return ret;
        }
    }
    s->send_over_time = 0;
    ret = recv(s->fd, buf, size, 0);
    //if(ret == 0) {
        //av_log(s,AV_LOG_INFO,"recv data 0,err:%d,timeout:%"PRId64"\n",ff_neterrno(),h->rw_timeout);
    //}
    if (ret < 0) {
        int errs = ff_neterrno();
        //av_log(h,AV_LOG_ERROR,"recv data err,err:%d,timeout:%"PRId64"\n",errs,h->rw_timeout);
        vcn_av_error(h, h->interrupt_callback.info_callback, netlog_err_info, "%d&%d ip:%s", ff_neterrno(), AVERROR_RECEIV_DATA_FAILED, s->ip_addr);
        return errs;
    }
    if (s->sumReadSize == 0) {
        vcn_av_net_info(h, netlog_tcp_first_packet, vcn_av_gettime()/1000, NULL);
    }
    s->sumReadSize += ret;
    return ret;
}

static int vcn_tcp_write(VCNURLContext *h, const uint8_t *buf, int size)
{
    VCNTCPContext *s = h->priv_data;
    int ret;

    if (!(h->flags & AVIO_FLAG_NONBLOCK)) {
        ret = vcn_network_wait_fd_timeout(h,s->fd, 1, h->rw_timeout,s->respone_timeout, &(s->send_over_time), &h->interrupt_callback);
        if (ret) {
            //av_log(h,AV_LOG_ERROR,"write timeout happen,err:%d,timeout:%"PRId64"\n",ff_neterrno(),h->rw_timeout);
            vcn_av_error(h, h->interrupt_callback.info_callback,  netlog_err_info, "%d&%d ip:%s", ff_neterrno(), AVERROR_WRITE_NETWORK_WAIT_TIMEOUT,s->ip_addr);
            return ret;
        }
    }
    ret = send(s->fd, buf, size, MSG_NOSIGNAL);
    if (ret < 0) {
        int errs = ff_neterrno();
        /*to diff with errcode with fun of vcn_network_wait_fd_timeout*/
        if (errs == AVERROR(ETIMEDOUT)) {
            errs = AVERROR_SOCKET_SEND_TIMEOUT;
        }
        else if(errs == AVERROR(EAGAIN)) {
            errs = AVERROR_SOCKET_SEND_AGAIN;
        }
        //vcn_av_log(h,AV_LOG_ERROR,"send data err,ret:%d err:%d,timeout:%"PRId64"\n",ret,errs,h->rw_timeout);
        vcn_av_error(h, h->interrupt_callback.info_callback,  netlog_err_info, "%d&%d ip:%s", ff_neterrno(), AVERROR_SEND_DATA_FAILED, s->ip_addr);
		return errs;
    }
    return ret;
}

static int vcn_tcp_shutdown(VCNURLContext *h, int flags)
{
    VCNTCPContext *s = h->priv_data;
    int how;

    if (flags & AVIO_FLAG_WRITE && flags & AVIO_FLAG_READ) {
        how = SHUT_RDWR;
    } else if (flags & AVIO_FLAG_WRITE) {
        how = SHUT_WR;
    } else {
        how = SHUT_RD;
    }

    return shutdown(s->fd, how);
}

static int vcn_tcp_close(VCNURLContext *h)
{
    VCNTCPContext *s = h->priv_data;
    closesocket(s->fd);
    return 0;
}

static int vcn_tcp_get_file_handle(VCNURLContext *h)
{
    VCNTCPContext *s = h->priv_data;
    return s->fd;
}

const char *vcn_tcp_get_ip_addr(VCNURLContext *h)
{
    if (!h) {
        return NULL;
    }
    VCNTCPContext *s = h->priv_data;
    if(s->ip_addr[0] != '\0') {
        return s->ip_addr;
    }
    return NULL;
}

static int tcp_get_window_size(VCNURLContext *h)
{
    VCNTCPContext *s = h->priv_data;
    int avail;
    socklen_t avail_len = sizeof(avail);
    
#if HAVE_WINSOCK2_H
    /* SO_RCVBUF with winsock only reports the actual TCP window size when
     auto-tuning has been disabled via setting SO_RCVBUF */
    if (s->recv_buffer_size < 0) {
        return AVERROR(ENOSYS);
    }
#endif
    
    if (getsockopt(s->fd, SOL_SOCKET, SO_RCVBUF, &avail, &avail_len)) {
        return ff_neterrno();
    }
    return avail;
}

const URLProtocol vcn_tcp_protocol = {
    .name                = "tcp",
    .url_open            = vcn_tcp_open,
    .url_accept          = vcn_tcp_accept,
    .url_read            = vcn_tcp_read,
    .url_write           = vcn_tcp_write,
    .url_close           = vcn_tcp_close,
    .url_get_file_handle = vcn_tcp_get_file_handle,
    .url_get_short_seek  = tcp_get_window_size,
    .url_shutdown        = vcn_tcp_shutdown,
    .priv_data_size      = sizeof(VCNTCPContext),
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
    .priv_data_class     = &tcp_class,
};
