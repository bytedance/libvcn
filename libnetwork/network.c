/*
 * Copyright (c) 2007 The FFmpeg Project
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

#include <fcntl.h>
#include "network.h"
#include "libutil/vcn_assert.h"
#include "vcn_time.h"
#include "tls.h"
#include "vcn_mem.h"
#include "vcn_avstring.h"
#include <sys/ioctl.h>
#if CUSTOM_VERIFY_INTERNAL
#include "custom_verify.h"
#endif
enum av_ev_ret_code {
    AV_EV_RET_FAILED = -1,             /* 内部异常 */
    AV_EV_RET_KEEP_ON = 0,             /* 继续 */
    AV_EV_RET_SENT_OVER = 1,           /* 内核态已完成所有数据发送 */
    AV_EV_RET_RETRY_IMMEDIATELY = 2,   /* 连续丢包建议立即重试 */
    AV_EV_RET_CHANGE_FOR_BACKOFF = 3,  /* 丢包原因建议换IP重试，如果没有备用ip则重新建连 */
    AV_EV_RET_CHANGE_FOR_RTO = 4,      /* 延迟原因建议换IP重试，如果没有备用ip则重新建连 */
    AV_EV_RET_CHANGE_FOR_ER = 5,       /* 速度原因建议换IP重试，如果没有备用ip则重新建连 */
    AV_EV_RET_CHANGE_FOR_AR = 6,       /* 速度原因建议换IP重试，如果没有备用ip则重新建连 */
    AV_EV_RET_CHANGE_FOR_TR = 7,       /* 速度原因建议换IP重试，如果没有备用ip则重新建连 */
};

int vcn_support_getaddrinfo_a(VCNURLContext *h) {
    if (!h) {
        return 0;;
    }
    if(h->interrupt_callback.addr_ctx.start == NULL || h->interrupt_callback.addr_ctx.result == NULL || h->interrupt_callback.addr_ctx.free == NULL) {
        return 0;
    }
    return 1;
}

void* vcn_getaddrinfo_a_start(VCNURLContext *h,int64_t wrapper,const char* hostname) {
    if (!h || !h->interrupt_callback.addr_ctx.start) {
        return NULL;
    }
    return h->interrupt_callback.addr_ctx.start(wrapper,hostname);
}

int vcn_getaddrinfo_a_result(VCNURLContext *h,void* ctx,char* ipaddress,int size) {
    if (!h || !h->interrupt_callback.addr_ctx.result) {
        return -1;
    }
    return h->interrupt_callback.addr_ctx.result(ctx,ipaddress,size);
}

void vcn_getaddrinfo_a_free(VCNURLContext *h,void* ctx) {
    if (!h || !h->interrupt_callback.addr_ctx.free) {
        return;
    }
    h->interrupt_callback.addr_ctx.free(ctx);
}


void vcn_av_net_info_set_callback(void(*callback)(void*, int, int64_t, const char*)) {
    vcn_av_net_info_callback = callback;
}
__attribute__((visibility ("default"))) void set_vcn_custom_verify_callback(int (*callback)(void*, void*, const char*, int)) {
    vcn_custom_verify_callback = callback;
}
__attribute__((visibility ("default"))) int is_has_vcn_custom_verify_callback() {
    return vcn_custom_verify_callback != NULL;
}
int do_vcn_custom_verify_callback(void* context, void* ssl, const char* host, int port) {
    if (vcn_custom_verify_callback != NULL) {
        return vcn_custom_verify_callback(context, ssl, host, port);
    }
    vcn_av_net_info(context, netlog_verify_result, custom_callback_null, NULL);
    return 0;
}
void vcn_av_net_info(VCNURLContext *h, enum net_type type, int64_t code, const char* info) {
    if (!h || !h->interrupt_callback.info_callback) {
        return;
    }
    h->interrupt_callback.info_callback(h, type, code, info);
}
void vcn_av_net_info_extern_internal(void *avcl, int level, const char* file, const char* function, int line, const char *fmt, ...) {
    const int size = 512;
    char logbuffer[512];
    char retbuf[512];

    if(level > vcn_av_getloglevel())
        return;
    va_list vl;
    va_start(vl, fmt);
    vsnprintf(logbuffer, size, fmt, vl);
    va_end(vl);
       
    snprintf(retbuf, size, "<%s,%s,%d>%s\n", file, function, line, logbuffer);
    if( vcn_av_net_info_callback != NULL ) {
        vcn_av_net_info_callback(avcl, -1, vcn_av_gettime()/1000/1000, retbuf);
    }
}



void ev_create(VCNURLContext *h,int fd,int rtt){
    if (!h || !h->interrupt_callback.connect_ctx.create) {
        return;
    }
    h->interrupt_callback.connect_ctx.create(h,fd,rtt);
}
void ev_destory(VCNURLContext *h){
   if (!h || !h->interrupt_callback.connect_ctx.destory) {
        return;
    }
    h->interrupt_callback.connect_ctx.destory(h);
}
int ev_status(VCNURLContext *h){
    if (!h || !h->interrupt_callback.connect_ctx.status) {
        return -1;
    }
    return h->interrupt_callback.connect_ctx.status(h);
}
void ev_reset(VCNURLContext *h){
    if (!h || !h->interrupt_callback.connect_ctx.reset) {
        return;
    }
    h->interrupt_callback.connect_ctx.reset(h);
}
int vcn_tls_init(void)
{
#if CONFIG_TLS_OPENSSL_PROTOCOL
    int ret;
    if ((ret = vcn_openssl_init()) < 0)
        return ret;
#endif
#if CONFIG_TLS_GNUTLS_PROTOCOL
    vcn_gnutls_init();
#endif
    
#if CUSTOM_VERIFY_INTERNAL
    set_vcn_custom_verify_callback(vcn_internal_custom_verify);
#endif
    return 0;
}

void vcn_tls_deinit(void)
{
#if CONFIG_TLS_OPENSSL_PROTOCOL
    vcn_openssl_deinit();
#endif
#if CONFIG_TLS_GNUTLS_PROTOCOL
    vcn_gnutls_deinit();
#endif
}

int vcn_network_inited_globally;

int vcn_network_init(void)
{
#if HAVE_WINSOCK2_H
    WSADATA wsaData;
#endif
    vcn_tls_init();
    if (!vcn_network_inited_globally) {
//        vcn_av_log(NULL, AV_LOG_INFO, "Using network protocols without global "
//                                     "network initialization. Please use "
//                                     "avformat_network_init(), this will "
//                                     "become mandatory later.\n");
    }
#if HAVE_WINSOCK2_H
    if (WSAStartup(MAKEWORD(1,1), &wsaData))
        return 0;
#endif
    return 1;
}

int vcn_network_wait_fd(int fd, int write)
{
    int ev = write ? POLLOUT : POLLIN;
    struct pollfd p = { .fd = fd, .events = ev, .revents = 0 };
    int ret;
    ret = poll(&p, 1, POLLING_TIME);
    return ret < 0 ? ff_neterrno() : p.revents & (ev | POLLERR | POLLHUP) ? 0 : AVERROR(EAGAIN);
}

int vcn_network_wait_fd_timeout(VCNURLContext *h, int fd, int write, int64_t timeout, int64_t respone_timeout, int64_t *send_over_time,AVNetIOInterruptCB *int_cb)
{
    int ret;
    int64_t wait_start = 0;
    while (1) {
        if (vcn_ff_check_interrupt(int_cb))
            return AVERROR_EXIT;
        int status = ev_status(h);
        switch (status) {
            case AV_EV_RET_SENT_OVER:
                //上行数据发完了，等待下行数据的时候的超时
                if(!write && respone_timeout > 0) {
                    if (*send_over_time == 0) {
                        *send_over_time = vcn_av_gettime();
                        vcn_av_log(h, AV_LOG_INFO,"sendTime:%lld",send_over_time);
                    }else if (vcn_av_gettime() - *send_over_time > respone_timeout){
                        vcn_av_log(h, AV_LOG_INFO,"sendTime:%lld,vcn_av_gettime():%lld,responeTimeout:%lld",send_over_time,vcn_av_gettime(),respone_timeout);
                        return AVERROR_RESPONE_TIMEOUT;
                    }
                }
                break;
            case AV_EV_RET_RETRY_IMMEDIATELY:
                return AVERROR_EV_RETRY_IMMEDIATELY;
            case AV_EV_RET_CHANGE_FOR_BACKOFF:
                return AVERROR_EV_CHANGE_FOR_BACKOFF;
            case AV_EV_RET_CHANGE_FOR_RTO:
                return AVERROR_EV_CHANGE_FOR_RTO;
            case AV_EV_RET_CHANGE_FOR_ER:
                return AVERROR_EV_CHANGE_FOR_ER;
            case AV_EV_RET_CHANGE_FOR_AR:
                return AVERROR_EV_CHANGE_FOR_AR;
            case AV_EV_RET_CHANGE_FOR_TR:
                return AVERROR_EV_CHANGE_FOR_TR;
            default:
                break;
        }
        
        ret = vcn_network_wait_fd(fd, write);
        if (ret != AVERROR(EAGAIN))
            return ret;
        if (timeout > 0) {
            if (!wait_start)
                wait_start = vcn_av_gettime_relative();
            else if (vcn_av_gettime_relative() - wait_start > timeout)
                return AVERROR(ETIMEDOUT);
        }
    }
}

void vcn_network_close(void)
{
#if HAVE_WINSOCK2_H
    WSACleanup();
#endif
}

#if HAVE_WINSOCK2_H
int ff_neterrno(void)
{
    int err = WSAGetLastError();
    switch (err) {
    case WSAEWOULDBLOCK:
        return AVERROR(EAGAIN);
    case WSAEINTR:
        return AVERROR(EINTR);
    case WSAEPROTONOSUPPORT:
        return AVERROR(EPROTONOSUPPORT);
    case WSAETIMEDOUT:
        return AVERROR(ETIMEDOUT);
    case WSAECONNREFUSED:
        return AVERROR(ECONNREFUSED);
    case WSAEINPROGRESS:
        return AVERROR(EINPROGRESS);
    }
    return -err;
}
#endif

int vcn_is_multicast_address(struct sockaddr *addr)
{
    if (addr->sa_family == AF_INET) {
        return IN_MULTICAST(ntohl(((struct sockaddr_in *)addr)->sin_addr.s_addr));
    }
#if HAVE_STRUCT_SOCKADDR_IN6
    if (addr->sa_family == AF_INET6) {
        return IN6_IS_ADDR_MULTICAST(&((struct sockaddr_in6 *)addr)->sin6_addr);
    }
#endif

    return 0;
}

static int vcn_poll_interrupt(struct pollfd *p, nfds_t nfds, int timeout,
                             AVNetIOInterruptCB *cb)
{
    int runs = timeout / POLLING_TIME;
    int ret = 0;

    do {
        if (vcn_ff_check_interrupt(cb))
            return AVERROR_EXIT;
        ret = poll(p, nfds, POLLING_TIME);
        if (ret != 0)
            break;
    } while (timeout <= 0 || runs-- > 0);

    if (!ret)
        return AVERROR(ETIMEDOUT);
    if (ret < 0)
        return AVERROR(errno);
    return ret;
}

int vcn_socket(int af, int type, int proto)
{
    int fd;

#ifdef SOCK_CLOEXEC
    fd = socket(af, type | SOCK_CLOEXEC, proto);
    if (fd == -1 && errno == EINVAL)
#endif
    {
        fd = socket(af, type, proto);
#if HAVE_FCNTL
        if (fd != -1) {
            if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
                vcn_av_log(NULL, AV_LOG_DEBUG, "Failed to set close on exec\n");
            }
        }
#endif
    }
#ifdef SO_NOSIGPIPE
    if (fd != -1)
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &(int){1}, sizeof(int));
#endif
    return fd;
}

int vcn_listen(int fd, const struct sockaddr *addr,
              socklen_t addrlen)
{
    int ret;
    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
        vcn_av_log(NULL, AV_LOG_WARNING, "setsockopt(SO_REUSEADDR) failed\n");
    }
    ret = bind(fd, addr, addrlen);
    if (ret)
        return ff_neterrno();

    ret = listen(fd, 1);
    if (ret)
        return ff_neterrno();
    return ret;
}

int vcn_accept(int fd, int timeout, VCNURLContext *h)
{
    int ret;
    struct pollfd lp = { fd, POLLIN, 0 };

    ret = vcn_poll_interrupt(&lp, 1, timeout, &h->interrupt_callback);
    if (ret < 0)
        return ret;

    ret = accept(fd, NULL, NULL);
    if (ret < 0)
        return ff_neterrno();
    if (ff_socket_nonblock(ret, 1) < 0) {
        vcn_av_log(NULL, AV_LOG_DEBUG, "ff_socket_nonblock failed\n");
    }

    return ret;
}

int vcn_listen_bind(int fd, const struct sockaddr *addr,
                   socklen_t addrlen, int timeout, VCNURLContext *h)
{
    int ret;
    if ((ret = vcn_listen(fd, addr, addrlen)) < 0)
        return ret;
    if ((ret = vcn_accept(fd, timeout, h)) < 0)
        return ret;
    //closesocket(fd);
    close(fd);
    return ret;
}

int vcn_listen_connect(int fd, const struct sockaddr *addr,
                      socklen_t addrlen, int timeout, VCNURLContext *h,
                      int will_try_next)
{
    struct pollfd p = {fd, POLLOUT, 0};
    int ret;
    socklen_t optlen;

    if (ff_socket_nonblock(fd, 1) < 0) {
        vcn_av_log(NULL, AV_LOG_DEBUG, "ff_socket_nonblock failed\n");
    }
	vcn_av_net_info(h, netlog_handshake_begin, vcn_av_gettime()/1000, NULL);
    ev_create(h, fd, -1);
    while ((ret = connect(fd, addr, addrlen))) {
        ret = ff_neterrno();
        switch (ret) {
        case AVERROR(EINTR):
            if (vcn_ff_check_interrupt(&h->interrupt_callback))
                return AVERROR_EXIT;
            continue;
        case AVERROR(EINPROGRESS):
        case AVERROR(EAGAIN):
            ret = vcn_poll_interrupt(&p, 1, timeout, &h->interrupt_callback);
            if (ret < 0)
                return ret;
            optlen = sizeof(ret);
            if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &ret, &optlen))
                ret = AVUNERROR(ff_neterrno());
            if (ret != 0) {
                char errbuf[100];
                ret = AVERROR(ret);
                vcn_av_strerror(ret, errbuf, sizeof(errbuf));
                if (will_try_next) {
                    vcn_av_log(h, AV_LOG_WARNING,
                           "Connection to %s failed (%s), trying next address\n",
                           h->filename, errbuf);
                }
                else {
                    vcn_av_log(h, AV_LOG_ERROR, "Connection to %s failed: %s\n",
                           h->filename, errbuf);
                }
            }
        default:
                if (ret >= 0) {
                     vcn_av_net_info(h, netlog_handshake_end, vcn_av_gettime()/1000, NULL);
                }
            return ret;
        }
    }
    vcn_av_net_info(h, netlog_handshake_end, vcn_av_gettime()/1000, NULL);
    return ret;
}

static int match_host_pattern(const char *pattern, const char *hostname)
{
    int len_p, len_h;
    if (!strcmp(pattern, "*"))
        return 1;
    // Skip a possible *. at the start of the pattern
    if (pattern[0] == '*')
        pattern++;
    if (pattern[0] == '.')
        pattern++;
    len_p = strlen(pattern);
    len_h = strlen(hostname);
    if (len_p > len_h)
        return 0;
    // Simply check if the end of hostname is equal to 'pattern'
    if (!strcmp(pattern, &hostname[len_h - len_p])) {
        if (len_h == len_p)
            return 1; // Exact match
        if (hostname[len_h - len_p - 1] == '.')
            return 1; // The matched substring is a domain and not just a substring of a domain
    }
    return 0;
}

int vcn_http_match_no_proxy(const char *no_proxy, const char *hostname)
{
    char *buf, *start;
    int ret = 0;
    if (!no_proxy)
        return 0;
    if (!hostname)
        return 0;
    buf = vcn_av_strdup(no_proxy);
    if (!buf)
        return 0;
    start = buf;
    while (start) {
        char *sep, *next = NULL;
        start += strspn(start, " ,");
        sep = start + strcspn(start, " ,");
        if (*sep) {
            next = sep + 1;
            *sep = '\0';
        }
        if (match_host_pattern(start, hostname)) {
            ret = 1;
            break;
        }
        start = next;
    }
    vcn_av_free(buf);
    return ret;
}

static void vcn_print_address_list(void *ctx, const struct addrinfo *addr,
                               const char *title)
{
    char hostbuf[100], portbuf[20];
    char hostList[1024]="";
    int len = 0;
    vcn_av_log(ctx, AV_LOG_DEBUG, "%s:\n", title);
    while (addr) {
        getnameinfo(addr->ai_addr, addr->ai_addrlen,
                    hostbuf, sizeof(hostbuf), portbuf, sizeof(portbuf),
                    NI_NUMERICHOST | NI_NUMERICSERV);
        vcn_av_log(ctx, AV_LOG_DEBUG, "Address %s port %s\n", hostbuf, portbuf);
        addr = addr->ai_next;
        if (sizeof(hostList) > len) {
            len += vcn_av_strlcatf(hostList + len, sizeof(hostList) - len,
                               "%s,", hostbuf);
        }
    }
    vcn_av_net_info(ctx, netlog_ip_list, 0, hostList);
}

struct VCNConnectionAttempt {
    int fd;
    int64_t deadline_us;
    struct addrinfo *addr;
};

static void vcn_interleave_addrinfo(struct addrinfo *base)
{
    struct addrinfo **next = &base->ai_next;
    while (*next) {
        struct addrinfo *cur = *next;
        // Iterate forward until we find an entry of a different family.
        if (cur->ai_family == base->ai_family) {
            next = &cur->ai_next;
            continue;
        }
        if (cur == base->ai_next) {
            // If the first one following base is of a different family, just
            // move base forward one step and continue.
            base = cur;
            next = &base->ai_next;
            continue;
        }
        // Unchain cur from the rest of the list from its current spot.
        *next = cur->ai_next;
        // Hook in cur directly after base.
        cur->ai_next = base->ai_next;
        base->ai_next = cur;
        // Restart with a new base. We know that before moving the cur element,
        // everything between the previous base and cur had the same family,
        // different from cur->ai_family. Therefore, we can keep next pointing
        // where it was, and continue from there with base at the one after
        // cur.
        base = cur->ai_next;
    }
}


// Returns < 0 on error, 0 on successfully started connection attempt,
// > 0 for a connection that succeeded already.
static int vcn_start_connect_attempt(struct VCNConnectionAttempt *attempt,
                                 struct addrinfo **ptr, int timeout_ms,
                                 VCNURLContext *h,
                                 void (*customize_fd)(void *, int), void *customize_ctx)
{
    struct addrinfo *ai = *ptr;
    int ret;
    
    *ptr = ai->ai_next;
    
    attempt->fd = vcn_socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

    if (attempt->fd < 0)
        return ff_neterrno();
    attempt->deadline_us = vcn_av_gettime_relative() + timeout_ms * 1000;
    attempt->addr = ai;
    
    ff_socket_nonblock(attempt->fd, 1);
    
    if (customize_fd)
        customize_fd(customize_ctx, attempt->fd);
    
    while ((ret = connect(attempt->fd, ai->ai_addr, ai->ai_addrlen))) {
        ret = ff_neterrno();
        switch (ret) {
            case AVERROR(EINTR):
                if (vcn_ff_check_interrupt(&h->interrupt_callback)) {
                    closesocket(attempt->fd);
                    attempt->fd = -1;
                    return AVERROR_EXIT;
                }
                continue;
            case AVERROR(EINPROGRESS):
            case AVERROR(EAGAIN):
                return 0;
            default:
                closesocket(attempt->fd);
                attempt->fd = -1;
                return ret;
        }
    }
    return 1;
}

// Try a new connection to another address after 200 ms, as suggested in
// RFC 8305 (or sooner if an earlier attempt fails).
#define NEXT_ATTEMPT_DELAY_MS 200

int vcn_connect_parallel(struct addrinfo *addrs, int timeout_ms_per_address,
                        int parallel, VCNURLContext *h, int *fd,
                        void (*customize_fd)(void *, int), void *customize_ctx, struct addrinfo **used_addrs)
{
    struct VCNConnectionAttempt attempts[3];
    struct pollfd pfd[3];
    int nb_attempts = 0, i, j;
    int64_t next_attempt_us = vcn_av_gettime_relative(), next_deadline_us;
    int last_err = AVERROR(EIO);
    socklen_t optlen;
    char errbuf[100], hostbuf[100], portbuf[20];
    
    if (parallel > FF_ARRAY_ELEMS(attempts))
        parallel = FF_ARRAY_ELEMS(attempts);
    vcn_av_log(h, AV_LOG_ERROR, "start parallel connect");
    vcn_av_net_info(h, -1, vcn_av_gettime()/1000, "start parallel connect");
    vcn_print_address_list(h, addrs, "Original list of addresses");
    // This mutates the list, but the head of the list is still the same
    // element, so the caller, who owns the list, doesn't need to get
    // an updated pointer.
    vcn_interleave_addrinfo(addrs);
    vcn_print_address_list(h, addrs, "Interleaved list of addresses");
    
    vcn_av_net_info(h, netlog_handshake_begin, vcn_av_gettime()/1000, NULL);
    
    while (nb_attempts > 0 || addrs) {
        // Start a new connection attempt, if possible.
        if (nb_attempts < parallel && addrs) {
            getnameinfo(addrs->ai_addr, addrs->ai_addrlen,
                        hostbuf, sizeof(hostbuf), portbuf, sizeof(portbuf),
                        NI_NUMERICHOST | NI_NUMERICSERV);
            vcn_av_log(h, AV_LOG_VERBOSE, "Starting connection attempt to %s port %s\n",
                   hostbuf, portbuf);
            last_err = vcn_start_connect_attempt(&attempts[nb_attempts], &addrs,
                                             timeout_ms_per_address, h,
                                             customize_fd, customize_ctx);
            if (last_err < 0) {
                vcn_av_strerror(last_err, errbuf, sizeof(errbuf));
                vcn_av_log(h, AV_LOG_VERBOSE, "Connected attempt failed: %s\n",
                       errbuf);
                continue;
            }
            if (last_err > 0) {
                for (i = 0; i < nb_attempts; i++)
                    closesocket(attempts[i].fd);
                *fd = attempts[nb_attempts].fd;
                return 0;
            }
            pfd[nb_attempts].fd = attempts[nb_attempts].fd;
            pfd[nb_attempts].events = POLLOUT;
            next_attempt_us = vcn_av_gettime_relative() + NEXT_ATTEMPT_DELAY_MS * 1000;
            nb_attempts++;
        }
        
        av_assert0(nb_attempts > 0);
        // The connection attempts are sorted from oldest to newest, so the
        // first one will have the earliest deadline.
        next_deadline_us = attempts[0].deadline_us;
        // If we can start another attempt in parallel, wait until that time.
        if (nb_attempts < parallel && addrs)
            next_deadline_us = FFMIN(next_deadline_us, next_attempt_us);
        last_err = vcn_poll_interrupt(pfd, nb_attempts,
                                     (next_deadline_us - vcn_av_gettime_relative())/1000,
                                     &h->interrupt_callback);
        if (last_err < 0 && last_err != AVERROR(ETIMEDOUT))
            break;
        
        // Check the status from the poll output.
        for (i = 0; i < nb_attempts; i++) {
            last_err = 0;
            if (pfd[i].revents) {
                // Some sort of action for this socket, check its status (either
                // a successful connection or an error).
                optlen = sizeof(last_err);
                if (getsockopt(attempts[i].fd, SOL_SOCKET, SO_ERROR, &last_err, &optlen))
                    last_err = ff_neterrno();
                else if (last_err != 0)
                    last_err = AVERROR(last_err);
                if (last_err == 0) {
                    // Everything is ok, we seem to have a successful
                    // connection. Close other sockets and return this one.
                    for (j = 0; j < nb_attempts; j++)
                        if (j != i)
                            closesocket(attempts[j].fd);
                    *fd = attempts[i].fd;
                    getnameinfo(attempts[i].addr->ai_addr, attempts[i].addr->ai_addrlen,
                                hostbuf, sizeof(hostbuf), portbuf, sizeof(portbuf),
                                NI_NUMERICHOST | NI_NUMERICSERV);
                    *used_addrs = attempts[i].addr;
                    vcn_av_net_info(h, netlog_handshake_end, vcn_av_gettime()/1000, hostbuf);
                    vcn_av_log(h, AV_LOG_VERBOSE, "Successfully connected to %s port %s\n",
                           hostbuf, portbuf);
                    return 0;
                }
            }
            if (attempts[i].deadline_us < vcn_av_gettime_relative() && !last_err)
                last_err = AVERROR(ETIMEDOUT);
            if (!last_err)
                continue;
            // Error (or timeout) for this socket; close the socket and remove
            // it from the attempts/pfd arrays, to let a new attempt start
            // directly.
            getnameinfo(attempts[i].addr->ai_addr, attempts[i].addr->ai_addrlen,
                        hostbuf, sizeof(hostbuf), portbuf, sizeof(portbuf),
                        NI_NUMERICHOST | NI_NUMERICSERV);
            vcn_av_strerror(last_err, errbuf, sizeof(errbuf));
            vcn_av_log(h, AV_LOG_VERBOSE, "Connection attempt to %s port %s "
                   "failed: %s\n", hostbuf, portbuf, errbuf);
            closesocket(attempts[i].fd);
            memmove(&attempts[i], &attempts[i + 1],
                    (nb_attempts - i - 1) * sizeof(*attempts));
            memmove(&pfd[i], &pfd[i + 1],
                    (nb_attempts - i - 1) * sizeof(*pfd));
            i--;
            nb_attempts--;
        }
    }
    for (i = 0; i < nb_attempts; i++)
        closesocket(attempts[i].fd);
    if (last_err >= 0)
        last_err = AVERROR(ECONNREFUSED);
    if (last_err != AVERROR_EXIT) {
        vcn_av_strerror(last_err, errbuf, sizeof(errbuf));
        vcn_av_log(h, AV_LOG_ERROR, "Connection to %s failed: %s\n",
               h->filename, errbuf);
    }
    return last_err;
}
