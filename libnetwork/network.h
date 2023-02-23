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

#ifndef AVFORMAT_NETWORK_H
#define AVFORMAT_NETWORK_H

#include <errno.h>
#include <stdint.h>

#include "config.h"
#include "libvcn/vcn_error.h"
#include "os_support.h"
#include "vcn_avio.h"
#include "vcn_url.h"

#include <stdlib.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#if HAVE_WINSOCK2_H
#include <winsock2.h>
#include <ws2tcpip.h>

#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT WSAEPROTONOSUPPORT
#endif
#ifndef ETIMEDOUT
#define ETIMEDOUT       WSAETIMEDOUT
#endif
#ifndef ECONNREFUSED
#define ECONNREFUSED    WSAECONNREFUSED
#endif
#ifndef EINPROGRESS
#define EINPROGRESS     WSAEINPROGRESS
#endif

#define getsockopt(a, b, c, d, e) getsockopt(a, b, c, (char*) d, e)
#define setsockopt(a, b, c, d, e) setsockopt(a, b, c, (const char*) d, e)

int ff_neterrno(void);
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>

#define ff_neterrno() AVERROR(errno)
#endif /* HAVE_WINSOCK2_H */

#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#if HAVE_POLL_H
#include <poll.h>
#endif

int ff_socket_nonblock(int socket, int enable);

extern int vcn_network_inited_globally;
void vcn_network_close(void);

int vcn_tls_init(void);
void vcn_tls_deinit(void);



int vcn_network_wait_fd(int fd, int write);

/**
 * This works similarly to vcn_network_wait_fd, but waits up to 'timeout' microseconds
 * Uses vcn_network_wait_fd in a loop
 *
 * @fd Socket descriptor
 * @write Set 1 to wait for socket able to be read, 0 to be written
 * @timeout Timeout interval, in microseconds. Actual precision is 100000 mcs, due to vcn_network_wait_fd usage
 * @param int_cb Interrupt callback, is checked before each vcn_network_wait_fd call
 * @return 0 if data can be read/written, AVERROR(ETIMEDOUT) if timeout expired, or negative error code
 */
int vcn_network_wait_fd_timeout(VCNURLContext *h, int fd, int write, int64_t timeout , int64_t respone_timeout,int64_t *send_over_Time, AVNetIOInterruptCB *int_cb);

int ff_inet_aton (const char * str, struct in_addr * add);

#if !HAVE_STRUCT_SOCKADDR_STORAGE
struct sockaddr_storage {
#if HAVE_STRUCT_SOCKADDR_SA_LEN
    uint8_t ss_len;
    uint8_t ss_family;
#else
    uint16_t ss_family;
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
    char ss_pad1[6];
    int64_t ss_align;
    char ss_pad2[112];
};
#endif /* !HAVE_STRUCT_SOCKADDR_STORAGE */

typedef union sockaddr_union {
    struct sockaddr_storage storage;
    struct sockaddr_in in;
#if HAVE_STRUCT_SOCKADDR_IN6
    struct sockaddr_in6 in6;
#endif
} sockaddr_union;

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#if !HAVE_STRUCT_ADDRINFO
struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    int ai_addrlen;
    struct sockaddr *ai_addr;
    char *ai_canonname;
    struct addrinfo *ai_next;
};
#endif /* !HAVE_STRUCT_ADDRINFO */

/* getaddrinfo constants */
#ifndef EAI_AGAIN
#define EAI_AGAIN 2
#endif
#ifndef EAI_BADFLAGS
#define EAI_BADFLAGS 3
#endif
#ifndef EAI_FAIL
#define EAI_FAIL 4
#endif
#ifndef EAI_FAMILY
#define EAI_FAMILY 5
#endif
#ifndef EAI_MEMORY
#define EAI_MEMORY 6
#endif
#ifndef EAI_NODATA
#define EAI_NODATA 7
#endif
#ifndef EAI_NONAME
#define EAI_NONAME 8
#endif
#ifndef EAI_SERVICE
#define EAI_SERVICE 9
#endif
#ifndef EAI_SOCKTYPE
#define EAI_SOCKTYPE 10
#endif

#ifndef AI_PASSIVE
#define AI_PASSIVE 1
#endif

#ifndef AI_CANONNAME
#define AI_CANONNAME 2
#endif

#ifndef AI_NUMERICHOST
#define AI_NUMERICHOST 4
#endif

#ifndef NI_NOFQDN
#define NI_NOFQDN 1
#endif

#ifndef NI_NUMERICHOST
#define NI_NUMERICHOST 2
#endif

#ifndef NI_NAMERQD
#define NI_NAMERQD 4
#endif

#ifndef NI_NUMERICSERV
#define NI_NUMERICSERV 8
#endif

#ifndef NI_DGRAM
#define NI_DGRAM 16
#endif

#if !HAVE_GETADDRINFO
int ff_getaddrinfo(const char *node, const char *service,
                   const struct addrinfo *hints, struct addrinfo **res);
void ff_freeaddrinfo(struct addrinfo *res);
int ff_getnameinfo(const struct sockaddr *sa, int salen,
                   char *host, int hostlen,
                   char *serv, int servlen, int flags);
#define getaddrinfo ff_getaddrinfo
#define freeaddrinfo ff_freeaddrinfo
#define getnameinfo ff_getnameinfo
#endif /* !HAVE_GETADDRINFO */

#if !HAVE_GETADDRINFO || HAVE_WINSOCK2_H
const char *ff_gai_strerror(int ecode);
#undef gai_strerror
#define gai_strerror ff_gai_strerror
#endif /* !HAVE_GETADDRINFO || HAVE_WINSOCK2_H */

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7f000001
#endif

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN INET_ADDRSTRLEN
#endif

#ifndef IN_MULTICAST
#define IN_MULTICAST(a) ((((uint32_t)(a)) & 0xf0000000) == 0xe0000000)
#endif
#ifndef IN6_IS_ADDR_MULTICAST
#define IN6_IS_ADDR_MULTICAST(a) (((uint8_t *) (a))[0] == 0xff)
#endif
static void (*vcn_av_net_info_callback)(void*, int, int64_t, const char*) = NULL;
static int (*vcn_custom_verify_callback)(void*, void*, const char*, int) = NULL;
int do_vcn_custom_verify_callback(void* context, void* ssl, const char* host, int port);



int vcn_support_getaddrinfo_a(VCNURLContext* h);

void vcn_getaddrinfo_a_init(getaddrinfo_a_start getinfo, getaddrinfo_a_result result,getaddrinfo_a_free end,save_host_addr save_ip);

void* vcn_getaddrinfo_a_start(VCNURLContext *h,int64_t wrapper,const char* hostname);

int vcn_getaddrinfo_a_result(VCNURLContext *h,void* ctx,char* ipaddress,int size);

void vcn_getaddrinfo_a_free(VCNURLContext *h,void* ctx);


void ev_create(VCNURLContext *h,int fd,int rtt);
void ev_destory(VCNURLContext *h);
int ev_status(VCNURLContext *h);
void ev_reset(VCNURLContext *h);

int vcn_is_multicast_address(struct sockaddr *addr);



__attribute__((visibility ("default"))) void vcn_av_net_info(VCNURLContext *h, enum net_type type, int64_t code, const char* info);

#define vcn_av_net_info_extern(avcl, level, ...) vcn_av_net_info_extern_internal(avcl, level, __FILENAME__, __FUNCTION__, __LINE__,__VA_ARGS__)

void vcn_av_net_info_extern_internal(void *avcl, int level, const char* file, const char* function, int line, const char *fmt, ...);


#define POLLING_TIME 100 /// Time in milliseconds between interrupt check

/**
 * Bind to a file descriptor and poll for a connection.
 *
 * @param fd      First argument of bind().
 * @param addr    Second argument of bind().
 * @param addrlen Third argument of bind().
 * @param timeout Polling timeout in milliseconds.
 * @param h       VCNURLContext providing interrupt check
 *                callback and logging context.
 * @return        A non-blocking file descriptor on success
 *                or an AVERROR on failure.
 */
int vcn_listen_bind(int fd, const struct sockaddr *addr,
                   socklen_t addrlen, int timeout,
                   VCNURLContext *h);

/**
 * Bind to a file descriptor to an address without accepting connections.
 * @param fd      First argument of bind().
 * @param addr    Second argument of bind().
 * @param addrlen Third argument of bind().
 * @return        0 on success or an AVERROR on failure.
 */
int vcn_listen(int fd, const struct sockaddr *addr, socklen_t addrlen);

/**
 * Poll for a single connection on the passed file descriptor.
 * @param fd      The listening socket file descriptor.
 * @param timeout Polling timeout in milliseconds.
 * @param h       VCNURLContext providing interrupt check
 *                callback and logging context.
 * @return        A non-blocking file descriptor on success
 *                or an AVERROR on failure.
 */
int vcn_accept(int fd, int timeout, VCNURLContext *h);

/**
 * Connect to a file descriptor and poll for result.
 *
 * @param fd       First argument of connect(),
 *                 will be set as non-blocking.
 * @param addr     Second argument of connect().
 * @param addrlen  Third argument of connect().
 * @param timeout  Polling timeout in milliseconds.
 * @param h        VCNURLContext providing interrupt check
 *                 callback and logging context.
 * @param will_try_next Whether the caller will try to connect to another
 *                 address for the same host name, affecting the form of
 *                 logged errors.
 * @return         0 on success, AVERROR on failure.
 */
int vcn_listen_connect(int fd, const struct sockaddr *addr,
                      socklen_t addrlen, int timeout,
                      VCNURLContext *h, int will_try_next);

int vcn_http_match_no_proxy(const char *no_proxy, const char *hostname);

int vcn_socket(int domain, int type, int protocol);
int vcn_connect_parallel(struct addrinfo *addrs, int timeout_ms_per_address,
                        int parallel, VCNURLContext *h, int *fd,
                        void (*customize_fd)(void *, int), void *customize_ctx, struct addrinfo **used_addrs);

#endif /* AVFORMAT_NETWORK_H */
