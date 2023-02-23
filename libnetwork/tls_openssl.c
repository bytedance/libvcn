/*
 * TLS/SSL Protocol
 * Copyright (c) 2011 Martin Storsjo
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

//#include "avformat.h"
//#include "internal.h"
#include "network.h"
#include "os_support.h"
#include "vcn_url.h"
#include "vcn_time.h"
#include "tls.h"
#include "vcn_avstring.h"
#include "vcn_avutil.h"
#include "vcn_opt.h"
#include "vcn_utils.h"
#include "libutil/thread.h"
#include "vcn_mem.h"

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static int openssl_init;
static int ssl_data_index;
enum ssl_verify_result_t verify_custom_callbak(SSL *ssl, uint8_t *out_alert);
static int new_session_callback(SSL* ssl, SSL_SESSION* session);
static SSL_SESSION* get_session(VCNURLContext *h);
typedef struct VCNTLSContext {
    const AVClass *class;
    VCNTLSShared tls_shared;
    SSL_CTX *ctx;
    SSL *ssl;
    int session_reuse;
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    BIO_METHOD* vcn_url_bio_method;
#endif
    int max_tls_version;
    int session_timeout;//seconds
    int tls_false_start;
	int enable_early_data;
} VCNTLSContext;

#if HAVE_THREADS
#include <openssl/crypto.h>
pthread_mutex_t *openssl_mutexes;
static int openssl_mutex_num;
static int try_reset_early_data(VCNURLContext *h);
static void vcn_openssl_lock(int mode, int type, const char *file, int line)
{
    if (mode & CRYPTO_LOCK)
        pthread_mutex_lock(&openssl_mutexes[type]);
    else
        pthread_mutex_unlock(&openssl_mutexes[type]);
}
#if !defined(WIN32) && OPENSSL_VERSION_NUMBER < 0x10000000
static unsigned long VCNopenssl_thread_id(void)
{
    return (intptr_t) pthread_self();
}
#endif
#endif

static int vcn_url_bio_create(BIO *b)
{
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    BIO_set_init(b, 1);
    BIO_set_data(b, NULL);
    BIO_set_flags(b, 0);
#else
    b->init = 1;
    b->ptr = NULL;
    b->flags = 0;
#endif
    return 1;
}

static int vcn_url_bio_destroy(BIO *b)
{
    return 1;
}

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
#define GET_BIO_DATA(x) BIO_get_data(x);
#else
#define GET_BIO_DATA(x) (x)->ptr;
#endif

static int vcn_url_bio_bread(BIO *b, char *buf, int len)
{
    VCNURLContext *h;
    int ret;
    h = GET_BIO_DATA(b);
    ret = vcn_url_read(h, buf, len);
    if (ret >= 0)
        return ret;
    BIO_clear_retry_flags(b);
    if (ret == AVERROR_EXIT)
        return 0;
    return -1;
}

static int vcn_url_bio_bwrite(BIO *b, const char *buf, int len)
{
    VCNURLContext *h;
    int ret;
    h = GET_BIO_DATA(b);
    ret = vcn_url_write(h, buf, len);
    if (ret >= 0)
        return ret;
    BIO_clear_retry_flags(b);
    if (ret == AVERROR_EXIT)
        return 0;
    return -1;
}

static long vcn_url_bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    if (cmd == BIO_CTRL_FLUSH) {
        BIO_clear_retry_flags(b);
        return 1;
    }
    return 0;
}

static int vcn_url_bio_bputs(BIO *b, const char *str)
{
    return vcn_url_bio_bwrite(b, str, strlen(str));
}

#if OPENSSL_VERSION_NUMBER < 0x1010000fL
static BIO_METHOD vcn_url_bio_method = {
    .type = BIO_TYPE_SOURCE_SINK,
    .name = "urlprotocol bio",
    .bwrite = vcn_url_bio_bwrite,
    .bread = vcn_url_bio_bread,
    .bputs = vcn_url_bio_bputs,
    .bgets = NULL,
    .ctrl = vcn_url_bio_ctrl,
    .create = vcn_url_bio_create,
    .destroy = vcn_url_bio_destroy,
};
#endif

int vcn_openssl_init(void)
{
    vcn_avpriv_lock_avformat();
    if (!openssl_init) {
        SSL_library_init();
        SSL_load_error_strings();
#if HAVE_THREADS
        if (!CRYPTO_get_locking_callback()) {
            int i;
            CRYPTO_set_locking_callback(vcn_openssl_lock);
            if (CRYPTO_get_locking_callback() == vcn_openssl_lock) {
                openssl_mutex_num = CRYPTO_num_locks();
                openssl_mutexes = av_malloc_array(sizeof(pthread_mutex_t), openssl_mutex_num);
                if (!openssl_mutexes) {
                    openssl_mutex_num = 0;
                    vcn_avpriv_unlock_avformat();
                    return AVERROR(ENOMEM);
                }
                for (i = 0; i < openssl_mutex_num; i++) {
                    pthread_mutex_init(&openssl_mutexes[i], NULL);
                }
#if !defined(WIN32) && OPENSSL_VERSION_NUMBER < 0x10000000
                CRYPTO_set_id_callback(openssl_thread_id);
#endif
            }
        }
#endif
		ssl_data_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
        vcn_av_log(NULL, AV_LOG_DEBUG, "init lock_nums:%d\n", openssl_mutex_num);
    }
    openssl_init++;
    vcn_avpriv_unlock_avformat();

    return 0;
}

void vcn_openssl_deinit(void)
{
    vcn_avpriv_lock_avformat();
    openssl_init--;
    if (!openssl_init) {
#if HAVE_THREADS
        vcn_av_log(NULL, AV_LOG_DEBUG, "dinit lock_nums:%d\n", openssl_mutex_num);
        int i;
        CRYPTO_set_locking_callback(NULL);
        if (openssl_mutexes != NULL) {
            for (i = 0; i < openssl_mutex_num; i++) {
                pthread_mutex_destroy(&openssl_mutexes[i]);
            }
            vcn_av_free(openssl_mutexes);
        }
        openssl_mutexes = NULL;
        openssl_mutex_num = 0;
#endif
        ssl_data_index = -1;
    }
    vcn_avpriv_unlock_avformat();
}

static int vcn_print_tls_error(VCNURLContext *h, int ret)
{
    VCNTLSContext *c = h->priv_data;
    if(c->ssl) {
        vcn_av_net_info(h, netlog_tls_err, SSL_get_error(c->ssl, ret), NULL);
        vcn_av_log(h, AV_LOG_ERROR, "ssl get err:%d \n", SSL_get_error(c->ssl, ret));
    }
    return AVERROR(EIO);
}

static int vcn_tls_close(VCNURLContext *h)
{
    VCNTLSContext *c = h->priv_data;
    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
    if (c->ctx)
        SSL_CTX_free(c->ctx);
    if (c->tls_shared.tcp)
        vcn_url_close(c->tls_shared.tcp);
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    if (c->vcn_url_bio_method)
        BIO_meth_free(c->vcn_url_bio_method);
#endif
    vcn_openssl_deinit();
    return 0;
}

static int vcn_tls_open(VCNURLContext *h, const char *uri, int flags, AVDictionary **options)
{
    VCNTLSContext *p = h->priv_data;
    VCNTLSShared *c = &p->tls_shared;
    BIO *bio;
    int ret;


    vcn_av_log(h, AV_LOG_ERROR, "start tls open, uri:%s\n", uri);
    if ((ret = vcn_openssl_init()) < 0)
        return ret;

    if ((ret = vcn_tls_open_underlying(c, h, uri, options)) < 0) {
        vcn_av_log(h, AV_LOG_ERROR, "underlying open error ret:%d", ret);
        goto fail;
    }
    
    vcn_av_net_info(h, netlog_tls_handshake_begin, 0, NULL);

    int64_t handShakestarVCN = vcn_av_gettime();

    p->ctx = SSL_CTX_new(TLS_method());
    if (p->session_reuse) {
        vcn_av_log(h, AV_LOG_DEBUG, "set new session callback");
        SSL_CTX_set_session_cache_mode(p->ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
        vcn_av_log(h, AV_LOG_DEBUG, "session timeout is:%d", p->session_timeout);
        if(p->session_timeout > 0) {
            SSL_CTX_set_timeout(p->ctx, p->session_timeout);
        }

        SSL_CTX_sess_set_new_cb(p->ctx, new_session_callback);
    }
    SSL_CTX_set_grease_enabled(p->ctx, 1);
    
    if (!p->ctx) {
        vcn_av_log(h, AV_LOG_ERROR, "SSL_CTX_new err %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = AVERROR(EIO);
        goto fail;
    }
    
    SSL_CTX_set_min_proto_version(p->ctx, 0);
    if (p->max_tls_version > 2) {
        SSL_CTX_set_max_proto_version(p->ctx, TLS1_3_VERSION);
    }
    else {
        SSL_CTX_set_max_proto_version(p->ctx, TLS1_2_VERSION);
    }
    
    vcn_av_log(h, AV_LOG_DEBUG, " max tls version:%d", p->max_tls_version);
    
    
    SSL_CTX_set_options(p->ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    if (c->ca_file) {
        if (!SSL_CTX_load_verify_locations(p->ctx, c->ca_file, NULL))
            vcn_av_log(h, AV_LOG_ERROR, "SSL_CTX_load_verify_locations %s\n", ERR_error_string(ERR_get_error(), NULL));
    }
    if (c->cert_file && !SSL_CTX_use_certificate_chain_file(p->ctx, c->cert_file)) {
        vcn_av_log(h, AV_LOG_ERROR, "Unable to load cert file %s: %s\n",
               c->cert_file, ERR_error_string(ERR_get_error(), NULL));
        ret = AVERROR(EIO);
        goto fail;
    }
    if (c->key_file && !SSL_CTX_use_PrivateKey_file(p->ctx, c->key_file, SSL_FILETYPE_PEM)) {
        vcn_av_log(h, AV_LOG_ERROR, "Unable to load key file %s: %s\n",
               c->key_file, ERR_error_string(ERR_get_error(), NULL));
        ret = AVERROR(EIO);
        goto fail;
    }
    
    /* custom verify*/
    if (c->verify) {
        vcn_av_log(h, AV_LOG_ERROR, "set verify call back\n");
        SSL_CTX_set_reverify_on_resume(p->ctx, 1);
        SSL_CTX_set_custom_verify(p->ctx, SSL_VERIFY_PEER,
                                  verify_custom_callbak);
    }
    if(p->tls_false_start) {
        vcn_av_log(h, AV_LOG_DEBUG, "enable false start ctx\n");
        SSL_CTX_set_mode(p->ctx,  SSL_MODE_ENABLE_FALSE_START);
    }

    SSL_CTX_set_early_data_enabled(p->ctx, p->enable_early_data);
    vcn_av_log(h, AV_LOG_DEBUG, "early data flag:%d\n", p->enable_early_data);
    p->ssl = SSL_new(p->ctx);
    if (!p->ssl) {
        vcn_av_log(h, AV_LOG_ERROR, "SSL_new err %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = AVERROR(EIO);
        goto fail;
    }
    

    
    

    ret = SSL_set_ex_data(p->ssl, ssl_data_index, h);
    if(ret == 0) {
        vcn_av_log(h, AV_LOG_DEBUG, "set ex data fail");
    }
    if (p->session_reuse) {
        SSL_SESSION* session = get_session(h);
        if (session != NULL) {
            vcn_av_net_info(h, netlog_tls_early_data_capable, SSL_SESSION_early_data_capable(session), NULL);
            vcn_av_log(h, AV_LOG_DEBUG, "session cable:%d enable earlydata:%d", SSL_SESSION_early_data_capable(session), p->enable_early_data);
            if(p->enable_early_data) {
                p->enable_early_data = SSL_SESSION_early_data_capable(session);
            }
            SSL_set_session(p->ssl, session);
        }
        ret = SSL_set_ex_data(p->ssl, ssl_data_index, h);
        if(ret == 0) {
            vcn_av_log(h, AV_LOG_DEBUG, "set ex data fail");
        }
        vcn_av_log(h, AV_LOG_DEBUG, "enable session reuse get session:%p ssldataindex:%d set exdata ret:%d opque:%p fun:%p",
                             session, ssl_data_index, ret, h->interrupt_callback.session_opaque, h->interrupt_callback.session_callback);
        if (session != NULL) {
            SSL_SESSION_free(session);
        }
    }
    
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    p->vcn_url_bio_method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "urlprotocol bio");
    BIO_meth_set_write(p->vcn_url_bio_method, vcn_url_bio_bwrite);
    BIO_meth_set_read(p->vcn_url_bio_method, vcn_url_bio_bread);
    BIO_meth_set_puts(p->vcn_url_bio_method, vcn_url_bio_bputs);
    BIO_meth_set_ctrl(p->vcn_url_bio_method, vcn_url_bio_ctrl);
    BIO_meth_set_create(p->vcn_url_bio_method, vcn_url_bio_create);
    BIO_meth_set_destroy(p->vcn_url_bio_method, vcn_url_bio_destroy);
    bio = BIO_new(p->vcn_url_bio_method);
    BIO_set_data(bio, c->tcp);
#else
    bio = BIO_new(&vcn_url_bio_method);
    bio->ptr = c->tcp;
#endif
    SSL_set_bio(p->ssl, bio, bio);
    if (!c->listen && !c->numerichost)
        SSL_set_tlsext_host_name(p->ssl, c->host);
    ret = c->listen ? SSL_accept(p->ssl) : SSL_connect(p->ssl);
    if (ret == 0) {
        vcn_av_log(h, AV_LOG_ERROR, "Unable to negotiate TLS/SSL session\n");
        ret = AVERROR(EIO);
        goto fail;
    } else if (ret < 0) {
        ret = vcn_print_tls_error(h, ret);
        goto fail;
    }
    vcn_av_net_info(h, netlog_tls_version, 0, SSL_get_version(p->ssl));
    vcn_av_net_info(h, netlog_tls_session, SSL_session_reused(p->ssl), NULL);
    vcn_av_net_info(h, netlog_tls_handshake_end, 0, NULL);
    vcn_av_log(NULL, AV_LOG_ERROR, "end handshake open success cost time:%"PRId64" session reused:%d tls version:%s\n",
            vcn_av_gettime() - handShakestarVCN, SSL_session_reused(p->ssl), SSL_get_version(p->ssl));
    return 0;
fail:
    vcn_av_log(h, AV_LOG_DEBUG, "tls open fail:%d cost time:%"PRId64"", ret, vcn_av_gettime() - handShakestarVCN);
    vcn_av_log(NULL, AV_LOG_ERROR, "open fail\n");
    vcn_tls_close(h);
    return ret;
}
enum ssl_verify_result_t verify_custom_callbak(SSL *ssl, uint8_t *out_alert) {
    VCNURLContext *h = (VCNURLContext*)(SSL_get_ex_data(ssl, ssl_data_index));
    vcn_av_log(h, AV_LOG_WARNING, "try do verify call \n");
    if (!h) {
        vcn_av_log(NULL, AV_LOG_ERROR, "verify call fail, URLContext null\n");
        return ssl_verify_invalid;
    }
    VCNTLSContext *p = h->priv_data;
    VCNTLSShared *c = &p->tls_shared;
    
    return do_vcn_custom_verify_callback(h, ssl, c->host, c->underlying_port);
}
int is_expired(SSL_SESSION* session) {

    if (!session) {
        return 0;
    }
    int64_t now = vcn_av_gettime()/1000/1000;

    int64_t session_create_time = SSL_SESSION_get_time(session);
    int64_t session_timeout = SSL_SESSION_get_timeout(session);
    vcn_av_log(NULL, AV_LOG_DEBUG, "ssl expired nowtime:%"PRId64" session create time:%"PRId64" sessiontimeout:%"PRId64"", now, session_create_time, session_timeout);
     return now < (session_create_time) ||
         now >= (session_create_time + session_timeout);
}

static SSL_SESSION* get_session(VCNURLContext *h) {
    
    VCNTLSContext *p = h->priv_data;
    VCNTLSShared *c = &p->tls_shared;
    char key[256];
    memset(key, 0, sizeof(key));
    snprintf(key, sizeof(key), "%s:%d", c->underlying_host, c->underlying_port);
    int ret = -1;
    unsigned char* buf = NULL;
    size_t len = 0;
    SSL_SESSION* session = NULL;
    if (!p->session_reuse) {
        return NULL;
    }
    
    if (h->interrupt_callback.session_callback != NULL && h->interrupt_callback.session_opaque != NULL) {
        vcn_av_log(NULL, AV_LOG_DEBUG, "get session call back set");
        ret = h->interrupt_callback.session_callback(callback_get_session, h->interrupt_callback.session_opaque, (void*)key, (void **)(&buf), (void*)(&len));
    }
    SSL_CTX *ctx = NULL;
    if(buf != NULL && len > 0) {
        ctx = SSL_CTX_new(TLS_method());
        if (!ctx) {
            vcn_av_log(h, AV_LOG_DEBUG,"get session for key :%s, create ctx fail!",key);
            goto end;
        }
        session = (SSL_SESSION*)SSL_SESSION_from_bytes(buf, len, ctx);
        if (session != NULL && is_expired(session)) {
            SSL_SESSION_free(session);
            session = NULL;
            vcn_av_log(h, AV_LOG_DEBUG,"session expired can not be used");
        }
    }
end:
    vcn_av_log(NULL, AV_LOG_DEBUG, "get session for key :%s set ret:%d opaque:%p fun:%p buf:%p len:%d session:%p",
                         key, ret, h->interrupt_callback.session_opaque,h->interrupt_callback.session_callback, buf, len, session);
    if (ctx) {
        SSL_CTX_free(ctx);
    }
    if (buf) {
        vcn_av_free(buf);
    }
    return session;
}

static int new_session_callback_internal(VCNURLContext *h, SSL_SESSION* session) {
    if (!session || !h) {
        vcn_av_log(h, AV_LOG_DEBUG, "new session internal:%p h:%p", session, h);
        return 0;
    }
    VCNTLSContext *p = h->priv_data;
    VCNTLSShared *c = &p->tls_shared;
    char key[256];
    memset(key, 0, sizeof(key));
    snprintf(key, sizeof(key), "%s:%d", c->underlying_host, c->underlying_port);
    unsigned char* buf = NULL;
    size_t len = 0;
    int ret = SSL_SESSION_to_bytes(session, &buf, &len);
    if(ret == 0) {
        vcn_av_log(h, AV_LOG_DEBUG, "new session internal:%p h:%p to bytes fail:%d", session, h, ret);
        return 0;
    }
    if (h->interrupt_callback.session_callback != NULL && h->interrupt_callback.session_opaque != NULL) {
        vcn_av_log(NULL, AV_LOG_DEBUG, "new session call back set");
        ret = h->interrupt_callback.session_callback(callback_set_session, h->interrupt_callback.session_opaque, (void*)key, (void **)&buf, (void *)(&len));
    }
    vcn_av_log(NULL, AV_LOG_DEBUG, "new session for key :%s set ret:%d opaque:%p fun:%p buf:%p len:%d session:%p",
             key, ret, h->interrupt_callback.session_opaque,h->interrupt_callback.session_callback, buf, len, session);
    OPENSSL_free(buf);
    return 0;
    
}



static int new_session_callback(SSL* ssl, SSL_SESSION* session) {
    vcn_av_log(NULL, AV_LOG_DEBUG, "new session callback:%p ssl:%p", session, ssl);
    VCNURLContext *h = (VCNURLContext*)(SSL_get_ex_data(ssl, ssl_data_index));
    return new_session_callback_internal(h, session);
}

static int vcn_tls_read(VCNURLContext *h, uint8_t *buf, int size)
{
    VCNTLSContext *c = h->priv_data;
    int ret = SSL_read(c->ssl, buf, size);
    if (ret > 0)
        return ret;
    if(SSL_get_error(c->ssl, ret) == SSL_ERROR_EARLY_DATA_REJECTED) {
        vcn_av_log(h, AV_LOG_DEBUG, "tls read early data rejected");
        return try_reset_early_data(h);
    }
    if (ret == 0)
        return AVERROR_EOF;
    return vcn_print_tls_error(h, ret);
}

static int vcn_tls_write(VCNURLContext *h, const uint8_t *buf, int size)
{
    VCNTLSContext *c = h->priv_data;
    int ssl_err = 0;
    int ret = SSL_write(c->ssl, buf, size);
    if (ret > 0)
        return ret;
    if(SSL_get_error(c->ssl, ret) == SSL_ERROR_EARLY_DATA_REJECTED) {
        vcn_av_log(h, AV_LOG_DEBUG, "tls write early data rejected");
        return try_reset_early_data(h);
    }
    if (ret == 0)
        return AVERROR_EOF;
    return vcn_print_tls_error(h, ret);
}
static int try_reset_early_data(VCNURLContext *h) {
    vcn_av_net_info(h, netlog_tls_early_data_reset, 1, NULL);
    VCNTLSContext *c = h->priv_data;
    int ssl_ret = 0;
    int ret = 0;
    c->enable_early_data = 0;
    vcn_av_log(h, AV_LOG_DEBUG, "try reset for early data reject");
    SSL_reset_early_data_reject(c->ssl);
    int64_t handShakestarVCN = vcn_av_gettime();
    vcn_av_net_info(h, netlog_tls_handshake_begin, 0, NULL);
    ret = SSL_connect(c->ssl);
    vcn_av_log(h, AV_LOG_DEBUG, "retry ssl connect ret:%d", ret);
    if(ret <= 0) {
        vcn_av_log(h, AV_LOG_DEBUG, "reset ssl fail for earlydatareject, ssl err:%d", SSL_get_error(c->ssl, ret));
        return AVERROR_RESET_EARLY_DATA;
    }
    vcn_av_net_info(h, netlog_tls_handshake_end, 0, NULL);
    vcn_av_net_info(h, netlog_tls_version, 1, SSL_get_version(c->ssl));
    vcn_av_net_info(h, netlog_tls_session, SSL_session_reused(c->ssl), NULL);
    vcn_av_log(NULL, AV_LOG_ERROR, "reset ssl suc end handshake cost time:%"PRId64" session reused:%d tls version:%s\n",
             vcn_av_gettime() - handShakestarVCN, SSL_session_reused(c->ssl), SSL_get_version(c->ssl));
    return AVERROR_EARLY_DATA_REJECTED;
}
const char *vcn_tls_get_ip_addr(VCNURLContext *h) {
    VCNTLSContext *c = NULL;
    if (!h) {
        return NULL;
    }
    c = h->priv_data;
    if (!c) {
        return NULL;
    }
    if (c->tls_shared.tcp != NULL) {
        return vcn_tcp_get_ip_addr(c->tls_shared.tcp);
    }
    return NULL;
}
int vcn_tls_get_file_handle(VCNURLContext *h)
{
    if (!h) {
        return -1;
    }
    VCNTLSContext *c = h->priv_data;
    if (!c || !c->tls_shared.tcp) {
        return -1;
    }
    return vcn_url_get_file_handle(c->tls_shared.tcp);
}
void vcn_tls_reset_interrupt_callback(VCNURLContext *h) {
    VCNTLSContext *c = NULL;
    if (!h) {
        return;
    }
    c = h->priv_data;
    if (!c) {
        return;
    }
    if (c->tls_shared.tcp != NULL) {
        c->tls_shared.tcp->log_handle = h->log_handle;
        c->tls_shared.tcp->interrupt_callback = h->interrupt_callback;
    }
}
#define OFFSET(x) offsetof(VCNTLSContext, x)
#define D AV_OPT_FLAG_DECODING_PARAM
#define E AV_OPT_FLAG_ENCODING_PARAM
static const AVOption options[] = {
    VCN_TLS_COMMON_OPTIONS(VCNTLSContext, tls_shared),
    { "max_tls_version",     "max tls version", OFFSET(max_tls_version),     AV_OPT_TYPE_INT, { .i64 = 2 },         2, INT_MAX, .flags = D|E },
    { "session_reuse",     "session reuse flag", OFFSET(session_reuse),     AV_OPT_TYPE_INT, { .i64 = 0 },         0, 1, .flags = D|E },
    { "session_timeout",     "session timeout", OFFSET(session_timeout),     AV_OPT_TYPE_INT, { .i64 = 3600 },         0, INT_MAX, .flags = D|E },
    { "tls_false_start",     "tls false start", OFFSET(tls_false_start),     AV_OPT_TYPE_INT, { .i64 = 0 },         0, 1, .flags = D|E },
    { "early_data",     "tls1.3 early data", OFFSET(enable_early_data),     AV_OPT_TYPE_INT, { .i64 = 0 },         0, 1, .flags = D|E },
    {NULL}
};

static const AVClass vcn_tls_class = {
    .class_name = "tls",
    .item_name  = vcn_av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};

const URLProtocol vcn_tls_openssl_protocol = {
    .name           = "tls",
    .url_open2      = vcn_tls_open,
    .url_read       = vcn_tls_read,
    .url_write      = vcn_tls_write,
    .url_close      = vcn_tls_close,
    .url_get_file_handle = vcn_tls_get_file_handle,
    .priv_data_size = sizeof(VCNTLSContext),
    .flags          = URL_PROTOCOL_FLAG_NETWORK,
    .priv_data_class = &vcn_tls_class,
};
