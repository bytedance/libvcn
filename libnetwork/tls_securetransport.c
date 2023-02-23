/*
 * Copyright (c) 2015 Rodger Combs
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with FFmpeg; if not, write to the Free Software * Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 * 
 * This file may have been modified by Bytedance Inc. ("Bytedance Modifications"). 
 * All Bytedance Modifications are Copyright 2023 Bytedance Inc.
 */

#include <errno.h>


#include "avio_internal.h"
#include "network.h"
#include "os_support.h"
#include "vcn_url.h"
#include "tls.h"
#include "libutil/vcn_avstring.h"
#include "libutil/vcn_opt.h"
#include "libutil/vcn_mem.h"
#include "vcn_avio.h"

#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <CoreFoundation/CoreFoundation.h>

// We use a private API call here; it's good enough for WebKit.
SecIdentityRef SecIdentityCreate(CFAllocatorRef allocator, SecCertificateRef certificate, SecKeyRef privateKey);
#define ioErr -36

typedef struct TLSContext {
    const AVClass *class;
    VCNTLSShared tls_shared;
    SSLContextRef ssl_context;
    CFArrayRef ca_array;
    int lastErr;
} TLSContext;

static int vcn_print_tls_error(VCNURLContext *h, int ret)
{
    TLSContext *c = h->priv_data;
    switch (ret) {
    case errSSLWouldBlock:
        break;
    case errSSLXCertChainInvalid:
        vcn_av_log(h, AV_LOG_ERROR, "Invalid certificate chain\n");
        return AVERROR(EIO);
    case ioErr:
        return c->lastErr;
    default:
        vcn_av_log(h, AV_LOG_ERROR, "IO Error: %i\n", ret);
        return AVERROR(EIO);
    }
    return AVERROR(EIO);
}

static int import_pem(VCNURLContext *h, char *path, CFArrayRef *array)
{
    AVIOContext *s = NULL;
    CFDataRef data = NULL;
    int64_t ret = 0;
    char *buf = NULL;
    SecExternalFormat format = kSecFormatPEMSequence;
    SecExternalFormat type = kSecItemTypeAggregate;
    CFStringRef pathStr = CFStringCreateWithCString(NULL, path, 0x08000100);
    if (!pathStr) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    if ((ret = vcn_io_open_whitelist(&s, path, AVIO_FLAG_READ,
                                   &h->interrupt_callback, NULL,
                                   h->protocol_whitelist, h->protocol_blacklist)) < 0)
        goto end;

    if ((ret = avio_size(s)) < 0)
        goto end;

    if (ret == 0) {
        ret = AVERROR_INVALIDDATA;
        goto end;
    }

    if (!(buf = vcn_av_malloc(ret))) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    if ((ret = avio_read(s, buf, ret)) < 0)
        goto end;

    data = CFDataCreate(kCFAllocatorDefault, buf, ret);

    if (SecItemImport(data, pathStr, &format, &type,
                      0, NULL, NULL, array) != noErr || !array) {
        ret = AVERROR_UNKNOWN;
        goto end;
    }

    if (CFArrayGetCount(*array) == 0) {
        ret = AVERROR_INVALIDDATA;
        goto end;
    }

end:
    vcn_av_free(buf);
    if (pathStr)
        CFRelease(pathStr);
    if (data)
        CFRelease(data);
    if (s)
        avio_close(s);
    return ret;
}

static int load_ca(VCNURLContext *h)
{
    TLSContext *c = h->priv_data;
    int ret = 0;
    CFArrayRef array = NULL;

    if ((ret = import_pem(h, c->tls_shared.ca_file, &array)) < 0)
        goto end;

    if (!(c->ca_array = CFRetain(array))) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

end:
    if (array)
        CFRelease(array);
    return ret;
}

static int load_cert(VCNURLContext *h)
{
    TLSContext *c = h->priv_data;
    int ret = 0;
    CFArrayRef certArray = NULL;
    CFArrayRef keyArray = NULL;
    SecIdentityRef id = NULL;
    CFMutableArrayRef outArray = NULL;

    if ((ret = import_pem(h, c->tls_shared.cert_file, &certArray)) < 0)
        goto end;

    if ((ret = import_pem(h, c->tls_shared.key_file, &keyArray)) < 0)
        goto end;

    if (!(id = SecIdentityCreate(kCFAllocatorDefault,
                                 (SecCertificateRef)CFArrayGetValueAtIndex(certArray, 0),
                                 (SecKeyRef)CFArrayGetValueAtIndex(keyArray, 0)))) {
        ret = AVERROR_UNKNOWN;
        goto end;
    }

    if (!(outArray = CFArrayCreateMutableCopy(kCFAllocatorDefault, 0, certArray))) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    CFArraySetValueAtIndex(outArray, 0, id);

    SSLSetCertificate(c->ssl_context, outArray);

end:
    if (certArray)
        CFRelease(certArray);
    if (keyArray)
        CFRelease(keyArray);
    if (outArray)
        CFRelease(outArray);
    if (id)
        CFRelease(id);
    return ret;
}

static OSStatus tls_read_cb(SSLConnectionRef connection, void *data, size_t *dataLength)
{
    VCNURLContext *h = (VCNURLContext*)connection;
    TLSContext *c = h->priv_data;
    int read = vcn_url_read_complete(c->tls_shared.tcp, data, *dataLength);
    if (read <= 0) {
        *dataLength = 0;
        switch(AVUNERROR(read)) {
            case ENOENT:
            case 0:
                return errSSLClosedGraceful;
            case ECONNRESET:
                return errSSLClosedAbort;
            case EAGAIN:
                return errSSLWouldBlock;
            default:
                c->lastErr = read;
                return ioErr;
        }
    } else {
        *dataLength = read;
        return noErr;
    }
}

static OSStatus tls_write_cb(SSLConnectionRef connection, const void *data, size_t *dataLength)
{
    VCNURLContext *h = (VCNURLContext*)connection;
    TLSContext *c = h->priv_data;
    int written = vcn_url_write(c->tls_shared.tcp, data, *dataLength);
    if (written <= 0) {
        *dataLength = 0;
        switch(AVUNERROR(written)) {
            case EAGAIN:
                return errSSLWouldBlock;
            default:
                c->lastErr = written;
                return ioErr;
        }
    } else {
        *dataLength = written;
        return noErr;
    }
}

static int tls_close(VCNURLContext *h)
{
    TLSContext *c = h->priv_data;
    if (c->ssl_context) {
        SSLClose(c->ssl_context);
        CFRelease(c->ssl_context);
    }
    if (c->ca_array)
        CFRelease(c->ca_array);
    if (c->tls_shared.tcp)
        vcn_url_close(c->tls_shared.tcp);
    return 0;
}

#define CHECK_ERROR(func, ...) do {                                     \
        OSStatus status = func(__VA_ARGS__);                            \
        if (status != noErr) {                                          \
            ret = AVERROR_UNKNOWN;                                      \
            vcn_av_log(h, AV_LOG_ERROR, #func ": Error %i\n", (int)status); \
            goto fail;                                                  \
        }                                                               \
    } while (0)

static int tls_open(VCNURLContext *h, const char *uri, int flags, AVDictionary **options)
{
    TLSContext *c = h->priv_data;
    VCNTLSShared *s = &c->tls_shared;
    int ret;

    if ((ret = ff_tls_open_underlying(s, h, uri, options)) < 0)
        goto fail;

    c->ssl_context = SSLCreateContext(NULL, s->listen ? kSSLServerSide : kSSLClientSide, kSSLStreamType);
    if (!c->ssl_context) {
        vcn_av_log(h, AV_LOG_ERROR, "Unable to create SSL context\n");
        ret = AVERROR(ENOMEM);
        goto fail;
    }
    if (s->ca_file) {
        if ((ret = load_ca(h)) < 0)
            goto fail;
    }
    if (s->ca_file || !s->verify)
        CHECK_ERROR(SSLSetSessionOption, c->ssl_context, kSSLSessionOptionBreakOnServerAuth, true);
    if (s->cert_file)
        if ((ret = load_cert(h)) < 0)
            goto fail;
    CHECK_ERROR(SSLSetPeerDomainName, c->ssl_context, s->host, strlen(s->host));
    CHECK_ERROR(SSLSetIOFuncs, c->ssl_context, tls_read_cb, tls_write_cb);
    CHECK_ERROR(SSLSetConnection, c->ssl_context, h);
    while (1) {
        OSStatus status = SSLHandshake(c->ssl_context);
        if (status == errSSLServerAuthCompleted) {
            SecTrustRef peerTrust;
            SecTrustResultType trustResult;
            if (!s->verify)
                continue;

            if (SSLCopyPeerTrust(c->ssl_context, &peerTrust) != noErr) {
                ret = AVERROR(ENOMEM);
                goto fail;
            }

            if (SecTrustSetAnchorCertificates(peerTrust, c->ca_array) != noErr) {
                ret = AVERROR_UNKNOWN;
                goto fail;
            }

            if (SecTrustEvaluate(peerTrust, &trustResult) != noErr) {
                ret = AVERROR_UNKNOWN;
                goto fail;
            }

            if (trustResult == kSecTrustResultProceed ||
                trustResult == kSecTrustResultUnspecified) {
                // certificate is trusted
                status = errSSLWouldBlock; // so we call SSLHandshake again
            } else if (trustResult == kSecTrustResultRecoverableTrustFailure) {
                // not trusted, for some reason other than being expired
                status = errSSLXCertChainInvalid;
            } else {
                // cannot use this certificate (fatal)
                status = errSSLBadCert;
            }

            if (peerTrust)
                CFRelease(peerTrust);
        }
        if (status == noErr)
            break;

        vcn_av_log(h, AV_LOG_ERROR, "Unable to negotiate TLS/SSL session: %i\n", (int)status);
        ret = AVERROR(EIO);
        goto fail;
    }
    vcn_av_log(NULL, AV_LOG_WARNING, "tls success!\n");
    return 0;
fail:
    vcn_av_log(NULL, AV_LOG_WARNING, "tls fail!\n");
    tls_close(h);
    return ret;
}

static int map_ssl_error(OSStatus status, size_t processed)
{
    switch (status) {
    case noErr:
        return processed;
    case errSSLClosedGraceful:
    case errSSLClosedNoNotify:
        return 0;
    default:
        return (int)status;
    }
}

static int tls_read(VCNURLContext *h, uint8_t *buf, int size)
{
    TLSContext *c = h->priv_data;
    size_t processed = 0;
    int ret = SSLRead(c->ssl_context, buf, size, &processed);
    ret = map_ssl_error(ret, processed);
    if (ret > 0)
        return ret;
    if (ret == 0)
        return AVERROR_EOF;
    return vcn_print_tls_error(h, ret);
}

static int tls_write(VCNURLContext *h, const uint8_t *buf, int size)
{
    TLSContext *c = h->priv_data;
    size_t processed = 0;
    int ret = SSLWrite(c->ssl_context, buf, size, &processed);
    ret = map_ssl_error(ret, processed);
    if (ret > 0)
        return ret;
    if (ret == 0)
        return AVERROR_EOF;
    return vcn_print_tls_error(h, ret);
}

static const AVOption options[] = {
    VCN_TLS_COMMON_OPTIONS(TLSContext, tls_shared),
    { NULL }
};

static const AVClass vcn_tls_class = {
    .class_name = "tls",
    .item_name  = vcn_av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};

const URLProtocol ff_tls_securetransport_protocol = {
    .name           = "tls",
    .url_open2      = tls_open,
    .url_read       = tls_read,
    .url_write      = tls_write,
    .url_close      = tls_close,
    .priv_data_size = sizeof(TLSContext),
    .flags          = URL_PROTOCOL_FLAG_NETWORK,
    .priv_data_class = &vcn_tls_class,
};
