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

#include "network.h"
#include "os_support.h"
#include "vcn_utils.h"
#include "vcn_url.h"
#include "tls.h"
#include "vcn_avstring.h"
#include "vcn_opt.h"

static void vcn_set_options(VCNTLSShared *c, const char *uri)
{
    char buf[1024];
    const char *p = strchr(uri, '?');
    if (!p)
        return;

    if (!c->ca_file && vcn_av_find_info_tag(buf, sizeof(buf), "cafile", p))
        c->ca_file = vcn_av_strdup(buf);

    if (!c->verify && vcn_av_find_info_tag(buf, sizeof(buf), "verify", p)) {
        char *endptr = NULL;
        c->verify = strtol(buf, &endptr, 10);
        if (buf == endptr)
            c->verify = 1;
    }

    if (!c->cert_file && vcn_av_find_info_tag(buf, sizeof(buf), "cert", p))
        c->cert_file = vcn_av_strdup(buf);

    if (!c->key_file && vcn_av_find_info_tag(buf, sizeof(buf), "key", p))
        c->key_file = vcn_av_strdup(buf);
}

int vcn_tls_open_underlying(VCNTLSShared *c, VCNURLContext *parent, const char *uri, AVDictionary **options)
{
    int port;
    const char *p;
    char buf[200], opts[50] = "";
    struct addrinfo hints = { 0 }, *ai = NULL;
    const char *proxy_path;
    int use_proxy;

    vcn_set_options(c, uri);

    if (c->listen)
        snprintf(opts, sizeof(opts), "?listen=1");

    vcn_av_url_split(NULL, 0, NULL, 0, c->underlying_host, sizeof(c->underlying_host), &port, NULL, 0, uri);
    c->underlying_port = port;

    p = strchr(uri, '?');

    if (!p) {
        p = opts;
    } else {
        if (vcn_av_find_info_tag(opts, sizeof(opts), "listen", p))
            c->listen = 1;
    }

    vcn_url_join(buf, sizeof(buf), "tcp", NULL, c->underlying_host, port, "%s", p);

    hints.ai_flags = AI_NUMERICHOST;
    if (!getaddrinfo(c->underlying_host, NULL, &hints, &ai)) {
        c->numerichost = 1;
        freeaddrinfo(ai);
    }

    if (!c->host && !(c->host = vcn_av_strdup(c->underlying_host)))
        return AVERROR(ENOMEM);

    proxy_path = getenv("http_proxy");
    use_proxy = !vcn_http_match_no_proxy(getenv("no_proxy"), c->underlying_host) &&
                proxy_path && vcn_av_strstart(proxy_path, "http://", NULL);

    if (use_proxy) {
        char proxy_host[200], proxy_auth[200], dest[200];
        int proxy_port;
        vcn_av_url_split(NULL, 0, proxy_auth, sizeof(proxy_auth),
                     proxy_host, sizeof(proxy_host), &proxy_port, NULL, 0,
                     proxy_path);
        vcn_url_join(dest, sizeof(dest), NULL, NULL, c->underlying_host, port, NULL);
        vcn_url_join(buf, sizeof(buf), "httpproxy", proxy_auth, proxy_host,
                    proxy_port, "/%s", dest);
    }

    return vcn_url_open_whitelist(&c->tcp, buf, AVIO_FLAG_READ_WRITE,
                                &parent->interrupt_callback, options,
                                parent->protocol_whitelist, parent->protocol_blacklist, parent);
}
