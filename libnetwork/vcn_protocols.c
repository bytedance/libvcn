/*
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
#include "libvcn/vcn_mem.h"
#include "libvcn/vcn_avstring.h"
#include "libvcn/vcn_url.h"



extern const URLProtocol vcn_tcp_protocol;
extern const URLProtocol vcn_tls_openssl_protocol;
extern const URLProtocol vcn_http_protocol;
extern const URLProtocol vcn_https_protocol;

static const URLProtocol *url_protocol_lists[] = {
    &vcn_http_protocol,
    &vcn_https_protocol,
    &vcn_tls_openssl_protocol,
    &vcn_tcp_protocol,
    NULL };


const AVClass *vcn_VCNURLContext_child_class_next(const AVClass *prev)
{
    int i;
    
    /* find the protocol that corresponds to prev */
    for (i = 0; prev && url_protocol_lists[i]; i++) {
        if (url_protocol_lists[i]->priv_data_class == prev) {
            i++;
            break;
        }
    }
    
    /* find next protocol with priv options */
    for (; url_protocol_lists[i]; i++)
        if (url_protocol_lists[i]->priv_data_class)
            return url_protocol_lists[i]->priv_data_class;
    return NULL;
}


const char *avio_enum_protocols(void **opaque, int output)
{
    const URLProtocol **p = *opaque;
    
    p = p ? p + 1 : url_protocol_lists;
    *opaque = p;
    if (!*p) {
        *opaque = NULL;
        return NULL;
    }
    if ((output && (*p)->url_write) || (!output && (*p)->url_read))
        return (*p)->name;
    return avio_enum_protocols(opaque, output);
}

const URLProtocol **vcn_url_get_protocols(const char *whitelist,
                                        const char *blacklist)
{
    const URLProtocol **ret;
    int i, ret_idx = 0;
    
    ret = vcn_av_mallocz_array(FF_ARRAY_ELEMS(url_protocol_lists), sizeof(*ret));
    if (!ret)
        return NULL;
    
    for (i = 0; url_protocol_lists[i]; i++) {
        const URLProtocol *up = url_protocol_lists[i];
        
        if (whitelist && *whitelist && !av_match_name(up->name, whitelist))
            continue;
        if (blacklist && *blacklist && av_match_name(up->name, blacklist))
            continue;
        
        ret[ret_idx++] = up;
    }
    
    return ret;
}

