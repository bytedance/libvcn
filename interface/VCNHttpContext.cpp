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
#include "VCNUtils.h"
#include "VCNDNSParserInterface.h"

NS_VCN_BEGIN
VCNHttpContext* createHttpContext() {
    VCNHttpContext* context = (VCNHttpContext*)vcn_av_mallocz(sizeof(VCNHttpContext));
    if (context == NULL) {
        return NULL;
    }
    memset(context, 0, sizeof(VCNHttpContext));
    context->flags |= AVIO_FLAG_READ_WRITE;
    context->seekable = -1;
    context->chunked_post = 1;
    context->multiple_requests = 0;
    context->icy = 1;
    context->auth_state.auth_type = HTTP_AUTH_NONE;
    context->send_expect_100 = 0;
    context->off = 0;
    context->end_off = 0;
    context->reconnect = 0;
    context->reconnect_at_eof = 0;
    context->reconnect_streamed = 0;
    context->reconnect_count = 0;
    context->reconnect_delay_max = 120;
    context->listen = 0;
    context->reply_code = 200;
    context->is_redirect = 1;
    context->is_err_continue = 0;
    context->open_timeout = 5;
	context->log_handle = 0;
    context->maxIPV4Num = INT32_MAX;
    context->maxIPV6Num = INT32_MAX;
    context->forbidByPassCookie = 0;
    context->mRequestAccessCheck = nullptr;
    context->mResponseAccessCheck = nullptr;
    context->reserved_code = 0;
    context->post_data = nullptr;
    context->lowerProto = LowerProtoIsInvalid;
    context->isUnlimitHttpHeader = 0;
    context->parserNotifyer = nullptr;
    context->parserStrategy = nullptr;
    context->parserHelper   = nullptr;
    context->socketInfoManager = nullptr;
    context->customHost = nullptr;
    context->dns_type = -1;
    return context;
}
int releaseHttpContext(VCNHttpContext** context) {
    VCNHttpContext* httpContext = *context;
    if (httpContext == nullptr) {
        return 0;
    }
    /*release hd*/
    /*release options*/
     //todo
    VCN_DELETE_OBJECT(httpContext->parser)
    VCN_DELETE_STRING(httpContext->location);
    VCN_DELETE_STRING(httpContext->http_proxy);
    VCN_DELETE_STRING(httpContext->mime_type);
    VCN_DELETE_STRING(httpContext->user_agent);
    VCN_DELETE_STRING(httpContext->content_type);
    VCN_DELETE_STRING(httpContext->cookies)
    VCN_DELETE_STRING(httpContext->icy_metadata_headers);
    VCN_DELETE_STRING(httpContext->icy_metadata_packet)
    VCN_DELETE_STRING(httpContext->method)
    VCN_DELETE_STRING(httpContext->resource)
    VCN_DELETE_STRING(httpContext->valid_http_content_type)
    VCN_DELETE_STRING(httpContext->headers);
    VCN_DELETE_STRING(httpContext->connectedIp)
    VCN_DELETE_STRING(httpContext->connectedHost)
    VCN_DELETE_STRING(httpContext->mRequestAccessCheck)
    VCN_DELETE_STRING(httpContext->mResponseAccessCheck)
    VCN_DELETE_STRING(httpContext->customHost)
    if (httpContext->post_data!= nullptr) {
        delete [] httpContext->post_data;
        httpContext->post_data = nullptr;
    }
    vcn_av_dict_free(&httpContext->cookie_dict);
    vcn_av_dict_free(&httpContext->metadata);
    vcn_av_dict_free(&httpContext->chained_options);
    using namespace std;
    httpContext->receivedHeader.~map();
    httpContext->socketInfo.~VCNSocketInfo();
    
    vcn_av_freep(context);
    return 0;
}
NS_VCN_END
