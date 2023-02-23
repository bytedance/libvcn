/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */
#pragma once
#include "VCNBase.h"
#include "VCNHttpContext.h"
extern "C" {
#include "vcn_url.h"
#include "vcn_dict.h"
#include "vcn_avio.h"
}
NS_VCN_BEGIN
//class VCNHttpContext;
VCN_INTERFACE_EXPORT int httpParserOpen(VCNHttpContext *s, const char *uri, int flags,
                          AVDictionary **options);

VCN_INTERFACE_EXPORT int  httpParserRead(VCNHttpContext *s, uint8_t *buf, int size);
VCN_INTERFACE_EXPORT int httpParserWrite(VCNHttpContext *s, const uint8_t *buf, int size);
VCN_INTERFACE_EXPORT int httpParserGetfileHandle(VCNHttpContext *s);
VCN_INTERFACE_EXPORT int httpParserHandshake(VCNHttpContext *c);
VCN_INTERFACE_EXPORT int httpParserAccept(VCNURLContext *sl, VCNHttpContext **c, const AVNetIOInterruptCB *int_cb,AVDictionary **options);
VCN_INTERFACE_EXPORT int httpParserClose(VCNHttpContext *s);
VCN_INTERFACE_EXPORT int httpParserGetShortSeek(VCNHttpContext *s);
VCN_INTERFACE_EXPORT int httpParsrGetLine(VCNHttpContext *s, char *line, int line_size);
VCN_INTERFACE_EXPORT int httpParserHttpAVError(int status_code, int default_averror);
VCN_INTERFACE_EXPORT void httpParserParseContentRange(VCNHttpContext *s, const char *p);
VCN_INTERFACE_EXPORT int httpParserGetSocketBufferAvailableSize(VCNHttpContext *s);
NS_VCN_END
