/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */
#pragma once
#include "VCNBase.h"

NS_VCN_BEGIN

class VCN_INTERFACE_EXPORT VCNDNSParserInterface {
public:
    enum {
        DNS_ERROR_NULL         = 0,
        DNS_ERROR_INVALID_HOST = -1,
        DNS_ERROR_AYSYNC       = -2,
        DNS_ERROR_TIMEOUT      = -3,
        DNS_ERROR_INTERRUPT    = -4,
    };
public:
    VCNDNSParserInterface(void *wrapper = nullptr, void* networkManagerPtr = nullptr) ;
    virtual ~VCNDNSParserInterface();
public:
    virtual char* parse(const char* hostName, int timeOut, int &type, int& err, int parameter, int preferDNSType = -1) = 0;
    virtual void close() = 0;
    virtual void notify(const char* host, const char* ipList, int64_t expiredTime,int type = -1) = 0;

public:
    int mType;
};
NS_VCN_END
