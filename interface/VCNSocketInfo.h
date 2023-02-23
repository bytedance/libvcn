/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */
#pragma once
#include "VCNBase.h"
extern "C" {
#include "vcn_url.h"
}
NS_VCN_BEGIN

class VCN_INTERFACE_EXPORT VCNSocketInfo {
public:
    VCNSocketInfo(VCNURLContext *hd, const char *host, const char *ip,
            int port, int64_t idleStartT,int lowerProto, const char* customHost = nullptr);
    ~VCNSocketInfo();
    VCNSocketInfo(const VCNSocketInfo& src);
    VCNSocketInfo& operator =(const VCNSocketInfo& src);
    void setInfo(VCNURLContext *hd, const char *host, const char *ip, int port, int64_t idleStartT,
                 int lowerProto, const char* customHost = nullptr);
    void onNetInfo(int type, int64_t code, const char* info);
    bool isAllowReuse(const char* srcHost, int srcPort, int srcLowerProto);
public:
    static void onNetInfoCallBack(int64_t clientId,int type, int64_t code, const char* logInfo);
public:
    void reset();
    bool isValid();
    static bool compareByIdleStartTAndUsedState(const VCNSocketInfo* info1,const VCNSocketInfo* info2);
public:
    VCNURLContext *socketHd;
    char *ip;
    char *host;
    char *tlsVersion;
    int port;
    int64_t idleStartT;
    int isUsed;
    int num;
    int useCount;
    int64_t createT;
    int lowerProto;
    char* customHost;
    int dnsType;
};
struct compareByHostAndPort
{
    bool operator()( const VCNSocketInfo* info1,const VCNSocketInfo* info2 ) const
    {
        int hostValue = strcmp( info1->host, info2->host );
        if(hostValue != 0) {
            return hostValue < 0;
        }
        return  info1->port == info2->port ? (info1->lowerProto < info2->lowerProto) : (info1->port < info2->port) ;
    }
};

NS_VCN_END
