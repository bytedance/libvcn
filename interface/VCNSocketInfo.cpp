/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */
#include "VCNBase.h"
#include "VCNSocketInfo.h"
#include "VCNUtils.h"
#include "VCNLogger.h"

NS_VCN_BEGIN
VCNSocketInfo::VCNSocketInfo(VCNURLContext *hd, const char *host, const char *ip, int port, int64_t idleStartT,
                                 int lowerProto, const char* customHost)
:socketHd(nullptr)
,ip(nullptr)
,tlsVersion(nullptr)
,port(-1)
,idleStartT(0)
,host(nullptr)
,isUsed(0)
,num(0)
,useCount(0)
,createT(0)
,lowerProto(LowerProtoIsTcp)
,customHost(nullptr)
,dnsType(-1){
    VCN_MEMCPY_STRING(this->ip, ip);
    VCN_MEMCPY_STRING(this->host, host);
    this->port = port;
    this->socketHd = hd;
    this->idleStartT = idleStartT;
    this->lowerProto = lowerProto;
    VCN_MEMCPY_STRING(this->customHost, customHost)
}
VCNSocketInfo::~VCNSocketInfo() {
    VCN_DELETE_STRING(ip)
    VCN_DELETE_STRING(host)
    VCN_DELETE_STRING(tlsVersion)
    VCN_DELETE_STRING(customHost)
}
VCNSocketInfo::VCNSocketInfo(const VCNSocketInfo& src)
:socketHd(nullptr)
,ip(nullptr)
,tlsVersion(nullptr)
,port(-1)
,idleStartT(0)
,host(nullptr)
,isUsed(0)
,num(0)
,useCount(0)
,createT(0)
,lowerProto(LowerProtoIsTcp)
,customHost(nullptr)
,dnsType(-1){
    VCN_MEMCPY_STRING(this->ip, src.ip)
    VCN_MEMCPY_STRING(this->host, src.host)
    VCN_MEMCPY_STRING(this->tlsVersion, src.tlsVersion)
    this->port = src.port;
    this->idleStartT = src.idleStartT;
    this->num = src.num;
    this->useCount = src.useCount;
    this->isUsed = src.isUsed;
    this->socketHd = src.socketHd;
    this->createT  = src.createT;
    this->lowerProto    = src.lowerProto;
    VCN_MEMCPY_STRING(this->customHost, customHost)
    this->dnsType = src.dnsType;
}
VCNSocketInfo& VCNSocketInfo::operator =(const VCNSocketInfo& src) {
    if(this != &src) {
        VCN_MEMCPY_STRING(this->ip, src.ip)
        VCN_MEMCPY_STRING(this->host, src.host)
        VCN_MEMCPY_STRING(this->tlsVersion, src.tlsVersion)
        this->port = src.port;
        this->idleStartT = src.idleStartT;
        this->num = src.num;
        this->useCount = src.useCount;
        this->isUsed = src.isUsed;
        this->socketHd = src.socketHd;
        this->createT  = src.createT;
        this->lowerProto    = src.lowerProto;
        VCN_MEMCPY_STRING(this->customHost, customHost)
        this->dnsType = src.dnsType;

    }
    return *this;
}
void VCNSocketInfo::setInfo(VCNURLContext *hd, const char *host, const char *ip, int port,
        int64_t idleStartT, int lowerProto, const char* customHost) {
    VCN_MEMCPY_STRING(this->ip, ip)
    VCN_MEMCPY_STRING(this->host, host)
    this->socketHd = hd;
    this->port = port;
    this->idleStartT = idleStartT;
    this->lowerProto = lowerProto;
    VCN_MEMCPY_STRING(this->customHost, customHost)
}
void VCNSocketInfo::reset() {
    VCN_DELETE_STRING(ip)
    VCN_DELETE_STRING(host)
    VCN_DELETE_STRING(tlsVersion)
    port = -1;
    idleStartT = 0;
    num = 0;
    socketHd = nullptr;
    isUsed = 0;
    useCount = 0;
    createT = 0;
    lowerProto = LowerProtoIsTcp;
    VCN_DELETE_STRING(customHost)
    dnsType = -1;
}
bool VCNSocketInfo::isValid() {
    if (VCN_IS_EMPTY_STRING(ip) || VCN_IS_EMPTY_STRING(host) || socketHd == nullptr || (!(port > 0 && port < 65535))) {
        return false;
    }
    return true;
}
void VCNSocketInfo::onNetInfo(int type, int64_t code, const char* info) {
    switch (type) {
        case netlog_tls_version:
            VCN_LOGK("socket info tls version:%s", info);
            VCN_MEMCPY_STRING(tlsVersion, info)
            break;

    }
}
bool VCNSocketInfo::compareByIdleStartTAndUsedState(const VCNSocketInfo* info1,const VCNSocketInfo* info2) {
    if (info1 == nullptr) {
        return false;
    }
    if (info2 == nullptr) {
        return true;
    }
    return info1->idleStartT > info2->idleStartT;
}
void VCNSocketInfo::onNetInfoCallBack(int64_t clientId,int type, int64_t code, const char* logInfo) {
    if(clientId == 0) {
        return;
    }
    VCNSocketInfo* info = reinterpret_cast<VCNSocketInfo*>(clientId);
    info->onNetInfo(type, code, logInfo);
}
bool VCNSocketInfo::isAllowReuse(const char* srcHost, int srcPort, int srcLowerProto) {
    if((strcmp(srcHost, this->host) == 0) && srcPort == this->port && srcLowerProto == this->lowerProto) {
        return true;
    }
    return false;
}
NS_VCN_END
