/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */

#pragma once
#include "VCNBase.h"
#include <string>
#include <map>
NS_VCN_BEGIN
struct VCNHttpContext;
class VCNSocketInfo;
enum class VCN_INTERFACE_EXPORT VCNHttpParserNotifyKey{
    VCNHttpParserNotifyKeyIsFinalUrl = 10000,
    VCNHttpParserNotifyKeyIsCDNStatusCode,
    VCNHttpParserNotifyKeyIsOriginUrl,
    VCNHttpParserNotifyKeyIsRequestEffectiveUrl,
    VCNHttpParserNotifyKeyIsDNSType,
    VCNHttpParserNotifyKeyIsSocketInfoTlsVersion,
    VCNHttpParserNotifyKeyIsSocketInfoUsedCout,
    VCNHttpParserNotifyKeyIsSocketInfoCreateTimeInternal,
    VCNHttpParserNotifyKeyIsLowSpeedCheckErr,
    VCNHttpParserNotifyKeyIsSocketInfoIdleTimeInternal,
    VCNHttpParserNotifyKeyIsEventInfo,
    VCNHttpParserNotifyKeyIsRequestHost,
    VCNHttpParserNotifyKeyIsConnectedIp,
    VCNHttpParserNotifyKeyIsParsedIpList,
    VCNHttpParserNotifyKeyIsSocketReuseFlag,
    VCNHttpParserNotifyKeyIsConnectedPort,
    VCNHttpParserNotifyKeyIsCDNttfb,
    VCNHttpParserNotifyKeyIsDNSParseStart,
    VCNHttpParserNotifyKeyIsDNSParseEnd,
    VCNHttpParserNotifyKeyIsLowerProto,
    VCNHttpParserNotifyKeyIsRedirectUrl,
};
class VCN_INTERFACE_EXPORT VCNHttpParserNotifyer{
public:
    virtual ~VCNHttpParserNotifyer(){}

    virtual void onResponseHeader(const char* key, const char* value) = 0;


    virtual void notify(VCNHttpParserNotifyKey key, int64_t code, const char* const info = nullptr, int64_t parameter = 0) = 0;
};
enum class VCN_INTERFACE_EXPORT VCNHttpParserHelperKey {
    VCNHttpParserHelperKeyIsProxyUrl = 20000,
    VCNHttpParserHelperKeyIsCustomHeader,
};
class VCN_INTERFACE_EXPORT VCNHttpParserHelper {
public:
    virtual ~VCNHttpParserHelper(){}
    virtual char* getStringValue(VCNHttpParserHelperKey key, int64_t code, const char* const value) = 0;
};
enum class VCN_INTERFACE_EXPORT VCNHttpParserErrorType{
    VCNHttpParserErrorTypeIsTCP = 30000,
    VCNHttpParserErrorTypeIsHTTP,
};
enum class VCN_INTERFACE_EXPORT VCNHttpParserStrategyKey{
    VCNHttpParserStrategyKeyIsEnableNetScheduler = 40000,
    VCNHttpParserStrategyKeyIsMinAllowLoadSpeed,
    VCNHttpParserStrategyKeyIsEnablePreconnect,
};
class VCN_INTERFACE_EXPORT VCNHttpParserStrategy {
public:
    virtual ~VCNHttpParserStrategy() {}
    virtual int getStrategyIntValue(VCNHttpParserStrategyKey key) = 0;
    virtual bool isSpeedException(VCNSocketInfo& info, int64_t costTime, int64_t size) = 0;
    virtual void onError(VCNHttpContext* context, VCNHttpParserErrorType type, int err, const char* extra) = 0;
    virtual void onInfo(VCNHttpContext* context) = 0;
};
class VCN_INTERFACE_EXPORT VCNHttpParserSocketInfoManager{
public:
    virtual ~VCNHttpParserSocketInfoManager() {}
    virtual VCNSocketInfo * getSocketInfoByIp(const char* host, const char* ipList, int port, int lowerProto) = 0;
    virtual VCNSocketInfo * getSocketInfoByHost(const char* host, int port, int lowerProto, const char* customHost, int preferDNSType = -1) = 0;
    virtual bool setSocketInfo(VCNSocketInfo* info) = 0;
};
enum class VCN_INTERFACE_EXPORT VCNHttpParserSetInfoKey{
    VCNHttpParserStrategyKeyIsEnableNetScheduler = 50000,
};
NS_VCN_END