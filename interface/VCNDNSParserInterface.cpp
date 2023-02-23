/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */
#include "VCNDNSParserInterface.h"
NS_VCN_BEGIN
VCNDNSParserInterface::VCNDNSParserInterface(void *wrapper, void* networkManagerPtr)
:mType(-1){
    
}
VCNDNSParserInterface::~VCNDNSParserInterface() {
    
}
char* VCNDNSParserInterface::parse(const char* hostName, int timeOut,int &type, int& err, int parameter, int preferDNSType) {
    return nullptr;
}
void VCNDNSParserInterface::close() {
    
}
void VCNDNSParserInterface::notify(const char* host, const char* ipList, int64_t expiredTime,int type) {
    
}
NS_VCN_END
