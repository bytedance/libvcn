/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */
#pragma once
#define VCN_IS_EMPTY_STRING(s) ((s==nullptr) || (strlen(s)==0))
#define VCN_DELETE_STRING(str) if(str != nullptr){delete str;str = nullptr;}
#define VCN_MEMCPY_STRING(dst,src) if(src != nullptr){\
size_t len = strlen(src);\
if(dst != nullptr){\
delete dst;\
dst = nullptr;}\
if(len > 0){\
dst = new char[len + 1];\
memcpy(dst,src,len);\
dst[len] = 0;\
}}

#define VCN_DELETE_OBJECT(object) if(object != nullptr){delete object;object = nullptr;}

typedef enum LowerProtoType {
    LowerProtoIsInvalid = 0,
    LowerProtoIsTcp = 1,
    LowerProtoIsTLS = 2,
}LowerProtoType;

#include <string>
__attribute__((visibility ("default"))) void vcnUrlSplit(std::string&proto,
              std::string&authorization,
              std::string&hostname,
              int *port_ptr, std::string&path,  std::string&quesryStr, std::string&fragment, const char *url);
