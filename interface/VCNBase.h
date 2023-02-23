/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */
#pragma once
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#ifdef __cplusplus
#define NS_VCN_BEGIN namespace com{ namespace ss{ namespace mediakit{ namespace vcn{
#define NS_VCN_END  }}}}
#define NS_VCN_CLASS(a) namespace com{ namespace ss{ namespace mediakit{ namespace vcn{class a;}}}}
#define USING_VCN_NS using namespace com::ss::mediakit::vcn;

#else
#define NS_VCN_BEGIN
#define NS_VCN_END
#define USING_VCN_NS

#endif
#define VCN_INTERFACE_EXPORT __attribute__((visibility ("default")))

