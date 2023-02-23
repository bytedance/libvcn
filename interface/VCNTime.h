/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */
#pragma once
#include <sys/time.h>
#include "VCNBase.h"
NS_VCN_BEGIN
int64_t vcnGetCurrentTime();
int64_t vcnGetCurrentTimeMicros();
NS_VCN_END