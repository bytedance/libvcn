/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */
#include "VCNTime.h"
NS_VCN_BEGIN
int64_t vcnGetCurrentTime() {
    struct timeval te;
    gettimeofday(&te, NULL); // get current time
    int64_t milliseconds = te.tv_sec*1000LL + te.tv_usec/1000LL; // caculate milliseconds
    // printf("milliseconds: %lld\n", milliseconds);
    return milliseconds;
}

int64_t vcnGetCurrentTimeMicros() {
    struct timeval te;
    gettimeofday(&te, NULL); // get current time
    return te.tv_sec*1000000LL + te.tv_usec; // caculate microsecond
}
NS_VCN_END