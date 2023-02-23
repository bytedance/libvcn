/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */
#pragma once
#include <stdlib.h>
#define VCN_LOG_VERBOSE 0
#define VCN_LOG_DEBUG   1
#define VCN_LOG_INFO    2
#define VCN_LOG_TRACK   3
#define VCN_LOG_KILL    4
#define VCN_LOG_PTR     5
#define VCN_LOG_WARN    6
#define VCN_LOG_ERROR   7
#define __ERROR_INFO__ __FILENAME__,##__FUNCTION__,##__LINE__
#define VCN_LOG_TAG "mediavcn"
#include <stdio.h>
#include <libgen.h>
#include <string.h>
#include <stdint.h>
#if defined(__ANDROID__)
#include <android/log.h>
#else
//#define __OS_LOG__
#endif
#ifdef __cplusplus
extern "C" {
#endif

void vcn_logger_nprintf(int level,const char* tag,const void* p,const char* file,const char* fun,int line,const char* format,...);
void vcn_logger_lprintf(int level,const char* tag,const char* file,const char* fun,int line);
#ifdef __cplusplus
}
#endif
#define __FILENAME__ (strrchr(__FILE__,'/')?strrchr(__FILE__,'/')+1:__FILE__)
#ifdef __DEBUG__
#define VCN_LOGWD(...) vcn_logger_nprintf(VCN_LOG_WARN,VCN_LOG_TAG,nullptr,__FILENAME__,__FUNCTION__,__LINE__,__VA_ARGS__)
    #ifdef __OS_LOG__
        #if defined(__ANDROID__)
            #define VCN_LOGD(...) __android_log_print(VCN_LOG_DEBUG,VCN_LOG_TAG,__VA_ARGS__)
            #define VCN_LOGI(...) __android_log_print(VCN_LOG_INFO,VCN_LOG_TAG,__VA_ARGS__)
            #define VCN_LOGL()    __android_log_print(VCN_LOG_INFO,VCN_LOG_TAG,"<%s,%s,%d>",__FILENAME__,__FUNCTION__,__LINE__)
            #define VCN_LOGK(...) __android_log_print(VCN_LOG_KILL,VCN_LOG_TAG,__VA_ARGS__)
            #define VCN_LOGP(...) __android_log_print(VCN_LOG_KILL,VCN_LOG_TAG,__VA_ARGS__)
            #define VCN_LOGTAGI(TAG,...) __android_log_print(VCN_LOG_KILL,TAG,__VA_ARGS__)
            #define VCN_LOGTAGL(TAG)    __android_log_print(VCN_LOG_KILL,TAG,"<%s,%s,%d>",__FILENAME__,__FUNCTION__,__LINE__)
        #elif defined(__IOS__)
            #define VCN_LOGD(...) printf(__VA_ARGS__)
            #define VCN_LOGI(...) printf(__VA_ARGS__)
            #define VCN_LOGK(...) printf(__VA_ARGS__)
            #define VCN_LOGP(...) printf(__VA_ARGS__)
            #define VCN_LOGL() printf("<%s,%s,%d>",__FILENAME__,__FUNCTION__,__LINE__)
            #define VCN_LOGTAGI(TAG,...) printf(__VA_ARGS__)
            #define VCN_LOGTAGL(TAG) printf("<%s,%s,%d>",__FILENAME__,__FUNCTION__,__LINE__)
        #else
            #define VCN_LOGD(...) printf(__VA_ARGS__)
            #define VCN_LOGI(...) printf(__VA_ARGS__)
            #define VCN_LOGK(...) printf(__VA_ARGS__)
            #define VCN_LOGP(...) printf(__VA_ARGS__)
            #define VCN_LOGTAGI(TAG,...) printf(__VA_ARGS__)
            #define VCN_LOGTAGL(TAG) printf("<%s,%s,%d>",__FILENAME__,__FUNCTION__,__LINE__)
        #endif
    #else
        #define VCN_LOGD(...) vcn_logger_nprintf(VCN_LOG_DEBUG,VCN_LOG_TAG,nullptr,__FILENAME__,__FUNCTION__,__LINE__,__VA_ARGS__)
        #define VCN_LOGI(...) vcn_logger_nprintf(VCN_LOG_INFO,VCN_LOG_TAG,nullptr,__FILENAME__,__FUNCTION__,__LINE__,__VA_ARGS__)
        #define VCN_LOGL()    vcn_logger_lprintf(VCN_LOG_INFO,VCN_LOG_TAG,__FILENAME__,__FUNCTION__,__LINE__)
        #define VCN_LOGK(...) vcn_logger_nprintf(VCN_LOG_KILL,VCN_LOG_TAG,this,__FILENAME__,__FUNCTION__,__LINE__,__VA_ARGS__)
        #if defined(__DEBUG_PTR__)
            #define VCN_LOGP(...) vcn_logger_nprintf(VCN_LOG_PTR,"ttpoint",nullptr,__FILENAME__,__FUNCTION__,__LINE__,__VA_ARGS__)
        #else
            #define VCN_LOGP(...)
        #endif
    #endif
#else
#define VCN_LOGV(...)
#define VCN_LOGD(...)
#define VCN_LOGI(...)
#define VCN_LOGK(...)
#define VCN_LOGL()
#define VCN_LOGP(...)
#define VCN_LOGTAGI(TAG,...)
#define VCN_LOGTAGL(TAG)
#define VCN_LOGWD(...)
#endif
#if defined(__ANDROID__)
    #define VCN_LOGW(...) vcn_logger_nprintf(VCN_LOG_WARN,VCN_LOG_TAG,nullptr,__FILENAME__,__FUNCTION__,__LINE__,__VA_ARGS__)
    #define VCN_LOGW_TAG(...) vcn_logger_nprintf(VCN_LOG_WARN,VCN_LOG_TAG,nullptr,__FILENAME__,__FUNCTION__,__LINE__,__VA_ARGS__)
#elif defined(__IOS__)
    #define VCN_LOGW(...) vcn_logger_nprintf(VCN_LOG_WARN,VCN_LOG_TAG,nullptr,__FILENAME__,__FUNCTION__,__LINE__,__VA_ARGS__)
    #define VCN_LOGW_TAG(TAG,...) vcn_logger_nprintf(VCN_LOG_WARN,TAG,nullptr,__FILENAME__,__FUNCTION__,__LINE__,__VA_ARGS__)
#else
#define VCN_LOGW(...) vcn_logger_nprintf(VCN_LOG_WARN,VCN_LOG_TAG,nullptr,__FILENAME__,__FUNCTION__,__LINE__,__VA_ARGS__)
#define VCN_LOGW_TAG(TAG,...) vcn_logger_nprintf(VCN_LOG_WARN,TAG,nullptr,__FILENAME__,__FUNCTION__,__LINE__,__VA_ARGS__)
#endif


