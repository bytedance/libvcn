/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */

#include "VCNLogger.h"
#include <stdio.h>
#include <stdarg.h>

extern "C" {
#include <stdbool.h>
}


#define INFO_SIZE 512

#if defined(__ANDROID__)
#include <android/log.h>
static int gLevel[]={
    ANDROID_LOG_VERBOSE,
    ANDROID_LOG_DEBUG,
    ANDROID_LOG_INFO,
    ANDROID_LOG_DEBUG,//track
    ANDROID_LOG_INFO,//k
    ANDROID_LOG_INFO,//p
    ANDROID_LOG_WARN,
    ANDROID_LOG_ERROR
};
#endif
void vcn_logger_nprintf(int level,const char* tag,const void* pThis,const char* file,const char* fun,int line,const char* format,...){

    char infos[INFO_SIZE];
    va_list args;
    va_start( args, format );
    vsnprintf((char *) infos, INFO_SIZE, format, args);
    va_end( args );
#if defined(__FILELOG__)
    fprintf(gLogFile,"<%p,%s,%s,%d>%s\n",pThis,file,fun,line,infos);
#else
#if defined(__ANDROID__)
    __android_log_print(gLevel[level],tag,"<%p,%s,%s,%d>%s",pThis,file,fun,line,infos);
#else
    printf("<%p,%s,%s,%d>%s\n",pThis,file,fun,line,infos);
#endif
#endif
}
void vcn_logger_lprintf(int level,const char* tag,const char* file,const char* fun,int line) {
#if defined(__FILELOG__)
    fprintf(gLogFile,"<%s,%s,%d>\r\n",file,fun,line);
#else
#if defined(__ANDROID__)
    __android_log_print(gLevel[level],tag,"<%s,%s,%d>",file,fun,line);
#else
    printf("<%s,%s,%d>\r\n",file,fun,line);
#endif
#endif
}