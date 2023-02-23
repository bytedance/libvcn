/*
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 * 
 * This file may have been modified by Bytedance Inc. ("Bytedance Modifications"). 
 * All Bytedance Modifications are Copyright 2023 Bytedance Inc.
 */
#include <stdarg.h>
#include <stdint.h>

#include "config.h"
#include "libutil/atomic.h"
#include "libvcn/vcn_avstring.h"
#include "libvcn/vcn_common.h"
#include "libvcn/vcn_internal.h"
#include "libvcn/vcn_mem.h"
#include "vcn_utils.h"
#include <time.h>
#include "libutil/thread.h"
/*
#include "libavutil/avassert.h"
#include "libavutil/avstring.h"
#include "libavutil/vcn_dict.h"
#include "libavutil/internal.h"
#include "libavutil/mathematics.h"
#include "libavutil/opt.h"
#include "libavutil/parseutils.h"
#include "libavutil/pixdesc.h"
#include "libavutil/time.h"
#include "libavutil/time_internal.h"
#include "libavutil/timestamp.h"

#include "libavcodec/bytestream.h"
#include "libavcodec/internal.h"
#include "libavcodec/raw.h"

#include "audiointerleave.h"
#include "avformat.h"
#include "avio_internal.h"
#include "id3v2.h"
#include "internal.h"
#include "metadata.h"
#if CONFIG_NETWORK
#include "network.h"
#endif
#include "riff.h"
#include "url.h"

#include "libavutil/ffversion.h"*/
//const char av_format_ffversion[] = "FFmpeg version " FFMPEG_VERSION;
static const char *months[12] = {
    "january", "february", "march", "april", "may", "june", "july", "august",
    "september", "october", "november", "december"
};
#if HAVE_PTHREADS || HAVE_W32THREADS || HAVE_OS2THREADS
static int vcn_default_lockmgr_cb(void **arg, enum VCNAVLockOp op)
{
    void * volatile * mutex = arg;
    int err;
    
    switch (op) {
        case VCN_AV_LOCK_CREATE:
            return 0;
        case VCN_AV_LOCK_OBTAIN:
            if (!*mutex) {
                pthread_mutex_t *tmp = vcn_av_malloc(sizeof(pthread_mutex_t));
                if (!tmp)
                    return AVERROR(ENOMEM);
                if ((err = pthread_mutex_init(tmp, NULL))) {
                    vcn_av_free(tmp);
                    return AVERROR(err);
                }
                if (vcn_avpriv_atomic_ptr_cas(mutex, NULL, tmp)) {
                    pthread_mutex_destroy(tmp);
                    vcn_av_free(tmp);
                }
            }
            
            if ((err = pthread_mutex_lock(*mutex)))
                return AVERROR(err);
            
            return 0;
        case VCN_AV_LOCK_RELEASE:
            if ((err = pthread_mutex_unlock(*mutex)))
                return AVERROR(err);
            
            return 0;
        case VCN_AV_LOCK_DESTROY:
            if (*mutex)
                pthread_mutex_destroy(*mutex);
            vcn_av_free(*mutex);
            vcn_avpriv_atomic_ptr_cas(mutex, *mutex, NULL);
            return 0;
    }
    return 1;
}
static int (*vcn_lockmgr_cb)(void **mutex, enum VCNAVLockOp op) = vcn_default_lockmgr_cb;
#else
static int (*vcn_lockmgr_cb)(void **mutex, enum VCNAVLockOp op) = NULL;
#endif

static void *vcn_avformat_mutex;


int vcn_av_lockmgr_register(int (*cb)(void **mutex, enum VCNAVLockOp op))
{
    if (vcn_lockmgr_cb) {
        // There is no good way to rollback a failure to destroy the
        // mutex, so we ignore failures.
        vcn_lockmgr_cb(&vcn_avformat_mutex, VCN_AV_LOCK_DESTROY);
        vcn_lockmgr_cb     = NULL;
        vcn_avformat_mutex = NULL;
    }
    
    if (cb) {
        void *new_avformat_mutex = NULL;
        int err;
        if (err = cb(&new_avformat_mutex, VCN_AV_LOCK_CREATE)) {
            // Ignore failures to destroy the newly created mutex.
            return err > 0 ? AVERROR_UNKNOWN : err;
        }
        vcn_lockmgr_cb     = cb;
        vcn_avformat_mutex = new_avformat_mutex;
    }
    
    return 0;
}

int vcn_avpriv_lock_avformat(void)
{
    if (vcn_lockmgr_cb) {
        if ((*vcn_lockmgr_cb)(&vcn_avformat_mutex, VCN_AV_LOCK_OBTAIN))
            return -1;
    }
    return 0;
}

int vcn_avpriv_unlock_avformat(void)
{
    if (vcn_lockmgr_cb) {
        if ((*vcn_lockmgr_cb)(&vcn_avformat_mutex, VCN_AV_LOCK_RELEASE))
            return -1;
    }
    return 0;
}

void vcn_av_url_split(char *proto, int proto_size,
                  char *authorization, int authorization_size,
                  char *hostname, int hostname_size,
                  int *port_ptr, char *path, int path_size, const char *url)
{
    const char *p, *ls, *ls2, *at, *at2, *col, *brk;
    
    if (port_ptr)
        *port_ptr = -1;
    if (proto_size > 0)
        proto[0] = 0;
    if (authorization_size > 0)
        authorization[0] = 0;
    if (hostname_size > 0)
        hostname[0] = 0;
    if (path_size > 0)
        path[0] = 0;
    
    /* parse protocol */
    if ((p = strchr(url, ':'))) {
        vcn_av_strlcpy(proto, url, FFMIN(proto_size, p + 1 - url));
        p++; /* skip ':' */
        if (*p == '/')
            p++;
        if (*p == '/')
            p++;
    } else {
        /* no protocol means plain filename */
        vcn_av_strlcpy(path, url, path_size);
        return;
    }
    
    /* separate path from hostname */
    ls = strchr(p, '/');
    ls2 = strchr(p, '?');
    if (!ls)
        ls = ls2;
    else if (ls && ls2)
        ls = FFMIN(ls, ls2);
    if (ls)
        vcn_av_strlcpy(path, ls, path_size);
    else
        ls = &p[strlen(p)];  // XXX
    
    /* the rest is hostname, use that to parse auth/port */
    if (ls != p) {
        /* authorization (user[:pass]@hostname) */
        at2 = p;
        while ((at = strchr(p, '@')) && at < ls) {
            vcn_av_strlcpy(authorization, at2,
                       FFMIN(authorization_size, at + 1 - at2));
            p = at + 1; /* skip '@' */
        }
        
        if (*p == '[' && (brk = strchr(p, ']')) && brk < ls) {
            /* [host]:port */
            vcn_av_strlcpy(hostname, p + 1,
                       FFMIN(hostname_size, brk - p));
            if (brk[1] == ':' && port_ptr)
                *port_ptr = atoi(brk + 2);
        } else if ((col = strchr(p, ':')) && col < ls) {
            vcn_av_strlcpy(hostname, p,
                       FFMIN(col + 1 - p, hostname_size));
            if (port_ptr)
                *port_ptr = atoi(col + 1);
        } else
            vcn_av_strlcpy(hostname, p,
                       FFMIN(ls + 1 - p, hostname_size));
    }
}

void vcn_av_url_split_hostname(char *hostname, int hostname_size, int *port_ptr, const char *url)
{
    const char *p, *ls, *ls2, *at, *at2, *col, *brk;
    
    if (port_ptr)
        *port_ptr = -1;
    if (hostname_size > 0)
        hostname[0] = 0;
    
    /* parse protocol */
    if ((p = strchr(url, ':'))) {
        p++; /* skip ':' */
        if (*p == '/')
            p++;
        if (*p == '/')
            p++;
    } else {
        /* no protocol means plain filename */
        p = url;
    }
    
    /* separate path from hostname */
    ls = strchr(p, '/');
    ls2 = strchr(p, '?');
    if (!ls)
        ls = ls2;
    else if (ls && ls2)
        ls = FFMIN(ls, ls2);
    if (!ls)
        ls = &p[strlen(p)];  // XXX
    
    /* the rest is hostname, use that to parse auth/port */
    if (ls != p) {
        /* authorization (user[:pass]@hostname) */
        at2 = p;
        while ((at = strchr(p, '@')) && at < ls) {
            p = at + 1; /* skip '@' */
        }
        
        if (*p == '[' && (brk = strchr(p, ']')) && brk < ls) {
            /* [host]:port */
            vcn_av_strlcpy(hostname, p + 1,
                       FFMIN(hostname_size, brk - p));
            if (brk[1] == ':' && port_ptr)
                *port_ptr = atoi(brk + 2);
        } else if ((col = strchr(p, ':')) && col < ls) {
            vcn_av_strlcpy(hostname, p,
                       FFMIN(col + 1 - p, hostname_size));
            if (port_ptr)
                *port_ptr = atoi(col + 1);
        } else
            vcn_av_strlcpy(hostname, p,
                       FFMIN(ls + 1 - p, hostname_size));
    }
}

void vcn_parse_key_value(const char *str, ff_parse_key_val_cb callback_get_buf,void *context)
{
    const char *ptr = str;
    
    /* Parse key=value pairs. */
    for (;;) {
        const char *key;
        char *dest = NULL, *dest_end;
        int key_len, dest_len = 0;
        
        /* Skip whitespace and potential commas. */
        while (*ptr && (av_isspace(*ptr) || *ptr == ','))
            ptr++;
        if (!*ptr)
            break;
        
        key = ptr;
        
        if (!(ptr = strchr(key, '=')))
            break;
        ptr++;
        key_len = ptr - key;
        
        callback_get_buf(context, key, key_len, &dest, &dest_len);
        dest_end = dest + dest_len - 1;
        
        if (*ptr == '\"') {
            ptr++;
            while (*ptr && *ptr != '\"') {
                if (*ptr == '\\') {
                    if (!ptr[1])
                        break;
                    if (dest && dest < dest_end)
                        *dest++ = ptr[1];
                    ptr += 2;
                } else {
                    if (dest && dest < dest_end)
                        *dest++ = *ptr;
                    ptr++;
                }
            }
            if (*ptr == '\"')
                ptr++;
        } else {
            for (; *ptr && !(av_isspace(*ptr) || *ptr == ','); ptr++)
                if (dest && dest < dest_end)
                    *dest++ = *ptr;
        }
        if (dest)
            *dest = 0;
    }
}
char *vcn_data_to_hex(char *buff, const uint8_t *src, int s, int lowercase)
{
    int i;
    static const char hex_table_uc[16] = { '0', '1', '2', '3',
        '4', '5', '6', '7',
        '8', '9', 'A', 'B',
        'C', 'D', 'E', 'F' };
    static const char hex_table_lc[16] = { '0', '1', '2', '3',
        '4', '5', '6', '7',
        '8', '9', 'a', 'b',
        'c', 'd', 'e', 'f' };
    const char *hex_table = lowercase ? hex_table_lc : hex_table_uc;
    
    for (i = 0; i < s; i++) {
        buff[i * 2]     = hex_table[src[i] >> 4];
        buff[i * 2 + 1] = hex_table[src[i] & 0xF];
    }
    
    return buff;
}
//from parseutils.c
int vcn_av_find_info_tag(char *arg, int arg_size, const char *tag1, const char *info)
{
    const char *p;
    char tag[128], *q;
    
    p = info;
    if (*p == '?')
        p++;
    for(;;) {
        q = tag;
        while (*p != '\0' && *p != '=' && *p != '&') {
            if ((q - tag) < sizeof(tag) - 1)
                *q++ = *p;
            p++;
        }
        *q = '\0';
        q = arg;
        if (*p == '=') {
            p++;
            while (*p != '&' && *p != '\0') {
                if ((q - arg) < arg_size - 1) {
                    if (*p == '+')
                        *q++ = ' ';
                    else
                        *q++ = *p;
                }
                p++;
            }
        }
        *q = '\0';
        if (!strcmp(tag, tag1))
            return 1;
        if (*p != '&')
            break;
        p++;
    }
    return 0;
}
/* get a positive number between n_min and n_max, for a maximum length
 of len_max. Return -1 if error. */
static int date_get_num(const char **pp,
                        int n_min, int n_max, int len_max)
{
    int i, val, c;
    const char *p;
    
    p = *pp;
    val = 0;
    for(i = 0; i < len_max; i++) {
        c = *p;
        if (!av_isdigit(c))
            break;
        val = (val * 10) + c - '0';
        p++;
    }
    /* no number read ? */
    if (p == *pp)
        return -1;
    if (val < n_min || val > n_max)
        return -1;
    *pp = p;
    return val;
}

static int date_get_month(const char **pp) {
    int i = 0;
    for (; i < 12; i++) {
        if (!vcn_av_strncasecmp(*pp, months[i], 3)) {
            const char *mo_full = months[i] + 3;
            int len = strlen(mo_full);
            *pp += 3;
            if (len > 0 && !vcn_av_strncasecmp(*pp, mo_full, len))
                *pp += len;
            return i;
        }
    }
    return -1;
}
char *vcn_av_small_strptime(const char *p, const char *fmt, struct tm *dt)
{
    int c, val;
    
    while((c = *fmt++)) {
        if (c != '%') {
            if (av_isspace(c))
                for (; *p && av_isspace(*p); p++);
            else if (*p != c)
                return NULL;
            else p++;
            continue;
        }
        
        c = *fmt++;
        switch(c) {
            case 'H':
            case 'J':
                val = date_get_num(&p, 0, c == 'H' ? 23 : INT_MAX, 2);
                
                if (val == -1)
                    return NULL;
                dt->tm_hour = val;
                break;
            case 'M':
                val = date_get_num(&p, 0, 59, 2);
                if (val == -1)
                    return NULL;
                dt->tm_min = val;
                break;
            case 'S':
                val = date_get_num(&p, 0, 59, 2);
                if (val == -1)
                    return NULL;
                dt->tm_sec = val;
                break;
            case 'Y':
                val = date_get_num(&p, 0, 9999, 4);
                if (val == -1)
                    return NULL;
                dt->tm_year = val - 1900;
                break;
            case 'm':
                val = date_get_num(&p, 1, 12, 2);
                if (val == -1)
                    return NULL;
                dt->tm_mon = val - 1;
                break;
            case 'd':
                val = date_get_num(&p, 1, 31, 2);
                if (val == -1)
                    return NULL;
                dt->tm_mday = val;
                break;
            case 'T':
                p = vcn_av_small_strptime(p, "%H:%M:%S", dt);
                if (!p)
                    return NULL;
                break;
            case 'b':
            case 'B':
            case 'h':
                val = date_get_month(&p);
                if (val == -1)
                    return NULL;
                dt->tm_mon = val;
                break;
            case '%':
                if (*p++ != '%')
                    return NULL;
                break;
            default:
                return NULL;
        }
    }
    
    return (char*)p;
}
time_t vcn_av_timegm(struct tm *tm)
{
    time_t t;
    
    int y = tm->tm_year + 1900, m = tm->tm_mon + 1, d = tm->tm_mday;
    
    if (m < 3) {
        m += 12;
        y--;
    }
    
    t = 86400LL *
    (d + (153 * m - 457) / 5 + 365 * y + y / 4 - y / 100 + y / 400 - 719469);
    
    t += 3600 * tm->tm_hour + 60 * tm->tm_min + tm->tm_sec;
    
    return t;
}

