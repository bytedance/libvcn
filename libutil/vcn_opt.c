/*
 * AVOptions
 * Copyright (c) 2005 Michael Niedermayer <michaelni@gmx.at>
 *
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

/**
 * @file
 * AVOptions
 * @author Michael Niedermayer <michaelni@gmx.at>
 */
#include <stdlib.h>
#include "libvcn/vcn_opt.h"
#include "libvcn/vcn_log.h"
#include "libvcn/vcn_avstring.h"
#include "vcn_eval.h"
#include "libvcn/vcn_error.h"

const AVOption *vcn_av_opt_find(void *obj, const char *name, const char *unit,
                            int opt_flags, int search_flags);

const AVOption *vcn_av_opt_next(const void *obj, const AVOption *last)
{
    const AVClass *class;
    if (!obj)
        return NULL;
    class = *(const AVClass**)obj;
    if (!last && class && class->option && class->option[0].name)
        return class->option;
    if (last && last[1].name)
        return ++last;
    return NULL;
}
static int vcn_read_number(const AVOption *o, const void *dst, double *num, int *den, int64_t *intnum)
{
    switch (o->type) {
        case AV_OPT_TYPE_FLAGS:
            *intnum = *(unsigned int*)dst;
            return 0;
        case AV_OPT_TYPE_BOOL:
        case AV_OPT_TYPE_INT:
            *intnum = *(int *)dst;
            return 0;
        case AV_OPT_TYPE_INT64:
        case AV_OPT_TYPE_UINT64:
            *intnum = *(int64_t *)dst;
            return 0;
        case AV_OPT_TYPE_FLOAT:
            *num = *(float *)dst;
            return 0;
        case AV_OPT_TYPE_DOUBLE:
            *num = *(double *)dst;
            return 0;
        case AV_OPT_TYPE_RATIONAL:
            *intnum = ((AVRational *)dst)->num;
            *den    = ((AVRational *)dst)->den;
            return 0;
        case AV_OPT_TYPE_CONST:
            *num = o->default_val.dbl;
            return 0;
    }
    return AVERROR(EINVAL);
}

static int vcn_write_number(void *obj, const AVOption *o, void *dst, double num, int den, int64_t intnum)
{
    if (o->type != AV_OPT_TYPE_FLAGS &&
        (!den || o->max * den < num * intnum || o->min * den > num * intnum)) {
        num = den ? num * intnum / den : (num && intnum ? INFINITY : NAN);
        vcn_av_log(obj, AV_LOG_ERROR, "Value %f for parameter '%s' out of range [%g - %g]\n",
               num, o->name, o->min, o->max);
        return AVERROR(ERANGE);
    }
    if (o->type == AV_OPT_TYPE_FLAGS) {
        double d = num*intnum/den;
        if (d < -1.5 || d > 0xFFFFFFFF+0.5 || (llrint(d*256) & 255)) {
            vcn_av_log(obj, AV_LOG_ERROR,
                   "Value %f for parameter '%s' is not a valid set of 32bit integer flags\n",num*intnum/den, o->name);
            return AVERROR(ERANGE);
        }
    }
    
    switch (o->type) {
        case AV_OPT_TYPE_BOOL:
        case AV_OPT_TYPE_FLAGS:
        case AV_OPT_TYPE_INT:
            *(int *)dst = llrint(num / den) * intnum;
            break;
	    case AV_OPT_TYPE_INT64:
		{
	        double d = num / den;
	        if (intnum == 1 && d == (double)INT64_MAX) {
	            *(int64_t *)dst = INT64_MAX;
	        } else
	            *(int64_t *)dst = llrint(d) * intnum;
	        break;
		}
	    case AV_OPT_TYPE_UINT64:
		{
		    // NOTE: port from FFMpeg, but it's not compatible with big uint64(when > 2^53)
	        double d = num / den;
	        // We must special case uint64_t here as llrint() does not support values
	        // outside the int64_t range and there is no portable function which does
	        // "INT64_MAX + 1ULL" is used as it is representable exactly as IEEE double
	        // while INT64_MAX is not
	        if (intnum == 1 && d == (double)UINT64_MAX) {
	            *(uint64_t *)dst = UINT64_MAX;
	        } else if (d > INT64_MAX + 1ULL) {
	            *(uint64_t *)dst = (llrint(d - (INT64_MAX + 1ULL)) + (INT64_MAX + 1ULL))*intnum;
	        } else {
	            *(uint64_t *)dst = llrint(d) * intnum;
	        }
	        break;
		}
        case AV_OPT_TYPE_FLOAT:
            *(float *)dst = num * intnum / den;
            break;
        case AV_OPT_TYPE_DOUBLE:
            *(double    *)dst = num * intnum / den;
            break;
        default:
            return AVERROR(EINVAL);
    }
    return 0;
}
static int vcn_hexchar2int(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}
static int vcn_set_string_binary(void *obj, const AVOption *o, const char *val, uint8_t **dst)
{
    int *lendst = (int *)(dst + 1);
    uint8_t *bin, *ptr;
    int len;
    
    vcn_av_freep(dst);
    *lendst = 0;
    
    if (!val || !(len = strlen(val)))
        return 0;
    
    if (len & 1)
        return AVERROR(EINVAL);
    len /= 2;
    
    ptr = bin = vcn_av_malloc(len);
    if (!ptr)
        return AVERROR(ENOMEM);
    while (*val) {
        int a = vcn_hexchar2int(*val++);
        int b = vcn_hexchar2int(*val++);
        if (a < 0 || b < 0) {
            vcn_av_free(bin);
            return AVERROR(EINVAL);
        }
        *ptr++ = (a << 4) | b;
    }
    *dst    = bin;
    *lendst = len;
    
    return 0;
}

static int vcn_set_string(void *obj, const AVOption *o, const char *val, uint8_t **dst)
{
    vcn_av_freep(dst);
    *dst = vcn_av_strdup(val);
    return *dst ? 0 : AVERROR(ENOMEM);
}

#define DEFAULT_NUMVAL(opt) ((opt->type == AV_OPT_TYPE_INT64 || \
opt->type == AV_OPT_TYPE_UINT64 || \
opt->type == AV_OPT_TYPE_CONST || \
opt->type == AV_OPT_TYPE_FLAGS || \
opt->type == AV_OPT_TYPE_INT)     \
? opt->default_val.i64             \
: opt->default_val.dbl)

static int vcn_set_string_number(void *obj, void *target_obj, const AVOption *o, const char *val, void *dst)
{
    // Fix big uint64 to double incorrect during 64bit
    // uint64 only used for handle
    if (o->type == AV_OPT_TYPE_UINT64) {
        uint64_t value = strtoull(val, NULL, 10);
        // vcn_av_log(obj, AV_LOG_TRACE, "val: %s, value : %lx", val, value);
        *(uint64_t *)dst = value;
        // vcn_av_log(obj, AV_LOG_TRACE," dst: %lx", *(uint64_t *)dst);
        return 0;
    }

    int ret = 0;
    if (o->type == AV_OPT_TYPE_RATIONAL || o->type == AV_OPT_TYPE_VIDEO_RATE) {
	    int num, den;
	    char c;
    
	    if (sscanf(val, "%d%*1[:/]%d%c", &num, &den, &c) == 2) {
	        if ((ret = vcn_write_number(obj, o, dst, 1, den, num)) >= 0)
	            return ret;
	        ret = 0;
        }
    }
    
    for (;;) {
        int i = 0;
        char buf[256];
        int cmd = 0;
        double d;
        int64_t intnum = 1;
        
        if (o->type == AV_OPT_TYPE_FLAGS) {
            if (*val == '+' || *val == '-')
                cmd = *(val++);
            for (; i < sizeof(buf) - 1 && val[i] && val[i] != '+' && val[i] != '-'; i++)
                buf[i] = val[i];
            buf[i] = 0;
        }
        
        {
            const AVOption *o_named = vcn_av_opt_find(target_obj, i ? buf : val, o->unit, 0, 0);
            int res;
            int ci = 0;
            double const_values[64];
            const char * const_names[64];
            if (o_named && o_named->type == AV_OPT_TYPE_CONST)
                d = DEFAULT_NUMVAL(o_named);
            else {
                if (o->unit) {
                    for (o_named = NULL; o_named = vcn_av_opt_next(target_obj, o_named); ) {
                        if (o_named->type == AV_OPT_TYPE_CONST &&
                            o_named->unit &&
                            !strcmp(o_named->unit, o->unit)) {
                            if (ci + 6 >= FF_ARRAY_ELEMS(const_values)) {
                                vcn_av_log(obj, AV_LOG_ERROR, "const_values array too small for %s\n", o->unit);
                                return AVERROR_PATCHWELCOME;
                            }
                            const_names [ci  ] = o_named->name;
                            const_values[ci++] = DEFAULT_NUMVAL(o_named);
                        }
                    }
                }
                const_names [ci  ] = "default";
                const_values[ci++] = DEFAULT_NUMVAL(o);
                const_names [ci  ] = "max";
                const_values[ci++] = o->max;
                const_names [ci  ] = "min";
                const_values[ci++] = o->min;
                const_names [ci  ] = "none";
                const_values[ci++] = 0;
                const_names [ci  ] = "all";
                const_values[ci++] = ~0;
                const_names [ci] = NULL;
                const_values[ci] = 0;
                
                res = vcn_av_expr_parse_and_eval(&d, i ? buf : val, const_names,
                                             const_values, NULL, NULL, NULL, NULL, NULL, 0, obj);
                if (res < 0) {
                    vcn_av_log(obj, AV_LOG_ERROR, "Unable to parse option value \"%s\"\n", val);
                    return res;
                }
            }
        }
        if (o->type == AV_OPT_TYPE_FLAGS) {
            vcn_read_number(o, dst, NULL, NULL, &intnum);
            if (cmd == '+')
                d = intnum | (int64_t)d;
            else if (cmd == '-')
                d = intnum &~(int64_t)d;
        }
        
        if ((ret = vcn_write_number(obj, o, dst, d, 1, 1)) < 0)
            return ret;
        val += i;
        if (!i || !*val)
            return 0;
    }
    
    return 0;
}
static int vcn_set_string_bool(void *obj, const AVOption *o, const char *val, int *dst)
{
    int n;
    
    if (!val)
        return 0;
    
    if (!strcmp(val, "auto")) {
        n = -1;
    } else if (av_match_name(val, "true,y,yes,enable,enabled,on")) {
        n = 1;
    } else if (av_match_name(val, "false,n,no,disable,disabled,off")) {
        n = 0;
    } else {
        char *end = NULL;
        n = strtol(val, &end, 10);
        if (val + strlen(val) != end)
            goto fail;
    }
    
    if (n < o->min || n > o->max)
        goto fail;
    
    *dst = n;
    return 0;
    
fail:
    vcn_av_log(obj, AV_LOG_ERROR, "Unable to parse option value \"%s\" as boolean\n", val);
    return AVERROR(EINVAL);
}

void *av_opt_child_next(void *obj, void *prev)
{
    const AVClass *c = *(AVClass **)obj;
    if (c->child_next)
        return c->child_next(obj, prev);
    return NULL;
}
const AVClass *av_opt_child_class_next(const AVClass *parent, const AVClass *prev)
{
    if (parent->child_class_next)
        return parent->child_class_next(prev);
    return NULL;
}

const AVOption *vcn_av_opt_find2(void *obj, const char *name, const char *unit,
                             int opt_flags, int search_flags, void **target_obj)
{
    const AVClass  *c;
    const AVOption *o = NULL;
    
    if(!obj)
        return NULL;
    
    c= *(AVClass**)obj;
    
    if (!c)
        return NULL;
    
    if (search_flags & AV_OPT_SEARCH_CHILDREN) {
        if (search_flags & AV_OPT_SEARCH_FAKE_OBJ) {
            const AVClass *child = NULL;
            while (child = av_opt_child_class_next(c, child))
                if (o = vcn_av_opt_find2(&child, name, unit, opt_flags, search_flags, NULL))
                    return o;
        } else {
            void *child = NULL;
            while (child = av_opt_child_next(obj, child))
                if (o = vcn_av_opt_find2(child, name, unit, opt_flags, search_flags, target_obj))
                    return o;
        }
    }
    
    while (o = vcn_av_opt_next(obj, o)) {
        if (!strcmp(o->name, name) && (o->flags & opt_flags) == opt_flags &&
            ((!unit && o->type != AV_OPT_TYPE_CONST) ||
             (unit  && o->type == AV_OPT_TYPE_CONST && o->unit && !strcmp(o->unit, unit)))) {
                if (target_obj) {
                    if (!(search_flags & AV_OPT_SEARCH_FAKE_OBJ))
                        *target_obj = obj;
                    else
                        *target_obj = NULL;
                }
                return o;
            }
    }
    return NULL;
}
const AVOption *vcn_av_opt_find(void *obj, const char *name, const char *unit,
                            int opt_flags, int search_flags)
{
    return vcn_av_opt_find2(obj, name, unit, opt_flags, search_flags, NULL);
}
int vcn_av_opt_set(void *obj, const char *name, const char *val, int search_flags)
{
    int ret = 0;
    void *dst, *target_obj;
    const AVOption *o = vcn_av_opt_find2(obj, name, NULL, 0, search_flags, &target_obj);
    if (!o || !target_obj)
        return AVERROR_OPTION_NOT_FOUND;
    if (!val && (o->type != AV_OPT_TYPE_STRING &&
                 o->type != AV_OPT_TYPE_PIXEL_FMT && o->type != AV_OPT_TYPE_SAMPLE_FMT &&
                 o->type != AV_OPT_TYPE_IMAGE_SIZE && o->type != AV_OPT_TYPE_VIDEO_RATE &&
                 o->type != AV_OPT_TYPE_DURATION && o->type != AV_OPT_TYPE_COLOR &&
                 o->type != AV_OPT_TYPE_CHANNEL_LAYOUT && o->type != AV_OPT_TYPE_BOOL))
        return AVERROR(EINVAL);
    
    if (o->flags & AV_OPT_FLAG_READONLY)
        return AVERROR(EINVAL);
    
    dst = ((uint8_t *)target_obj) + o->offset;
    switch (o->type) {
        case AV_OPT_TYPE_BOOL:
            return vcn_set_string_bool(obj, o, val, dst);
        case AV_OPT_TYPE_STRING:
            return vcn_set_string(obj, o, val, dst);
        case AV_OPT_TYPE_BINARY:
            return vcn_set_string_binary(obj, o, val, dst);
        case AV_OPT_TYPE_FLAGS:
        case AV_OPT_TYPE_INT:
        case AV_OPT_TYPE_INT64:
        case AV_OPT_TYPE_UINT64:
        case AV_OPT_TYPE_FLOAT:
        case AV_OPT_TYPE_DOUBLE:
        case AV_OPT_TYPE_RATIONAL:
            return vcn_set_string_number(obj, target_obj, o, val, dst);
    }
    
    vcn_av_log(obj, AV_LOG_ERROR, "Invalid option type.\n");
    return AVERROR(EINVAL);
}

void vcn_av_opt_set_defaults2(void *s, int mask, int flags)
{
    const AVOption *opt = NULL;
    while ((opt = vcn_av_opt_next(s, opt))) {
        void *dst = ((uint8_t*)s) + opt->offset;
        
        if ((opt->flags & mask) != flags)
            continue;
        
        if (opt->flags & AV_OPT_FLAG_READONLY)
            continue;
        
        switch (opt->type) {
            case AV_OPT_TYPE_CONST:
                /* Nothing to be done here */
                break;
            case AV_OPT_TYPE_BOOL:
            case AV_OPT_TYPE_FLAGS:
            case AV_OPT_TYPE_INT:
            case AV_OPT_TYPE_INT64:
            case AV_OPT_TYPE_UINT64:
            case AV_OPT_TYPE_DURATION:
            case AV_OPT_TYPE_CHANNEL_LAYOUT:
            case AV_OPT_TYPE_PIXEL_FMT:
            case AV_OPT_TYPE_SAMPLE_FMT:
                vcn_write_number(s, opt, dst, 1, 1, opt->default_val.i64);
                break;
            case AV_OPT_TYPE_DOUBLE:
            case AV_OPT_TYPE_FLOAT: {
                double val;
                val = opt->default_val.dbl;
                vcn_write_number(s, opt, dst, val, 1, 1);
            }
                break;
            case AV_OPT_TYPE_STRING:
                vcn_set_string(s, opt, opt->default_val.str, dst);
                break;
            case AV_OPT_TYPE_BINARY:
                vcn_set_string_binary(s, opt, opt->default_val.str, dst);
                break;
            case AV_OPT_TYPE_DICT:
                /* Cannot set defaults for these types */
                break;
                // default:
                vcn_av_log(s, AV_LOG_DEBUG, "AVOption type %d of option %s not implemented yet\n",opt->type, opt->name);
        }
    }
}

void vcn_av_opt_set_defaults(void *s)
{
    vcn_av_opt_set_defaults2(s, 0, 0);
}
static int vcn_opt_size(enum AVOptionType type)
{
    switch(type) {
        case AV_OPT_TYPE_BOOL:
        case AV_OPT_TYPE_INT:
        case AV_OPT_TYPE_FLAGS:
            return sizeof(int);
        case AV_OPT_TYPE_DURATION:
        case AV_OPT_TYPE_CHANNEL_LAYOUT:
        case AV_OPT_TYPE_INT64:
        case AV_OPT_TYPE_UINT64:
            return sizeof(int64_t);
        case AV_OPT_TYPE_DOUBLE:
            return sizeof(double);
        case AV_OPT_TYPE_FLOAT:
            return sizeof(float);
        case AV_OPT_TYPE_STRING:
            return sizeof(uint8_t*);
        case AV_OPT_TYPE_VIDEO_RATE:
        case AV_OPT_TYPE_RATIONAL:
            return sizeof(AVRational);
        case AV_OPT_TYPE_BINARY:
            return sizeof(uint8_t*) + sizeof(int);
        case AV_OPT_TYPE_IMAGE_SIZE:
            return sizeof(int[2]);
        /*case AV_OPT_TYPE_PIXEL_FMT:
            return sizeof(enum AVPixelFormat);
        case AV_OPT_TYPE_SAMPLE_FMT:
            return sizeof(enum AVSampleFormat);*/ /*this part is not used in network module*/
        case AV_OPT_TYPE_COLOR:
            return 4;
    }
    return AVERROR(EINVAL);
}

int vcn_av_opt_copy(void *dst, const void *src)
{
    const AVOption *o = NULL;
    const AVClass *c;
    int ret = 0;
    
    if (!src)
        return AVERROR(EINVAL);
    
    c = *(AVClass **)src;
    if (!c || c != *(AVClass **)dst)
        return AVERROR(EINVAL);
    
    while ((o = vcn_av_opt_next(src, o))) {
        void *field_dst = (uint8_t *)dst + o->offset;
        void *field_src = (uint8_t *)src + o->offset;
        uint8_t **field_dst8 = (uint8_t **)field_dst;
        uint8_t **field_src8 = (uint8_t **)field_src;
        
        if (o->type == AV_OPT_TYPE_STRING) {
            if (*field_dst8 != *field_src8)
                vcn_av_freep(field_dst8);
            *field_dst8 = vcn_av_strdup(*field_src8);
            if (*field_src8 && !*field_dst8)
                ret = AVERROR(ENOMEM);
        } else if (o->type == AV_OPT_TYPE_BINARY) {
            int len = *(int *)(field_src8 + 1);
            if (*field_dst8 != *field_src8)
                vcn_av_freep(field_dst8);
            *field_dst8 = av_memdup(*field_src8, len);
            if (len && !*field_dst8) {
                ret = AVERROR(ENOMEM);
                len = 0;
            }
            *(int *)(field_dst8 + 1) = len;
        } else if (o->type == AV_OPT_TYPE_CONST) {
            // do nothing
        } else if (o->type == AV_OPT_TYPE_DICT) {
            AVDictionary **sdict = (AVDictionary **) field_src;
            AVDictionary **ddict = (AVDictionary **) field_dst;
            if (*sdict != *ddict)
                vcn_av_dict_free(ddict);
            *ddict = NULL;
            vcn_av_dict_copy(ddict, *sdict, 0);
            if (vcn_av_dict_count(*sdict) != vcn_av_dict_count(*ddict))
                ret = AVERROR(ENOMEM);
        } else {
            int size = vcn_opt_size(o->type);
            if (size < 0)
                ret = size;
            else
                memcpy(field_dst, field_src, size);
        }
    }
    return ret;
}

void vcn_av_opt_free(void *obj)
{
    const AVOption *o = NULL;
    while ((o = vcn_av_opt_next(obj, o))) {
        switch (o->type) {
            case AV_OPT_TYPE_STRING:
            case AV_OPT_TYPE_BINARY:
                vcn_av_freep((uint8_t *)obj + o->offset);
                break;
                
            case AV_OPT_TYPE_DICT:
                vcn_av_dict_free((AVDictionary **)(((uint8_t *)obj) + o->offset));
                break;
                
            default:
                break;
        }
    }
}

int vcn_av_opt_set_dict2(void *obj, AVDictionary **options, int search_flags)
{
    AVDictionaryEntry *t = NULL;
    AVDictionary    *tmp = NULL;
    int ret = 0;
    
    if (!options)
        return 0;
    
    while ((t = vcn_av_dict_get(*options, "", t, AV_DICT_IGNORE_SUFFIX))) {
        ret = vcn_av_opt_set(obj, t->key, t->value, search_flags);
        if (ret == AVERROR_OPTION_NOT_FOUND || strcmp(t->key, "log_handle") == 0 )//change by xiewei
            ret = vcn_av_dict_set(&tmp, t->key, t->value, 0);
        if (ret < 0) {
            vcn_av_log(obj, AV_LOG_ERROR, "Error setting option %s to value %s.\n", t->key, t->value);
            vcn_av_dict_free(&tmp);
            return ret;
        }
        ret = 0;
    }
    vcn_av_dict_free(options);
    *options = tmp;
    return ret;
}
int vcn_av_opt_set_dict(void *obj, AVDictionary **options)
{
    return vcn_av_opt_set_dict2(obj, options, 0);
}


