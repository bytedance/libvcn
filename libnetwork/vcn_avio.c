/*
 * unbuffered I/O
 * Copyright (c) 2001 Fabrice Bellard
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



#include "libutil/vcn_assert.h"
#include "vcn_error.h"
#include "vcn_log.h"
#include "vcn_opt.h"
#include "vcn_mem.h"
#include "vcn_time.h"
#include "libutil/crc.h"
#include "vcn_avstring.h"
#include "os_support.h"
#include <limits.h>
#include "vcn_url.h"
#include "vcn_avio.h"
#include "network.h"
#include<unistd.h>
static const char *vcn_VCNURLContext_to_name(void *ptr)
{
    VCNURLContext *h = (VCNURLContext *)ptr;
    if (h->prot)
        return h->prot->name;
    else
        return "NULL";
}
static int64_t vcn_url_get_log_handle(void * ptr) {
    VCNURLContext* s = ptr;
    return s->log_handle;
}
static void *vcn_VCNURLContext_child_next(void *obj, void *prev)
{
    VCNURLContext *h = obj;
    if (!prev && h->priv_data && h->prot->priv_data_class)
        return h->priv_data;
    return NULL;
}
#define OFFSET(x) offsetof(VCNURLContext,x)
#define E AV_OPT_FLAG_ENCODING_PARAM
#define D AV_OPT_FLAG_DECODING_PARAM
static const AVOption options[] = {
    {"protocol_whitelist", "List of protocols that are allowed to be used", OFFSET(protocol_whitelist), AV_OPT_TYPE_STRING, { .str = NULL },  CHAR_MIN, CHAR_MAX, D },
    {"protocol_blacklist", "List of protocols that are not allowed to be used", OFFSET(protocol_blacklist), AV_OPT_TYPE_STRING, { .str = NULL },  CHAR_MIN, CHAR_MAX, D },
    {"rw_timeout", "Timeout for IO operations (in microseconds)", offsetof(VCNURLContext, rw_timeout), AV_OPT_TYPE_INT64, { .i64 = 0 }, 0, INT64_MAX, AV_OPT_FLAG_ENCODING_PARAM | AV_OPT_FLAG_DECODING_PARAM },
    {"log_handle", "set log handle for log", OFFSET(log_handle), AV_OPT_TYPE_UINT64, { .i64 = 0 }, 0, UINT64_MAX, .flags = D|E },
    { NULL }
};
const AVClass vcn_url_context_class = {
    .class_name       = "VCNURLContext",
    .item_name        = vcn_VCNURLContext_to_name,
    .option           = options,
    .version          = LIBAVUTIL_VERSION_INT,
    .child_next       = vcn_VCNURLContext_child_next,
    .child_class_next = vcn_VCNURLContext_child_class_next,
    .get_log_handle = vcn_url_get_log_handle,
};

static int vcn_url_alloc_for_protocol(VCNURLContext **puc, const URLProtocol *up,
                                  const char *filename, int flags,
                                  const AVNetIOInterruptCB *int_cb)
{
    VCNURLContext *uc;
    int err;
    
#if CONFIG_NETWORK
    if (up->flags & URL_PROTOCOL_FLAG_NETWORK && !vcn_network_init()){
        //vcn_av_trace(NULL,AVERROR(EIO),"AVERROR(EIO)");
        return AVERROR(EIO);
    }
#endif
    if ((flags & AVIO_FLAG_READ) && !up->url_read) {
        vcn_av_log(NULL, AV_LOG_ERROR,
        "Impossible to open the '%s' protocol for reading\n", up->name);
        return AVERROR(EIO);
    }
    if ((flags & AVIO_FLAG_WRITE) && !up->url_write) {
        vcn_av_log(NULL, AV_LOG_ERROR,
        "Impossible to open the '%s' protocol for writing\n", up->name);
        return AVERROR(EIO);
    }
    uc = vcn_av_mallocz(sizeof(VCNURLContext) + strlen(filename) + 1);
    if (!uc) {
        err = AVERROR(ENOMEM);
        //vcn_av_trace(NULL,err,"AVERROR(ENOMEM)");
        goto fail;
    }
    uc->av_class = &vcn_url_context_class;
    uc->filename = (char *)&uc[1];
    strcpy(uc->filename, filename);
    uc->prot            = up;
    uc->flags           = flags;
    uc->is_streamed     = 0; /* default = not streamed */
    uc->max_packet_size = 0; /* default: stream file */
    if (up->priv_data_size) {
        uc->priv_data = vcn_av_mallocz(up->priv_data_size);
        if (!uc->priv_data) {
            err = AVERROR(ENOMEM);
            //vcn_av_trace(NULL,err,"AVERROR(ENOMEM)");
            goto fail;
        }
        if (up->priv_data_class) {
            int proto_len= strlen(up->name);
            char *start = strchr(uc->filename, ',');
            *(const AVClass **)uc->priv_data = up->priv_data_class;
            vcn_av_opt_set_defaults(uc->priv_data);
            if(!strncmp(up->name, uc->filename, proto_len) && uc->filename + proto_len == start){
                int ret= 0;
                char *p= start;
                char sep= *++p;
                char *key, *val;
                p++;
                
                if (strcmp(up->name, "subfile")){
                    ret = AVERROR(EINVAL);
                    //vcn_av_trace(uc,ret,"AVERROR(EINVAL)");
                }
                
                while(ret >= 0 && (key= strchr(p, sep)) && p<key && (val = strchr(key+1, sep))){
                    *val= *key= 0;
                    if (strcmp(p, "start") && strcmp(p, "end")) {
                        ret = AVERROR_OPTION_NOT_FOUND;
                        //vcn_av_trace(uc,ret,"AVERROR_OPTION_NOT_FOUND");
                    } else
                        ret= vcn_av_opt_set(uc->priv_data, p, key+1, 0);
                    if (ret == AVERROR_OPTION_NOT_FOUND) {
                        vcn_av_log(uc, AV_LOG_ERROR, "Key '%s' not found.\n", p);
                    }
                    *val= *key= sep;
                    p= val+1;
                }
                if(ret<0 || p!=key){
                    vcn_av_log(uc, AV_LOG_ERROR, "Error parsing options string %s\n", start);
                    vcn_av_freep(&uc->priv_data);
                    vcn_av_freep(&uc);
                    err = AVERROR(EINVAL);
                    goto fail;
                }
                memmove(start, key+1, strlen(key));
            }
        }
    }
    if (int_cb)
        uc->interrupt_callback = *int_cb;
    
    *puc = uc;
    return 0;
fail:
    *puc = NULL;
    if (uc)
        vcn_av_freep(&uc->priv_data);
    vcn_av_freep(&uc);
#if CONFIG_NETWORK
    if (up->flags & URL_PROTOCOL_FLAG_NETWORK)
        vcn_network_close();
#endif
    return err;
}
int vcn_ff_check_interrupt(AVNetIOInterruptCB *cb)
{
    int ret;
    if (cb && cb->callback && (ret = cb->callback(cb->opaque)))
        return ret;
    return 0;
}

int vcn_url_connect(VCNURLContext *uc, AVDictionary **options)
{
    int err;
    AVDictionary *tmp_opts = NULL;
    AVDictionaryEntry *e;
    
    if (!options)
        options = &tmp_opts;
    
    // Check that VCNURLContext was initialized correctly and lists are matching if set
    av_assert0(!(e=vcn_av_dict_get(*options, "protocol_whitelist", NULL, 0)) ||
               (uc->protocol_whitelist && !strcmp(uc->protocol_whitelist, e->value)));
    av_assert0(!(e=vcn_av_dict_get(*options, "protocol_blacklist", NULL, 0)) ||
               (uc->protocol_blacklist && !strcmp(uc->protocol_blacklist, e->value)));
    
    if (uc->protocol_whitelist && av_match_list(uc->prot->name, uc->protocol_whitelist, ',') <= 0) {
        vcn_av_log(uc, AV_LOG_ERROR, "Protocol not on whitelist \'%s\'!\n", uc->protocol_whitelist);
        return AVERROR(EINVAL);
    }
    
    if (uc->protocol_blacklist && av_match_list(uc->prot->name, uc->protocol_blacklist, ',') > 0) {
        vcn_av_log(uc, AV_LOG_ERROR, "Protocol blacklisted \'%s\'!\n", uc->protocol_blacklist);
        return AVERROR(EINVAL);
    }
    
    if (!uc->protocol_whitelist && uc->prot->default_whitelist) {
        vcn_av_log(uc, AV_LOG_DEBUG, "Setting default whitelist '%s'\n", uc->prot->default_whitelist);
        uc->protocol_whitelist = vcn_av_strdup(uc->prot->default_whitelist);
        if (!uc->protocol_whitelist) {
            //vcn_av_trace(uc,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
            return AVERROR(ENOMEM);
        }
    } else if (!uc->protocol_whitelist)
        vcn_av_log(uc, AV_LOG_DEBUG, "No default whitelist set\n"); // This should be an error once all declare a default whitelist
    
    if ((err = vcn_av_dict_set(options, "protocol_whitelist", uc->protocol_whitelist, 0)) < 0) {
        //vcn_av_trace(uc,err,"err:%d", err);
        return err;
    }
    if ((err = vcn_av_dict_set(options, "protocol_blacklist", uc->protocol_blacklist, 0)) < 0) {
        //vcn_av_trace(uc,err,"err:%d", err);
        return err;
    }
    
    err =
    uc->prot->url_open2 ? uc->prot->url_open2(uc,
                                              uc->filename,
                                              uc->flags,
                                              options) :
    uc->prot->url_open(uc, uc->filename, uc->flags);
    
    vcn_av_dict_set(options, "protocol_whitelist", NULL, 0);
    vcn_av_dict_set(options, "protocol_blacklist", NULL, 0);
    
    if (err) {
        //vcn_av_trace(uc,err,"err:%d", err);
        return err;
    }
    uc->is_connected = 1;
    /* We must be careful here as vcn_url_seek() could be slow,
     * for example for http */
    if ((uc->flags & AVIO_FLAG_WRITE) || !strcmp(uc->prot->name, "file"))
        if (!uc->is_streamed && vcn_url_seek(uc, 0, SEEK_SET) < 0)
            uc->is_streamed = 1;
    return 0;
}

int vcn_url_accept(VCNURLContext *s, VCNURLContext **c)
{
    av_assert0(!*c);
    if (s->prot->url_accept)
        return s->prot->url_accept(s, c);
    //vcn_av_trace(s,AVERROR(EBADF),"AVERROR(EBADF)");
    return AVERROR(EBADF);
}

int vcn_url_handshake(VCNURLContext *c)
{
    int ret;
    if (c->prot->url_handshake) {
        ret = c->prot->url_handshake(c);
        if (ret)
            return ret;
    }
    c->is_connected = 1;
    return 0;
}

static const struct URLProtocol *vcn_url_find_protocol(const char *filename)
{
    const URLProtocol **protocols;
    char proto_str[128], proto_nested[128], *ptr;
    size_t proto_len = strspn(filename, URL_SCHEME_CHARS);
    int i;
    
    if (filename[proto_len] != ':' &&
        (strncmp(filename, "subfile,", 8) || !strchr(filename + proto_len + 1, ':')) ||
        is_dos_path(filename))
        strcpy(proto_str, "file");
    else
        vcn_av_strlcpy(proto_str, filename,
                   FFMIN(proto_len + 1, sizeof(proto_str)));
    
    if ((ptr = strchr(proto_str, ',')))
        *ptr = '\0';
    vcn_av_strlcpy(proto_nested, proto_str, sizeof(proto_nested));
    if ((ptr = strchr(proto_nested, '+')))
        *ptr = '\0';
    
    protocols = vcn_url_get_protocols(NULL, NULL);
    if (!protocols)
        return NULL;
    for (i = 0; protocols[i]; i++) {
        const URLProtocol *up = protocols[i];
        if (!strcmp(proto_str, up->name)) {
            vcn_av_freep(&protocols);
            return up;
        }
        if (up->flags & URL_PROTOCOL_FLAG_NESTED_SCHEME &&
            !strcmp(proto_nested, up->name)) {
            vcn_av_freep(&protocols);
            return up;
        }
    }
    vcn_av_freep(&protocols);
    
    return NULL;
}

int vcn_url_alloc(VCNURLContext **puc, const char *filename, int flags,
                const AVNetIOInterruptCB *int_cb)
{
    const URLProtocol *p = NULL;
    
    p = vcn_url_find_protocol(filename);
    if (p)
        return vcn_url_alloc_for_protocol(puc, p, filename, flags, int_cb);
    
    *puc = NULL;
    if (vcn_av_strstart(filename, "https:", NULL)) {
        vcn_av_log(NULL, AV_LOG_WARNING, "https protocol not found, recompile FFmpeg with "
        "openssl, gnutls "
        "or securetransport enabled.\n");
    }
    //vcn_av_trace(NULL,AVERROR_OPTION_NOT_FOUND,"AVERROR_OPTION_NOT_FOUND");
    return AVERROR_PROTOCOL_NOT_FOUND;
}

int vcn_url_open_whitelist(VCNURLContext **puc, const char *filename, int flags,
                         const AVNetIOInterruptCB *int_cb, AVDictionary **options,
                         const char *whitelist, const char* blacklist,
                         VCNURLContext *parent)
{
    AVDictionary *tmp_opts = NULL;
    AVDictionaryEntry *e;
    int ret = vcn_url_alloc(puc, filename, flags, int_cb);
    if (ret < 0) {
        //vcn_av_trace(NULL,ret,"ret:%d", ret);
        return ret;
    }
    if (parent)
        vcn_av_opt_copy(*puc, parent);
    if (options &&
        (ret = vcn_av_opt_set_dict(*puc, options)) < 0)
        goto fail;
    if (options && (*puc)->prot->priv_data_class &&
        (ret = vcn_av_opt_set_dict((*puc)->priv_data, options)) < 0){
        //vcn_av_trace(NULL,ret,"ret:%d", ret);
        goto fail;
    }
    
    if (!options)
        options = &tmp_opts;
    
    av_assert0(!whitelist ||
               !(e=vcn_av_dict_get(*options, "protocol_whitelist", NULL, 0)) ||
               !strcmp(whitelist, e->value));
    av_assert0(!blacklist ||
               !(e=vcn_av_dict_get(*options, "protocol_blacklist", NULL, 0)) ||
               !strcmp(blacklist, e->value));
    
    if ((ret = vcn_av_dict_set(options, "protocol_whitelist", whitelist, 0)) < 0) {
        //vcn_av_trace(NULL,ret,"ret:%d", ret);
        goto fail;
    }
    
    if ((ret = vcn_av_dict_set(options, "protocol_blacklist", blacklist, 0)) < 0) {
        //vcn_av_trace(NULL,ret,"ret:%d", ret);
        goto fail;
    }
    
    if ((ret = vcn_av_opt_set_dict(*puc, options)) < 0) {
        //vcn_av_trace(NULL,ret,"ret:%d", ret);
        goto fail;
    }
    
    ret = vcn_url_connect(*puc, options);
    
    if (!ret)
        return 0;
fail:
    vcn_url_close(*puc);
    *puc = NULL;
    return ret;
}


static inline int retry_transfer_wrapper(VCNURLContext *h, uint8_t *buf,
                                         int size, int size_min,
                                         int (*transfer_func)(VCNURLContext *h,
                                                              uint8_t *buf,
                                                              int size))
{
    int ret, len;
    int fast_retries = 5;
    int64_t wait_since = 0;
    
    len = 0;
    while (len < size_min) {
        if (vcn_ff_check_interrupt(&h->interrupt_callback)) {
            return AVERROR_EXIT;
        }
        ret = transfer_func(h, buf + len, size - len);
        if (ret == AVERROR(EINTR)){
            continue;
        }
        if (h->flags & AVIO_FLAG_NONBLOCK)
            return ret;
        if (ret == AVERROR(EAGAIN)) {
            ret = 0;
            if (fast_retries) {
                fast_retries--;
            } else {
                if (h->rw_timeout) {
                    if (!wait_since)
                        wait_since = vcn_av_gettime_relative();
                    else if (vcn_av_gettime_relative() > wait_since + h->rw_timeout) {
                        //vcn_av_trace(h,AVERROR(EIO),"AVERROR(EIO)");
                        return AVERROR(EIO);
                    }
                }
                vcn_av_usleep(1000);
            }
        } else if (ret < 1){
            //vcn_av_trace(h,ret,"ret:%d", ret);
            return (ret < 0 && ret != AVERROR_EOF) ? ret : len;
        }
        if (ret){
            fast_retries = FFMAX(fast_retries, 2);
            wait_since = 0;
        }
        len += ret;
    }
    return len;
}

int vcn_url_read(VCNURLContext *h, unsigned char *buf, int size)
{
    if (!(h->flags & AVIO_FLAG_READ)) {
        //vcn_av_trace(h,AVERROR(EIO),"AVERROR(EIO)");
        return AVERROR(EIO);
    }
    return retry_transfer_wrapper(h, buf, size, 1, h->prot->url_read);
}
int vcn_url_read_complete(VCNURLContext *h, unsigned char *buf, int size)
{
    if (!(h->flags & AVIO_FLAG_READ)){
        //vcn_av_trace(h,AVERROR(EIO),"AVERROR(EIO)");
        return AVERROR(EIO);
    }
    return retry_transfer_wrapper(h, buf, size, size, h->prot->url_read);
}

int vcn_url_write(VCNURLContext *h, const unsigned char *buf, int size)
{
    if (!(h->flags & AVIO_FLAG_WRITE)){
        //vcn_av_trace(h,AVERROR(EIO),"AVERROR(EIO)");
        return AVERROR(EIO);
    }
    /* avoid sending too big packets */
    if (h->max_packet_size && size > h->max_packet_size){
        //vcn_av_trace(h,AVERROR(EIO),"AVERROR(EIO)");
        return AVERROR(EIO);
    }
    
    return retry_transfer_wrapper(h, (unsigned char *)buf, size, size,
                                  (int (*)(struct VCNURLContext *, uint8_t *, int))
                                  h->prot->url_write);
}
int64_t vcn_url_seek(VCNURLContext *h, int64_t pos, int whence)
{
    int64_t ret;
    
    if (!h->prot->url_seek){
        //vcn_av_trace(h,AVERROR(ENOSYS),"AVERROR(ENOSYS)");
        return AVERROR(ENOSYS);
    }
    ret = h->prot->url_seek(h, pos, whence & ~AVSEEK_FORCE);
    return ret;
}
int vcn_url_closep(VCNURLContext **hh)
{
    VCNURLContext *h= *hh;
    int ret = 0;
    if (!h)
        return 0;     /* can happen when ffurl_open fails */
    
    if (h->is_connected && h->prot->url_close)
        ret = h->prot->url_close(h);
#if CONFIG_NETWORK
    if (h->prot->flags & URL_PROTOCOL_FLAG_NETWORK)
        vcn_network_close();
#endif
    if (h->prot->priv_data_size) {
        if (h->prot->priv_data_class)
            vcn_av_opt_free(h->priv_data);
        vcn_av_freep(&h->priv_data);
    }
    vcn_av_opt_free(h);
    vcn_av_freep(hh);
    return ret;
}

int vcn_url_close(VCNURLContext *h)
{
    return vcn_url_closep(&h);
}

int vcn_url_get_file_handle(VCNURLContext *h)
{
    if (!h->prot->url_get_file_handle)
        return -1;
    return h->prot->url_get_file_handle(h);
}
int vcn_url_shutdown(VCNURLContext *h, int flags)
{
    if (!h || !h->prot || !h->prot->url_shutdown)
        return AVERROR(ENOSYS);
    return h->prot->url_shutdown(h, flags);
}
int vcn_url_get_short_seek(VCNURLContext *h)
{
    if (!h || !h->prot || !h->prot->url_get_short_seek)
        return AVERROR(ENOSYS);
    return h->prot->url_get_short_seek(h);
}
void save_filebox(int write_fd,uint64_t filesize,FileNode *nodes,char *cache_file_key)
{
    int fd             = write_fd;
    int resss= 0;
    int32_t  node_num = 0 ;
    FileNode *head    = nodes;
    FileNode *cur     = head;
    uint8_t *buffer   = NULL;
    int32_t cache_file_key_size = 0;
    int32_t node_buf_size = 0;
    uint32_t head_key     = 0;
    uint32_t head_size = sizeof(uint32_t)*2;
    VCNMFBox box;
    if(write_fd <= 0) {//file is already load finished.
        return;
    }
    while(cur != NULL) {
        node_num++;
        cur = cur->next;
    }
    node_buf_size = FILE_NODE_SIZE * node_num;
    box.num  = node_num;
    box.head = MKTAG('t','t','m','f');
    box.file_size[0] = filesize&0xffffffff;
    box.file_size[1] = filesize>>32;
    box.rv1 = 0;
    box.rv2 = 0;
    buffer = vcn_av_mallocz(node_buf_size);
    
    cur      = head;
    node_num = 0;
    
    while(cur != NULL) {
        memcpy(buffer + node_num * FILE_NODE_SIZE, cur, FILE_NODE_SIZE);
        node_num++;
        cur = cur->next;
    }
    
    box.crc =  av_crc(av_crc_get_table(AV_CRC_16_ANSI), 0, buffer,node_buf_size);
    
    node_buf_size += head_size; //node info size + head
    box.length = sizeof(VCNMFBox)//box size
    + head_size//tail box head and size
    + node_buf_size;//node info
    
    if(cache_file_key != NULL) {
        cache_file_key_size = strlen(cache_file_key) + head_size;
        box.length += cache_file_key_size;
    }
    
    lseek(fd, 0, SEEK_END);
    
    write(fd, &box, sizeof(VCNMFBox));
    
    head_key = MKTAG('m','f','n','i');
    write(fd,&node_buf_size,sizeof(uint32_t));
    write(fd,&head_key,sizeof(uint32_t));
    write(fd, buffer, node_buf_size - head_size);
    
    if(cache_file_key_size > 0) {
        head_key= MKTAG('f','k','e','y');
        write(fd,&cache_file_key_size,sizeof(uint32_t));
        write(fd,&head_key,sizeof(uint32_t));
        resss = write(fd,cache_file_key,cache_file_key_size - head_size);
    }
    write(fd, &box, head_size);
    vcn_av_free(buffer);
}
static unsigned long get_file_size(const char *filename)
{
    struct stat buf;
    if(stat(filename, &buf)<0)
    {
        return 0;
    }
    return (unsigned long)buf.st_size;
}
static int read_filenode_info(FileNode**nodes,uint8_t *buffer,int num)
{
    FileNode     *head = NULL;
    int64_t  file_size = 0;
    FileNode *pre_node = NULL;
    int i = 0;
    for(i=0; i < num; i++) {
        FileNode *new_node = (FileNode *)vcn_av_mallocz(sizeof(FileNode));
        memcpy(new_node,buffer + i * FILE_NODE_SIZE,FILE_NODE_SIZE);
        
        file_size += new_node->node_size;
        new_node->next=NULL;
        
        if(head==NULL) {
            head=new_node;
        }
        
        new_node->prev=pre_node;
        if(pre_node!=NULL) {
            pre_node->next=new_node;
        }
        
        pre_node=new_node;
    }
    
    (*nodes)=head;
    
    return 0;
}
static void free_node_list(FileNode **headp)
{
    FileNode *head = *headp;
    FileNode *node = NULL;
    while(head != NULL){
        node = head;
        head = head->next;
        vcn_av_freep(&node);
    }
    *headp = NULL;
}
int read_filebox(int r_handle,char* file_path,FileNode **nodes,char *cache_file_key,int is_need_truncate)
{
    int rSize         =  0;
    int w_handle      = 0;
    uint8_t *buffer   = NULL;
    int node_buf_size = 0;
    //int flag          = O_RDWR;
    long file_size    = 0;
    uint32_t head_info[2];
    int  head_size    = sizeof(uint32_t)*2;
    
    VCNMFBox box;
   
    if(file_path == NULL) {
        return -1;
    }
    
    file_size = get_file_size(file_path);
    //vcn_av_log(NULL, AV_LOG_WARNING,"file size:%ld",file_size );
    
    rSize = lseek(r_handle,file_size - head_size, SEEK_CUR);
    rSize = read(r_handle, head_info, head_size);
    if(rSize < head_size || head_info[0] <= 0 || head_info[1] != MKTAG('t','t','m','f')) {
        vcn_av_log(NULL, AV_LOG_WARNING,"open fail.rSize:%d,head size:%d,head key:%x",rSize,head_info[0],head_info[1]);
        goto fail;
    }
    
    rSize = lseek(r_handle,file_size - head_info[0], SEEK_SET);
    rSize = read(r_handle,&box,sizeof(VCNMFBox));
    
    if(rSize < sizeof(VCNMFBox) || box.length <= 0 || box.head != MKTAG('t','t','m','f') || box.num == 0) {
        vcn_av_log(NULL, AV_LOG_WARNING,"open fail.rSize:%d,box.length:%d,box.head:%x",rSize,box.length,box.head);
        goto fail;
    }
    
    node_buf_size  = FILE_NODE_SIZE * box.num;
    
    buffer  = vcn_av_mallocz(node_buf_size);
    rSize  = read(r_handle,head_info, head_size);//read mfni
    if(rSize != head_size || (head_info[0] - head_size) != node_buf_size || head_info[1] != MKTAG('m','f','n','i') ) {
        vcn_av_log(NULL, AV_LOG_WARNING,"open fail.rSize:%d,head size:%d,key:%x,node_buf_size:%d",rSize,head_info[0],head_info[1],node_buf_size);
        goto fail;
    }
    rSize = read(r_handle,buffer,node_buf_size);
    vcn_av_log(NULL, AV_LOG_WARNING,"node_buf_size:%d,box.crc:%d,rSize:%d",node_buf_size,box.crc,rSize);
    if(av_crc(av_crc_get_table(AV_CRC_16_ANSI), 0, buffer,node_buf_size) != box.crc) {
        vcn_av_log(NULL, AV_LOG_WARNING,"open fail");
        goto fail;
    }
    
    read_filenode_info(nodes,buffer,box.num);
    
    if(cache_file_key == NULL) {
        goto fail;
    }
    vcn_av_log(NULL, AV_LOG_WARNING,"cache_file_key:%s",cache_file_key);
    if(box.length >  (node_buf_size + sizeof(VCNMFBox)+ head_size)) {
        uint32_t box_info[2];
        int length;
        int mdata_len = box.length -  (node_buf_size + sizeof(VCNMFBox)+ head_size);
        while(mdata_len > 0) {
            rSize = read(r_handle,&box_info,head_size);
            if(rSize <= 0) {
                break;
            }
            mdata_len -= rSize;
            length = box_info[0] - head_size;
            switch (box_info[1]) {
                    case MKTAG('f','k','e','y'):{
                        if(node_buf_size < length) {
                            node_buf_size = vcn_av_reallocp(&buffer,length);
                        } else {
                            node_buf_size = length;
                        }
                        if(buffer == NULL || node_buf_size != length) {
                            vcn_av_log(NULL, AV_LOG_WARNING,"open fail");
                            goto fail;
                        }
                        rSize = read(r_handle,buffer,length);
                        if(rSize != length) {
                            goto fail;
                        }
                        if(length != strlen(cache_file_key)) {
                            vcn_av_log(NULL, AV_LOG_WARNING,"input filekey size:%dnot equal read file_key size:%d",strlen(cache_file_key),length);
                            goto fail;
                        }
                        mdata_len -= rSize;
                        vcn_av_log(NULL, AV_LOG_WARNING,"read cache_file_key:%s",buffer);
                        if(strncmp(cache_file_key,buffer,length) != 0) {
                            vcn_av_log(NULL, AV_LOG_WARNING,"cache_file_key not equal open fail");
                            goto fail;
                        }
                        break;
                    }
                    
                default:
                    rSize = lseek(r_handle,length,SEEK_CUR);
                    if(rSize < 0) {
                        vcn_av_log(NULL, AV_LOG_WARNING,"open fail");
                        goto fail;
                    }
                    mdata_len -= length;
                    break;
            }
        }
    }
    if(is_need_truncate && truncate(file_path, file_size - box.length) != 0) {
        goto fail;
    }
    vcn_av_free(buffer);
    vcn_av_log(NULL, AV_LOG_WARNING,"read file_box success:%s",file_path);
    return 0;
fail:
    free_node_list(nodes);
    vcn_av_log(NULL, AV_LOG_WARNING,"r_handle:%d",r_handle);
    vcn_av_free(buffer);
    return -1;
}




