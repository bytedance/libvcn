/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */
#include "VCNUtils.h"
#define URIMIN(a,b) ((a) > (b) ? (b) : (a))
__attribute__((visibility ("default"))) void vcnUrlSplit(std::string&proto,
              std::string&authorization,
              std::string&hostname,
              int *port_ptr, std::string&path,  std::string&quesryStr, std::string&fragment, const char *url)
{
    const char *p, *ls, *ls2, *at, *at2, *col, *brk;

    if (port_ptr)
        *port_ptr = -1;


    /* parse protocol */
    if ((p = strchr(url, ':'))) {
        proto.append((char*)url, p - url);
        //vcn_av_strlcpy(proto, url, FFMIN(proto_size, p + 1 - url));
        p++; /* skip ':' */
        if (*p == '/')
            p++;
        if (*p == '/')
            p++;
    } else {
        /* no protocol means plain filename */
        path.append((char*)url, strlen(url));
        //vcn_av_strlcpy(path, url, path_size);
        return;
    }

    /* separate path from hostname */
    ls = strchr(p, '/');
    ls2 = strchr(p, '?');
    if (!ls)
        ls = ls2;
    else if (ls && ls2)
        ls = URIMIN(ls, ls2);

    if (ls) {
        path.append((char*)ls, strlen(ls));
        //vcn_av_strlcpy(path, ls, path_size);
    }
    else {
        ls = &p[strlen(p)];  // XXX
    }

    /* the rest is hostname, use that to parse auth/port */
    if (ls != p) {
        /* authorization (user[:pass]@hostname) */
        at2 = p;
        while ((at = strchr(p, '@')) && at < ls) {
            authorization.append((char*)at2, at - at2);
            //vcn_av_strlcpy(authorization, at2,
            //FFMIN(authorization_size, at + 1 - at2));
            p = at + 1; /* skip '@' */
        }

        if (*p == '[' && (brk = strchr(p, ']')) && brk < ls) {
            /* [host]:port */
            hostname.append((char*)(p + 1), brk - p - 1);
//            vcn_av_strlcpy(hostname, p + 1,
//                       FFMIN(hostname_size, brk - p));
            if (brk[1] == ':' && port_ptr)
                *port_ptr = atoi(brk + 2);
        } else if ((col = strchr(p, ':')) && col < ls) {
            hostname.append((char*)p, col - p);
//            vcn_av_strlcpy(hostname, p,
//                       FFMIN(col + 1 - p, hostname_size));
            if (port_ptr)
                *port_ptr = atoi(col + 1);
        } else {
            hostname.append((char*)p, ls - p);
//            vcn_av_strlcpy(hostname, p,
//                       FFMIN(ls + 1 - p, hostname_size));
        }
    }
    if (path.length() > 0) {
        size_t off = path.find('?');
        if(off != std::string::npos) {
            quesryStr = path.substr(off+1,path.size()-1);
            path = path.substr(0, off);
        }
    }
    if (quesryStr.length() > 0) {
        size_t off = quesryStr.find('#');
        if(off != std::string::npos) {
            fragment = quesryStr.substr(off+1,quesryStr.size()-1);
            quesryStr = quesryStr.substr(0, off);
        }
    } else if (!path.empty()){
        size_t off = path.find('#');
        if(off != std::string::npos) {
            fragment = path.substr(off+1,quesryStr.size()-1);
            path = path.substr(0, off);
        }
    }
}