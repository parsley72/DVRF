/*
* Copyright (C) 2009 - 2010, CyberTAN Corporation
*    
* All Rights Reserved.
* You can redistribute it and/or modify it under the terms of the GPL v2 
*
* THIS SOFTWARE IS OFFERED "AS IS", AND CYBERTAN GRANTS NO WARRANTIES OF ANY 
* KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. CYBERTAN 
* SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS 
* FOR A SPECIFIC PURPOSE OR NON INFRINGEMENT CONCERNING THIS SOFTWARE. 
*/

#ifndef __NLINKD_H__
#define __NLINKD_H__

#include <netinet/in.h>
#include <arpa/inet.h>
#include "code_pattern.h"

#define _DEBUG_		0

#if _DEBUG_
#define tm_dbg(fmt, arg...) fprintf(stderr, "[%s]: " fmt "\n", __FUNCTION__ , ## arg)
#else
#define tm_dbg(fmt, arg...)
#endif

#define ASSERT(x, msg, args...) \
	if(x){ \
		fprintf(stderr, "Error At %s:%d:", __FILE__, __LINE__); \
			fprintf(stderr, msg, ##args); \
			exit(0); \
	}

//#define MAX_URL_SIZE 512
#define MAX_HOST_SIZE 256

typedef struct http_message_st
{
	enum
	{
		HTTP_MSG_ACTION_UNKNOWN = 0,
		HTTP_MSG_ACTION_RELAY,
		HTTP_MSG_ACTION_BLOCK,		//wangfei sync patch from RC4-RC8
		HTTP_MSG_ACTION_WTP_BLOCK,
		HTTP_MSG_ACTION_PC_BLOCK,
		HTTP_MSG_ACTION_REDIRECT,      /* For AV Enforcer */
		HTTP_MSG_ACTION_WHITELIST,     /* IR-B0011870, add white list checking. */
		HTTP_MSG_ACTION_LICENSE_EXPIRED
	} action;

	int blk_idx;
	int policy_num;
#if 0
	const char *host;
	const char *path;
	const char *pszMAC;
#else
	char host[MAX_HOST_SIZE];
	char path[MAX_HOST_SIZE];	
	char pszMAC[20];
#endif
}http_message_t;

#define M_ROUTER	((LINKSYS_MODEL == WRT120N_M10) || (LINKSYS_MODEL == WRT120N_M10V2) || (LINKSYS_MODEL == WRT310NV2_M20) || (LINKSYS_MODEL == WRT310NV2_M20V2))

#define BLOCK_PAGE_ID_WTP	0
#define BLOCK_PAGE_ID_PC	1

#define HTTP_HND_REDIRECT_URL  "http://%s/hndBlock.cgi?url=%s%s&policy=%d&mac=%s&blockpage=%d"
#define HTTP_REDIRECT_URL		"http://%s/tmBlock.cgi?url=%s%s&blockpage=%d&type=%ld&mac=%s"
#define HTTP_HND_FORBIDDEN_HEADER "HTTP/1.1 403 Forbidden"
#define HTTP_WP_REDIRECT_URL  "http://%s:52000/Unsecured.asp?%s%s"


//local declaration
int same_net(struct in_addr ip1,struct in_addr ip2,struct in_addr mask);
int need_block(http_message_t *http_info, char blkpage[], unsigned int srcip);
#ifdef CES_PARENTAL_CONTROL_SUPPORT
#if M_ROUTER 
int wtp_find_match(const char *mac, const char *url);
#endif
#endif


#endif	//__NLINKD_H__

/* get lan ipv6 address */
char lan_ipv6_ipaddr[64];
