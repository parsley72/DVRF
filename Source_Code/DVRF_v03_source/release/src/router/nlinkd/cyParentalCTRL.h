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


#ifndef __CYPARENTAL_CTRL_H__
#define __CYPARENTAL_CTRL_H__

#include "nlinkd.h"

int ParetanlCTRL(http_message_t *http_message, unsigned int srcip, int gn_flag);
void initlist(void);
void k_init_tblk(void);
void unblockCTRL(int signo);
#ifdef PARENTAL_CONTROL_ALLOWEDLIST_SUPPORT
int checkWList(const char *mac, const char* incoming);	//add by seal 100923
#endif

int check_unblock(int flag, int policy, const char *mac, const char *url, unsigned long time_now);	//add by seal 100917
//int CheckTimeBlock(const char *mac, unsigned int srcip);	//remove by seal 100907
int CheckTimeBlock(const char *mac, const char *url, unsigned int srcip);	//modify by seal 100907

#define MAX_DOMAIN_NAME_LEN 32	//add by seal 100917
typedef struct unblock_st
{
	unsigned int srcip;
	char mac[18];
	char url[MAX_DOMAIN_NAME_LEN + 1];	//add by seal 100907
	unsigned long secs;
	int policy;
	int flag;	//modify by seal 101009
	struct unblock_st *next; 
} unblock_t;

#define REASON_URL 0x00000100;
#define REASON_TIME 0;

//add by seal 101009	---
#define BLOCK_BY_TIME 0
#define BLOCK_BY_SITE 1
#define BLOCK_BY_CATEGORY 2
//add by seal 101009	+++

#if 0	//for test
#include "debugdef.h"
#else
#undef pdebug
#define pdebug(fmt, arg...)
#undef pwarning
#define pwarning(fmt, arg...)
#endif

#endif	//__CYPARENTAL_CTRL_H__

