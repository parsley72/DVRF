
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

#ifndef __DNS_TABLE_H__
#define __DNS_TABLE_H__

#include <linux/list.h>
#include <linux/skbuff.h>
#include "decode.h"

#define MAX_HOST_SIZE 256

enum dns_entry_state
{
	DNS_QUERY_RCVD = 0,
	DNS_RESPONSE_RCVD,
};

struct dns_entry_t
{
    struct list_head list;
    struct list_head lru; //last recent use list
    unsigned long time_out;

    u_int32_t cli_addr;	//who invoked this dns query 
  struct my_addr_in svr_addr[MAX_DNS_ANSWER];	//who responsed the dns request
	u_int8_t mac[6];
    
    atomic_t refcnt;
    rwlock_t lock;

	u_int8_t state;
	char dnsname[MAX_HOST_SIZE];
};

struct dns_table_t
{
    struct list_head hash_list[MAX_HASH_SIZE];
    struct list_head lru_list;
    struct list_head free_list;
    struct dns_entry_t *entry;
};

int dns_add( struct dnsrr * tuple );
int dns_delete(struct dns_entry_t *d);
struct dns_entry_t *dns_find(char *dnsname);
int dns_update_timeout(struct dns_entry_t *d);
int dns_update_state(struct dns_entry_t *d, int state);
unsigned int dns_hash(char* str, unsigned int len);


int  dns_init(void);
void dns_fini(void);

#endif	//__DNS_TABLE_H__
