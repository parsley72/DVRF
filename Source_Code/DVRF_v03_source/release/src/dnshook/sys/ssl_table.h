
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

#ifndef __SSL_TABLE_H__
#define __SSL_TABLE_H__
#include <linux/list.h>
#include <linux/skbuff.h>

#define MAX_HOST_SIZE	256

struct ssl_entry_t
{
    struct list_head list;
    struct list_head lru;
    unsigned long time_out;

	u_int32_t saddr;
	u_int32_t daddr;

	u_int16_t sport;
	u_int16_t dport;

    atomic_t refcnt;
    rwlock_t lock;

	u_int8_t state;
	u_int8_t can_trust;
	void	*nfconn;

	char host[MAX_HOST_SIZE];
};

struct ssl_table_t
{
    struct list_head hash_list[MAX_HASH_SIZE];
    struct list_head lru_list;
    struct list_head free_list;
    struct ssl_entry_t *entry;
};

int ssl_add(u_int32_t saddr, u_int32_t daddr, char *host, int state);
int ssl_delete(struct ssl_entry_t *s);
int ssl_delete_all(int really);

struct ssl_entry_t *ssl_find(struct iphdr *iph);
struct ssl_entry_t *ssl_find_with_trust(struct iphdr *iph);

int ssl_update_timeout(struct ssl_entry_t *s);
int ssl_update_state(struct ssl_entry_t *s, int state);
int ssl_update_trust(struct ssl_entry_t *s, int result);
int ssl_update_nfconn(struct ssl_entry_t *s, struct sk_buff *skb);

int  ssl_init(void);
void ssl_fini(void);

#endif	//__SSL_TABLE_H__
