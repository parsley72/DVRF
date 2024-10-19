
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

#ifndef __TCP_TABLE_H__
#define __TCP_TABLE_H__

#include <linux/list.h>
#include <linux/skbuff.h>

#include "defs.h"

#define MAX_HEADER_SIZE 2048

struct tcp_entry_t
{
    struct list_head list;
    struct list_head lru; //last recent use list
    unsigned long time_out;

    u_int8_t id;
    u_int8_t state;

    u_int32_t saddr;
    u_int32_t daddr;
#ifdef __CONFIG_IPV6__
    struct in6_addr saddr6;
    struct in6_addr daddr6;
#endif
    u_int16_t sport;
    u_int16_t dport;

    atomic_t refcnt;
    rwlock_t lock;
	void	*nfconn;

    char blk_page[MAX_URL_LENGTH];
    char *header_buff;
    unsigned int header_idx;
    struct sk_buff *skb_copy;
};

struct tcp_table_t
{
    struct list_head hash_list[MAX_HASH_SIZE];
    struct list_head lru_list;
    struct list_head free_list;
    struct tcp_entry_t *entry;
};

int tcp_add(struct iphdr *iph, struct tcphdr *tcph);
int tcp_delete(struct tcp_entry_t *t);

struct tcp_entry_t *tcp_find(struct iphdr *iph, struct tcphdr *tcph);
int tcp_update_timeout(struct tcp_entry_t *t);
int tcp_update_state(struct tcp_entry_t *t, int state);
int tcp_update_nfconn(struct tcp_entry_t *t, struct sk_buff *skb);

int  cbt_tcp_init(void);
void cbt_tcp_fini(void);

#ifdef __CONFIG_IPV6__
int tcp_add6(struct ipv6hdr *iph, struct tcphdr *tcph);
int tcp_delete6(struct tcp_entry_t *t);

struct tcp_entry_t *tcp_find6(struct ipv6hdr *iph, struct tcphdr *tcph);
int tcp_update_timeout6(struct tcp_entry_t *t);
int tcp_update_state6(struct tcp_entry_t *t, int state);
#endif
#endif	//__TCP_TABLE_H__
