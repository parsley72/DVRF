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

#ifndef __KERNEL__
#define __KERNEL__
#endif
#ifndef MODULE
#define MODULE
#endif
#define LINUX
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/version.h>
#define __CONFIG_IPV6__

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#include <net/netfilter/nf_conntrack.h>
#else
#include <linux/timer.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>
#endif

#ifdef __CONFIG_IPV6__
#include <linux/ipv6.h>
struct tcp_table_t *tcp_table6;
extern int table6_init(void);
#endif

#include "log.h"
#include "decode.h"
#include "tcp_table.h"

static unsigned long check_period = 0;
static rwlock_t tcptable_lock = RW_LOCK_UNLOCKED;
struct tcp_table_t *tcp_table;

static unsigned int tcp_hash(struct iphdr *iph, struct tcphdr *tcph)
{
	return ((iph->saddr + iph->daddr + tcph->source + tcph->dest) % MAX_HASH_SIZE);
}


int tcp_update_timeout(struct tcp_entry_t *t)
{
    tm_write_lock(&t->lock);

    list_move_tail(&t->lru, &tcp_table->lru_list);
    t->time_out = jiffies + MAX_LIFE_TIME;

    tm_write_unlock(&t->lock);

    return 0;
}


int tcp_update_state(struct tcp_entry_t *t, int state)
{
    tm_write_lock(&t->lock);
    t->state = state;
    tm_write_unlock(&t->lock);

    return 0;
}

int tcp_update_nfconn(struct tcp_entry_t *t, struct sk_buff *skb)
{
	int ret = -1;
	enum ip_conntrack_info ctinfo;

    tm_write_lock(&t->lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	if ( NULL != (t->nfconn = nf_ct_get(skb, &ctinfo)) )
#else
	if ( NULL != (t->nfconn = ip_conntrack_get(skb, &ctinfo)) )
#endif	
		ret = 0;
	
    tm_write_unlock(&t->lock);

    return ret;
}

int tcp_delete(struct tcp_entry_t *t)
{
    tm_write_lock(&tcptable_lock);

    list_move(&t->list, &tcp_table->free_list);
    list_del(&t->lru);
    t->time_out = 0;

    tm_write_unlock(&tcptable_lock);
    
    return 0;
}


struct tcp_entry_t *tcp_find(struct iphdr *iph, struct tcphdr *tcph)
{
    struct list_head *p;
    struct tcp_entry_t *t;
    unsigned int hash = tcp_hash(iph, tcph);

    tm_read_lock(&tcptable_lock);

    list_for_each(p, &tcp_table->hash_list[hash])
    {
        t = list_entry(p, struct tcp_entry_t, list);

		if (t->saddr == iph->saddr && t->daddr == iph->daddr &&
			t->sport == tcph->source && t->dport == tcph->dest)
        {
            tm_read_unlock(&tcptable_lock);
            atomic_inc(&t->refcnt);
            return t;
        }
		else if (t->saddr == iph->daddr && t->daddr == iph->saddr &&
			t->sport == tcph->dest && t->dport == tcph->source)
        {
            tm_read_unlock(&tcptable_lock);
            atomic_inc(&t->refcnt);
            return t;
        }
    }

    tm_read_unlock(&tcptable_lock);

    return NULL;
}


int tcp_add(struct iphdr *iph, struct tcphdr *tcph)
{
	struct tcp_entry_t *t;
	struct list_head *p;
	unsigned long next_timeout;
	unsigned int hash = tcp_hash(iph, tcph);

	if (time_after(jiffies, check_period))
	{
		next_timeout = jiffies + MAX_LIFE_TIME;

		tm_write_lock(&tcptable_lock);
		list_for_each(p, &tcp_table->lru_list)
		{
			t = list_entry(p, struct tcp_entry_t, lru);
			if (time_after(jiffies, t->time_out))
			{
				list_move(&t->list, &tcp_table->free_list);
				p = p->prev;
				list_del(&t->lru);
			}
			else
			{
				next_timeout = t->time_out;
				break;
			}
		}
		tm_write_unlock(&tcptable_lock);

		check_period = next_timeout;
	}


	tm_write_lock(&tcptable_lock);
	if (list_empty(&tcp_table->free_list))
	{
		//pk_debug("tcp table is full, delete oldest tcp entry");
		t = list_entry(tcp_table->lru_list.next, struct tcp_entry_t, lru);
		list_move(&t->list, &tcp_table->free_list);
		list_del(&t->lru);
	}

	t = list_entry(tcp_table->free_list.next, struct tcp_entry_t, list);

	list_move(&t->list, &tcp_table->hash_list[hash]);
	list_add_tail(&t->lru, &tcp_table->lru_list);
	t->time_out = jiffies + MAX_LIFE_TIME;

	t->state = STATE_SYN_RCVD;
	t->saddr = iph->saddr;
	t->daddr = iph->daddr;
	
	t->sport = tcph->source;
	t->dport = tcph->dest;
	t->lock = RW_LOCK_UNLOCKED;
	t->nfconn = NULL;

	memset(t->header_buff, 0, MAX_HEADER_SIZE);
	memset(t->blk_page, 0, MAX_URL_LENGTH);
	t->header_idx = 0;
	
	atomic_set(&t->refcnt, 1);
	tm_write_unlock(&tcptable_lock);

	return 0;
}


static int table_init(void)
{
    int i;
    struct tcp_entry_t *t;

    INIT_LIST_HEAD(&tcp_table->free_list);
    INIT_LIST_HEAD(&tcp_table->lru_list);

    for (i = 0; i < MAX_HASH_SIZE; i++)
    {
        INIT_LIST_HEAD(&tcp_table->hash_list[i]);
    }

    for (i = 0; i < MAX_TRACKING_SIZE; i++)
    {
        t = &tcp_table->entry[i];

        list_add_tail(&t->list, &tcp_table->free_list);
        INIT_LIST_HEAD(&t->lru);
        t->time_out = 0;

        t->id = i;

        atomic_set(&t->refcnt, 0);
        t->lock = RW_LOCK_UNLOCKED;

		//tlhhh 2010-7-29.
		t->header_buff = (char *)kmalloc(MAX_HEADER_SIZE, GFP_KERNEL);
		if (t->header_buff == NULL)
		{
			pk_err("kmalloc failed!");
			return -1;
		}
    }
    return 0;
}


int cbt_tcp_init(void)
{
    tcp_table = kmalloc( sizeof(struct tcp_table_t)+sizeof(struct tcp_entry_t)*MAX_TRACKING_SIZE, GFP_KERNEL );
    if (tcp_table == NULL)
    {
        pk_err("init tcp module failed!");
        return -1;
    }

    tcp_table->entry = (struct tcp_entry_t*)((int)tcp_table + sizeof(struct tcp_table_t));
    if (table_init() == -1)
    {
        return -1;
    }
#ifdef __CONFIG_IPV6__
    tcp_table6 = kmalloc( sizeof(struct tcp_table_t) + sizeof(struct tcp_entry_t) * MAX_TRACKING_SIZE, GFP_KERNEL );
    if (tcp_table6 == NULL){
        pk_err("init TCP module failed!");
        return -1;
    }

    tcp_table6->entry = (struct tcp_entry_t*)((int)tcp_table6 + sizeof(struct tcp_table_t));
    if (table6_init() == -1){
        return -1;
    }
#endif
    check_period = jiffies + MAX_LIFE_TIME;
	
	pk_info("init tcp module ..");

    return 0;
}


void cbt_tcp_fini(void)
{
	//tlhhh 2010-8-1. free header_buff if malloced. 
    struct list_head *p;
    struct tcp_entry_t *t;
    int i;

    tm_write_lock(&tcptable_lock);

    for (i = 0; i < MAX_HASH_SIZE; i++)
    {
        list_for_each(p, &tcp_table->hash_list[i])
        {
            t = list_entry(p, struct tcp_entry_t, list);
			if( t->header_buff )
				kfree(t->header_buff);
        }
    }

    list_for_each(p, &tcp_table->free_list)
    {
        t = list_entry(p, struct tcp_entry_t, list);
		if( t->header_buff )
			kfree(t->header_buff);
    }
#ifdef __CONFIG_IPV6__
    ////////////////////////////////////////////////////////
    p = NULL;
    t = NULL;
    for (i = 0; i < MAX_HASH_SIZE; i++)
    {
        list_for_each(p, &tcp_table6->hash_list[i])
        {
			t = list_entry(p, struct tcp_entry_t, list);
			if( t->header_buff )
				kfree(t->header_buff);
        }
    }

    list_for_each(p, &tcp_table6->free_list)
    {
		t = list_entry(p, struct tcp_entry_t, list);
		if( t->header_buff )
			kfree(t->header_buff);		
    }
    ////////////////////////////////////////////////////////
#endif
    tm_write_unlock(&tcptable_lock);

	pk_info("exit tcp module ..");
    kfree(tcp_table);
}

#ifdef __CONFIG_IPV6__
int
table6_init(void)
{
    int i;
    struct tcp_entry_t *t;

    INIT_LIST_HEAD(&tcp_table6->free_list);
    INIT_LIST_HEAD(&tcp_table6->lru_list);

    for (i = 0; i < MAX_HASH_SIZE; i++){
        INIT_LIST_HEAD(&tcp_table6->hash_list[i]);
    }

    for (i = 0; i < MAX_TRACKING_SIZE; i++)
    {
        t = &tcp_table6->entry[i];

        list_add_tail(&t->list, &tcp_table6->free_list);
        INIT_LIST_HEAD(&t->lru);
        t->time_out = 0;

        t->id = i;

        atomic_set(&t->refcnt, 0);
        t->lock = RW_LOCK_UNLOCKED;

		//tlhhh 2010-7-29.
		t->header_buff = (char *)kmalloc(MAX_HEADER_SIZE, GFP_KERNEL);
		if (t->header_buff == NULL){
			pk_err("kmalloc failed!");
			return -1;
		}
    }
    return 0;
}


static unsigned int
tcp_hash6(struct ipv6hdr *iph, struct tcphdr *tcph)
{
	return (( (iph->saddr.s6_addr32[0]+iph->saddr.s6_addr32[1]+iph->saddr.s6_addr32[2]+iph->saddr.s6_addr32[3])+ \
			(iph->daddr.s6_addr32[0]+iph->daddr.s6_addr32[1]+iph->daddr.s6_addr32[2]+iph->daddr.s6_addr32[3])+ \
			tcph->source+tcph->dest ) % MAX_HASH_SIZE);
}


int
tcp_update_timeout6(struct tcp_entry_t *t)
{
    tm_write_lock(&t->lock);

    list_move_tail(&t->lru, &tcp_table6->lru_list);
    t->time_out = jiffies + MAX_LIFE_TIME;

    tm_write_unlock(&t->lock);

    return 0;
}


int
tcp_update_state6(struct tcp_entry_t *t, int state)
{
    tm_write_lock(&t->lock);
    t->state = state;
    tm_write_unlock(&t->lock);

    return 0;
}


int
tcp_delete6(struct tcp_entry_t *t)
{
    tm_write_lock(&tcptable_lock);

    list_move(&t->list, &tcp_table6->free_list);
    list_del(&t->lru);
    t->time_out = 0;

    tm_write_unlock(&tcptable_lock);
    
    return 0;
}


struct tcp_entry_t*
tcp_find6(struct ipv6hdr *iph, struct tcphdr *tcph)
{
    struct list_head *p;
    struct tcp_entry_t *t;
    unsigned int hash = tcp_hash6(iph, tcph);

    tm_read_lock(&tcptable_lock);
    ////////////////////////////////////////////////////////
    list_for_each(p, &tcp_table6->hash_list[hash])
    {
        t = list_entry(p, struct tcp_entry_t, list);
	if (memcmp(&t->saddr6.s6_addr, &iph->saddr.s6_addr, 16)==0 &&
	    memcmp(&t->daddr6.s6_addr, &iph->daddr.s6_addr, 16)==0 &&
	    (t->sport == tcph->source) && (t->dport == tcph->dest))
        {
            tm_read_unlock(&tcptable_lock);
            atomic_inc(&t->refcnt);
            return t;
        }
	else
	if (memcmp(&t->saddr6.s6_addr, &iph->daddr.s6_addr, 16)==0 &&
	    memcmp(&t->daddr6.s6_addr, &iph->saddr.s6_addr, 16)==0 &&
	    (t->sport == tcph->dest) && (t->dport == tcph->source))
        {
            tm_read_unlock(&tcptable_lock);
            atomic_inc(&t->refcnt);
            return t;
        }
    }
    ////////////////////////////////////////////////////////
    tm_read_unlock(&tcptable_lock);

    return NULL;
}


int
tcp_add6(struct ipv6hdr *iph, struct tcphdr *tcph)
{
	struct tcp_entry_t *t;
	struct list_head *p;
	unsigned long next_timeout;
	unsigned int hash = tcp_hash6(iph, tcph);

	if (time_after(jiffies, check_period))
	{
		next_timeout = jiffies + MAX_LIFE_TIME;
		tm_write_lock(&tcptable_lock);
		/////////////////////////////////////////[1]
		list_for_each(p, &tcp_table6->lru_list)
		{
			t = list_entry(p, struct tcp_entry_t, lru);
			if (time_after(jiffies, t->time_out))
			{
				list_move(&t->list, &tcp_table6->free_list);
				p = p->prev;
				list_del(&t->lru);
			}
			else
			{
				next_timeout = t->time_out;
				break;
			}
		}
		////////////////////////////////////////////
		tm_write_unlock(&tcptable_lock);
		check_period = next_timeout;
	}

	tm_write_lock(&tcptable_lock);
	/////////////////////////////////////////////////[2]
	if (list_empty(&tcp_table6->free_list))
	{
		//pk_debug("tcp table is full, delete oldest tcp entry");
		t = list_entry(tcp_table6->lru_list.next, struct tcp_entry_t, lru);
		list_move(&t->list, &tcp_table6->free_list);
		list_del(&t->lru);
	}

	t = list_entry(tcp_table6->free_list.next, struct tcp_entry_t, list);

	list_move(&t->list, &tcp_table6->hash_list[hash]);
	list_add_tail(&t->lru, &tcp_table6->lru_list);
	t->time_out = jiffies + MAX_LIFE_TIME;

	t->state = STATE_SYN_RCVD;
	memcpy(&t->saddr6.s6_addr, &iph->saddr.s6_addr, 16);
	memcpy(&t->daddr6.s6_addr, &iph->daddr.s6_addr, 16);
	
	t->sport = tcph->source;
	t->dport = tcph->dest;
	t->lock = RW_LOCK_UNLOCKED;
	t->nfconn = NULL;

	memset(t->header_buff, 0, MAX_HEADER_SIZE);
	memset(t->blk_page, 0, MAX_URL_LENGTH);
	t->header_idx = 0;
	
	atomic_set(&t->refcnt, 1);
	////////////////////////////////////////////////////
	tm_write_unlock(&tcptable_lock);

	return 0;
}
#endif /* __CONFIG_IPV6__ */
