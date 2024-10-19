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
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#include <net/netfilter/nf_conntrack.h>
#else
#include <linux/timer.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>
#endif

#include "defs.h"
#include "log.h"
#include "ssl_table.h"


static unsigned long check_period = 0;
static rwlock_t ssltable_lock = RW_LOCK_UNLOCKED; //protect all list_head struct
struct ssl_table_t *ssl_table;

static unsigned int ssl_hash(u_int32_t saddr, u_int32_t daddr)
{   
    return ((saddr + daddr) % MAX_HASH_SIZE);
}           

int ssl_update_timeout(struct ssl_entry_t *s)
{
    tm_write_lock(&s->lock);

    list_move_tail(&s->lru, &ssl_table->lru_list);
    s->time_out = jiffies + MAX_LIFE_TIME;

    tm_write_unlock(&s->lock);

    return 0;
}

int ssl_update_state(struct ssl_entry_t *s, int state)
{
    tm_write_lock(&s->lock);
    s->state = state;
    tm_write_unlock(&s->lock);

    return 0;
}

int ssl_update_nfconn(struct ssl_entry_t *s, struct sk_buff *skb)
{
	int ret = -1;
	enum ip_conntrack_info ctinfo;

    tm_write_lock(&s->lock);
	
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	if ( NULL != (s->nfconn = nf_ct_get(skb, &ctinfo)) )
#else
	if ( NULL != (s->nfconn = ip_conntrack_get(skb, &ctinfo)) )
#endif	
		ret = 0;
	
    tm_write_unlock(&s->lock);

    return ret;
}

/* tlhhh. Routine to set if this conntrack's state can be trusted */
int ssl_update_trust(struct ssl_entry_t *s, int result)
{
    tm_write_lock(&s->lock);
    s->can_trust = result;
    tm_write_unlock(&s->lock);

    return 0;
}

int ssl_delete_all(int really)
{
    int i;
    struct ssl_entry_t *s = NULL;

    tm_write_lock(&ssltable_lock);

    for (i = 0; i < MAX_HASH_SIZE; i++)
    {
		struct list_head *pos, *n;
		
        list_for_each_safe(pos, n, &ssl_table->hash_list[i])
        {
            s = list_entry(pos, struct ssl_entry_t, list);

			if ( s )
			{
				pk_debug("clear ssl tracking[%d], host=%s", i, s->host);
#if 0
				if ( s->host[0] != '\0' || s->saddr != 0 || s->daddr != 0 )
				{
					s->time_out = 0;
				}
#endif
				if ( really )	//execute real delete
				{
					/*move to free list*/
					list_move(&s->list, &ssl_table->free_list);
					list_del(&s->lru);
					s->time_out = 0;
				}
				else	//tlhhh 2010-11-05. just can _not_ trust this conntrack's state anymore.(need to rating) 
				{
					s->can_trust = 0;	
				}
			}
        }
    }

    tm_write_unlock(&ssltable_lock);
    
    return 0;
}

int ssl_delete(struct ssl_entry_t *s)
{
    tm_write_lock(&ssltable_lock);

    list_move(&s->list, &ssl_table->free_list);
    list_del(&s->lru);
    s->time_out = 0;

    tm_write_unlock(&ssltable_lock);

    return 0;
}


struct ssl_entry_t *ssl_find(struct iphdr *iph)
{
    struct list_head *p;
    struct ssl_entry_t *s;
    unsigned int hash = ssl_hash(iph->saddr, iph->daddr);

    tm_read_lock(&ssltable_lock);
    list_for_each(p, &ssl_table->hash_list[hash])
    {
        s = list_entry(p, struct ssl_entry_t, list);

		if ( s->saddr == iph->saddr && s->daddr == iph->daddr ) 
		{
			tm_read_unlock(&ssltable_lock);
			atomic_inc(&s->refcnt);
			return s;
		}
		else if ( s->daddr == iph->saddr && s->saddr == iph->daddr ) 
		{
			tm_read_unlock(&ssltable_lock);
			atomic_inc(&s->refcnt);
			return s;
		}
    }
    tm_read_unlock(&ssltable_lock);

    return NULL;
}


/* tlhhh, 2010-11-05. routine to find conntrack with trust */
struct ssl_entry_t *ssl_find_with_trust(struct iphdr *iph)
{
    struct list_head *p;
    struct ssl_entry_t *s;
    unsigned int hash = ssl_hash(iph->saddr, iph->daddr);

    tm_read_lock(&ssltable_lock);
    list_for_each(p, &ssl_table->hash_list[hash])
    {
        s = list_entry(p, struct ssl_entry_t, list);


		if ( s->can_trust && 
			(s->saddr == iph->saddr && s->daddr == iph->daddr) ) 
		{
			tm_read_unlock(&ssltable_lock);
			atomic_inc(&s->refcnt);
			return s;
		}
		else if ( s->can_trust && 
			(s->daddr == iph->saddr && s->saddr == iph->daddr) ) 
		{
			tm_read_unlock(&ssltable_lock);
			atomic_inc(&s->refcnt);
			return s;
		}
    }
    tm_read_unlock(&ssltable_lock);
    return NULL;
}


int ssl_add(u_int32_t saddr, u_int32_t daddr, char *host, int state)
{
    struct ssl_entry_t *s;
    struct list_head *p;
    unsigned long next_timeout;
    unsigned int hash = ssl_hash(saddr, daddr);

    if (time_after(jiffies, check_period))
    {
        next_timeout = jiffies + MAX_LIFE_TIME;

        tm_write_lock(&ssltable_lock);
        list_for_each(p, &ssl_table->lru_list)
        {
            s = list_entry(p, struct ssl_entry_t, lru);
            if (time_after(jiffies, s->time_out))
            {
                list_move(&s->list, &ssl_table->free_list);
                p = p->prev;
                list_del(&s->lru);
            }
            else
            {
                next_timeout = s->time_out;
                break;
            }
        }
        tm_write_unlock(&ssltable_lock);

        check_period = next_timeout;
    }

	tm_write_lock(&ssltable_lock);

	//ensure free list is not empty
	if (list_empty(&ssl_table->free_list))
	{
		//pk_debug("ssl table is full, delete oldest ssl entry");
		s = list_entry(ssl_table->lru_list.next, struct ssl_entry_t, lru);
		list_move(&s->list, &ssl_table->free_list);
		list_del(&s->lru);
	}

	s = list_entry(ssl_table->free_list.next, struct ssl_entry_t, list);

	list_move(&s->list, &ssl_table->hash_list[hash]);
	list_add_tail(&s->lru, &ssl_table->lru_list);
	s->time_out = jiffies + MAX_LIFE_TIME;

	s->saddr = saddr;
	s->daddr = daddr;
	s->sport = 0;
	s->dport = 0;

	s->can_trust = 0;

	memset(s->host, 0, MAX_HOST_SIZE);
	memcpy(s->host, host, MAX_HOST_SIZE-1);
	s->host[MAX_HOST_SIZE-1] = '\0';
	s->nfconn = NULL;

	//tlhhh 2010-8-1. ssl tracking default state to SSL_BLOCK
	s->state = state;
	s->lock = RW_LOCK_UNLOCKED;
	atomic_set(&s->refcnt, 1);

    tm_write_unlock(&ssltable_lock);

    return 0;
}


static int table_init(void)
{
    int i;
    struct ssl_entry_t *s;

    INIT_LIST_HEAD(&ssl_table->free_list);
    INIT_LIST_HEAD(&ssl_table->lru_list);

    for (i = 0; i < MAX_HASH_SIZE; i++)
    {
        INIT_LIST_HEAD(&ssl_table->hash_list[i]);
    }

    for (i = 0; i < MAX_TRACKING_SIZE; i++)
    {
        s = &ssl_table->entry[i];

        list_add_tail(&s->list, &ssl_table->free_list);
        INIT_LIST_HEAD(&s->lru);
        s->time_out = 0;

        atomic_set(&s->refcnt, 0);
        s->lock = RW_LOCK_UNLOCKED;
    }

    return 0;
}


int ssl_init(void)
{
    ssl_table = kmalloc( sizeof(struct ssl_table_t)+sizeof(struct ssl_entry_t)*MAX_TRACKING_SIZE, GFP_KERNEL );
    if (ssl_table == NULL)
    {
        pk_err("init ssl moudle failed!");
        return -1;
    }

    ssl_table->entry = (struct ssl_entry_t*)((int)ssl_table + sizeof(struct ssl_table_t));
    if (table_init() == -1)
    {
        return -1;
    }
    check_period = jiffies + MAX_LIFE_TIME;

	pk_info("init ssl module ..");
    return 0;
}

void ssl_fini(void)
{
    pk_info("exit ssl module ..");
    kfree(ssl_table);
}
