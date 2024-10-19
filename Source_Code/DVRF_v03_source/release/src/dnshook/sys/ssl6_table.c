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
#include "ssl6_table.h"


static unsigned long check_period = 0;
static rwlock_t ssl6table_lock = RW_LOCK_UNLOCKED; //protect all list_head struct
struct ssl6_table_t *ssl6_table;

static unsigned int ssl6_hash(u_int32_t saddr, u_int32_t daddr)
{   
    return ((daddr) % MAX_HASH_SIZE);
}           

int ssl6_update_timeout(struct ssl6_entry_t *s)
{
    tm_write_lock(&s->lock);

    list_move_tail(&s->lru, &ssl6_table->lru_list);
    s->time_out = jiffies + MAX_LIFE_TIME;

    tm_write_unlock(&s->lock);

    return 0;
}

int ssl6_update_state(struct ssl6_entry_t *s, int state)
{
    tm_write_lock(&s->lock);
    s->state = state;
    tm_write_unlock(&s->lock);

    return 0;
}

int ssl6_update_nfconn(struct ssl6_entry_t *s, struct sk_buff *skb)
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
int ssl6_update_trust(struct ssl6_entry_t *s, int result)
{
    tm_write_lock(&s->lock);
    s->can_trust = result;
    tm_write_unlock(&s->lock);

    return 0;
}

int ssl6_delete_all(int really)
{
    int i;
    struct ssl6_entry_t *s = NULL;

    tm_write_lock(&ssl6table_lock);

    for (i = 0; i < MAX_HASH_SIZE; i++)
    {
				struct list_head *pos, *n;
		
        list_for_each_safe(pos, n, &ssl6_table->hash_list[i])
        {
            s = list_entry(pos, struct ssl6_entry_t, list);

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
									list_move(&s->list, &ssl6_table->free_list);
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

    tm_write_unlock(&ssl6table_lock);
    
    return 0;
}

int ssl6_delete(struct ssl6_entry_t *s)
{
    tm_write_lock(&ssl6table_lock);

    list_move(&s->list, &ssl6_table->free_list);
    list_del(&s->lru);
    s->time_out = 0;

    tm_write_unlock(&ssl6table_lock);

    return 0;
}


struct ssl6_entry_t *ssl6_find(struct ipv6hdr *ip6h)
{
    struct list_head *p;
    struct ssl6_entry_t *s;
    struct in6_addr zero_addr;
    int is_zero;
    unsigned int hash = ssl6_hash(ip6h->saddr.s6_addr32[3], ip6h->daddr.s6_addr32[3]);

    memset(&zero_addr, 0, sizeof(struct in6_addr));
    
    tm_read_lock(&ssl6table_lock);
    list_for_each(p, &ssl6_table->hash_list[hash])
    {
        s = list_entry(p, struct ssl6_entry_t, list);
    		is_zero = ipv6_addr_equal(&s->saddr, &zero_addr);

		if ((is_zero || ipv6_addr_equal(&s->saddr, &ip6h->saddr)) && ipv6_addr_equal(&s->daddr, &ip6h->daddr))
		{
			tm_read_unlock(&ssl6table_lock);
			atomic_inc(&s->refcnt);
			return s;
		}
		else if (ipv6_addr_equal(&s->daddr, &ip6h->saddr) && (is_zero || ipv6_addr_equal(&s->saddr, &ip6h->daddr))) 
		{
			tm_read_unlock(&ssl6table_lock);
			atomic_inc(&s->refcnt);
			return s;
		}
    }
    tm_read_unlock(&ssl6table_lock);

    return NULL;
}


/* tlhhh, 2010-11-05. routine to find conntrack with trust */
struct ssl6_entry_t *ssl6_find_with_trust(struct ipv6hdr *ip6h)
{
    struct list_head *p;
    struct ssl6_entry_t *s;
    struct in6_addr zero_addr;
    int is_zero;
    unsigned int hash = ssl6_hash(ip6h->saddr.s6_addr32[3], ip6h->daddr.s6_addr32[3]);

    memset(&zero_addr, 0, sizeof(struct in6_addr));
    
    tm_read_lock(&ssl6table_lock);
    list_for_each(p, &ssl6_table->hash_list[hash])
    {
        s = list_entry(p, struct ssl6_entry_t, list);
    		is_zero = ipv6_addr_equal(&s->saddr, &zero_addr);

		if ( s->can_trust && 
					(is_zero || ipv6_addr_equal(&s->saddr, &ip6h->saddr)) && ipv6_addr_equal(&s->daddr, &ip6h->daddr) ) 
		{
			tm_read_unlock(&ssl6table_lock);
			atomic_inc(&s->refcnt);
			return s;
		}
		else if ( s->can_trust && 
							ipv6_addr_equal(&s->daddr, &ip6h->saddr) && (is_zero || ipv6_addr_equal(&s->saddr, &ip6h->daddr)) ) 
		{
			tm_read_unlock(&ssl6table_lock);
			atomic_inc(&s->refcnt);
			return s;
		}
    }
    tm_read_unlock(&ssl6table_lock);
    return NULL;
}


int ssl6_add(struct in6_addr *saddr, struct in6_addr *daddr, char *host, int state)
{
    struct ssl6_entry_t *s;
    struct list_head *p;
    unsigned long next_timeout;
    unsigned int hash = ssl6_hash(saddr->s6_addr32[3], daddr->s6_addr32[3]);

    if (time_after(jiffies, check_period))
    {
        next_timeout = jiffies + MAX_LIFE_TIME;

        tm_write_lock(&ssl6table_lock);
        list_for_each(p, &ssl6_table->lru_list)
        {
            s = list_entry(p, struct ssl6_entry_t, lru);
            if (time_after(jiffies, s->time_out))
            {
                list_move(&s->list, &ssl6_table->free_list);
                p = p->prev;
                list_del(&s->lru);
            }
            else
            {
                next_timeout = s->time_out;
                break;
            }
        }
        tm_write_unlock(&ssl6table_lock);

        check_period = next_timeout;
    }

	tm_write_lock(&ssl6table_lock);

	//ensure free list is not empty
	if (list_empty(&ssl6_table->free_list))
	{
		//pk_debug("ssl table is full, delete oldest ssl entry");
		s = list_entry(ssl6_table->lru_list.next, struct ssl6_entry_t, lru);
		list_move(&s->list, &ssl6_table->free_list);
		list_del(&s->lru);
	}

	s = list_entry(ssl6_table->free_list.next, struct ssl6_entry_t, list);

	list_move(&s->list, &ssl6_table->hash_list[hash]);
	list_add_tail(&s->lru, &ssl6_table->lru_list);
	s->time_out = jiffies + MAX_LIFE_TIME;

	memcpy((unsigned char *)&s->saddr, (unsigned char *)saddr, sizeof(struct in6_addr));
	memcpy((unsigned char *)&s->daddr, (unsigned char *)daddr, sizeof(struct in6_addr));
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

    tm_write_unlock(&ssl6table_lock);

    return 0;
}


static int table6_init(void)
{
    int i;
    struct ssl6_entry_t *s;

    INIT_LIST_HEAD(&ssl6_table->free_list);
    INIT_LIST_HEAD(&ssl6_table->lru_list);

    for (i = 0; i < MAX_HASH_SIZE; i++)
    {
        INIT_LIST_HEAD(&ssl6_table->hash_list[i]);
    }

    for (i = 0; i < MAX_TRACKING_SIZE; i++)
    {
        s = &ssl6_table->entry[i];

        list_add_tail(&s->list, &ssl6_table->free_list);
        INIT_LIST_HEAD(&s->lru);
        s->time_out = 0;

        atomic_set(&s->refcnt, 0);
        s->lock = RW_LOCK_UNLOCKED;
    }

    return 0;
}


int ssl6_init(void)
{
    ssl6_table = kmalloc( sizeof(struct ssl6_table_t)+sizeof(struct ssl6_entry_t)*MAX_TRACKING_SIZE, GFP_KERNEL );
    if (ssl6_table == NULL)
    {
        pk_err("init ssl6 moudle failed!");
        return -1;
    }

    ssl6_table->entry = (struct ssl6_entry_t*)((int)ssl6_table + sizeof(struct ssl6_table_t));
    if (table6_init() == -1)
    {
        return -1;
    }
    check_period = jiffies + MAX_LIFE_TIME;

	pk_info("init ssl module ..");
    return 0;
}

void ssl6_fini(void)
{
    pk_info("exit ssl module ..");
    kfree(ssl6_table);
}
