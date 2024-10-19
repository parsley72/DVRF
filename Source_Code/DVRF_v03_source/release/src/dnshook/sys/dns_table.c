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

#include "defs.h"
#include "log.h"
#include "dns_table.h"


#define MAX_ENTRY_SIZE 100

unsigned long check_period = 0;
rwlock_t dnstable_lock = RW_LOCK_UNLOCKED;
struct dns_table_t *dns_table;


/* ELF Hash Function */
//tlh 2010-08-18, we use dnsname to hash instead of sip/dip tuple. 
unsigned int dns_hash(char* str, unsigned int len)
{
	unsigned int hash = 0;
	unsigned int x    = 0;
	unsigned int i    = 0;

	for(i = 0; i < len; str++, i++)
	{
		hash = (hash << 4) + (*str);
		if((x = hash & 0xF0000000L) != 0)
		{
			hash ^= (x >> 24);
		}
		hash &= ~x;
	}

	return (hash % MAX_HASH_SIZE);
}

int dns_update_timeout(struct dns_entry_t *d)
{
    tm_write_lock(&d->lock);

    list_move_tail(&d->lru, &dns_table->lru_list);
    d->time_out = jiffies + MAX_LIFE_TIME;

    tm_write_unlock(&d->lock);
    return 0;
}

int dns_update_state(struct dns_entry_t *d, int state)
{
    tm_write_lock(&d->lock);
    d->state = state;
    tm_write_unlock(&d->lock);
    return 0;
}

int dns_delete(struct dns_entry_t *d)
{
    tm_write_lock(&dnstable_lock);

    list_move(&d->list, &dns_table->free_list);
    list_del(&d->lru);
    d->time_out = 0;

    tm_write_unlock(&dnstable_lock);
    
    return 0;
}

struct dns_entry_t *dns_find(char *dnsname)
{
    struct list_head *p;
    struct dns_entry_t *d;
    unsigned int hash = dns_hash(dnsname, strlen(dnsname));

	tm_read_lock(&dnstable_lock);

    list_for_each(p, &dns_table->hash_list[hash])
    {
        d = list_entry(p, struct dns_entry_t, list);
		if( memcmp(d->dnsname, dnsname, strlen(dnsname)) == 0 )
		{
			tm_read_unlock(&dnstable_lock);
			atomic_inc(&d->refcnt);
			return d;
		}
    }

    tm_read_unlock(&dnstable_lock);

    return NULL;
}

int dns_add( struct dnsrr * tuple )
{
    struct dns_entry_t *d;
    struct list_head *p;
    unsigned long next_timeout;
    unsigned int hash = dns_hash(tuple->domainname, strlen(tuple->domainname));
	int i;

    if (time_after(jiffies, check_period))
	{
        next_timeout = jiffies + MAX_LIFE_TIME;

        tm_write_lock(&dnstable_lock);
        list_for_each(p, &dns_table->lru_list)
        {
            d = list_entry(p, struct dns_entry_t, lru);
            if (time_after(jiffies, d->time_out))
            {
                list_move(&d->list, &dns_table->free_list);
                /* delete lru, push back p */
                p = p->prev;
                list_del(&d->lru);
            }
            else
            {
                next_timeout = d->time_out;
                break;
            }
        }
        tm_write_unlock(&dnstable_lock);

        check_period = next_timeout;
    }


    tm_write_lock(&dnstable_lock);

	/* ensure free list is not empty */
	if (list_empty(&dns_table->free_list))
	{
		pk_debug("dns table is full, delete oldest dns entry");
		d = list_entry(dns_table->lru_list.next, struct dns_entry_t, lru);
		list_move(&d->list, &dns_table->free_list);
		list_del(&d->lru);
	}

	d = list_entry(dns_table->free_list.next, struct dns_entry_t, list);

	list_move(&d->list, &dns_table->hash_list[hash]);
	list_add_tail(&d->lru, &dns_table->lru_list);
	d->time_out = jiffies + MAX_LIFE_TIME;
	
	d->cli_addr = tuple->cli_addr;

	for( i=0; i<MAX_DNS_ANSWER; i++ )
	{
		memset(&d->svr_addr[i], 0, sizeof(struct my_addr_in));
	}

	memset(d->mac, 0, sizeof(d->mac));

	memset(d->dnsname, 0, sizeof(d->dnsname));
	memcpy(d->dnsname, tuple->domainname, MAX_HOST_SIZE-1);
	d->dnsname[MAX_HOST_SIZE - 1] = '\0';

	//tlhhh 2010-8-1. add rating result cache dns tracking. default set to DNS_TRACKING_RESP_RCVD.
	d->state = DNS_QUERY_RCVD;
	d->lock = RW_LOCK_UNLOCKED;
	atomic_set(&d->refcnt, 1);

    tm_write_unlock(&dnstable_lock);

    return 0;
}

static int table_init(void)
{
    int i;
    struct dns_entry_t *d;

    INIT_LIST_HEAD(&dns_table->free_list);
    INIT_LIST_HEAD(&dns_table->lru_list);

    for (i = 0; i < MAX_HASH_SIZE; i++)
    {
        INIT_LIST_HEAD(&dns_table->hash_list[i]);
    }

    for (i = 0; i < MAX_ENTRY_SIZE; i++)
    {
        d = &dns_table->entry[i];

        list_add_tail(&d->list, &dns_table->free_list);
        INIT_LIST_HEAD(&d->lru);
        d->time_out = 0;

        atomic_set(&d->refcnt, 0);
        d->lock = RW_LOCK_UNLOCKED;
    }
    return 0;
}


int dns_init(void)
{
    dns_table = kmalloc( sizeof(struct dns_table_t)+sizeof(struct dns_entry_t)*MAX_ENTRY_SIZE, GFP_KERNEL );
    if (dns_table == NULL)
    {
        pk_err("Init DNS module failed\n");
        return -1;
    }

    dns_table->entry = (struct dns_entry_t*)((int)dns_table + sizeof(struct dns_table_t));
    if (table_init() == -1)
    {
        return -1;
    }
    check_period = jiffies + MAX_LIFE_TIME;

	pk_info("init dns module ..");
    return 0;
}


void dns_fini(void)
{
    pk_info("exit dns module ..");
    kfree(dns_table);
}
