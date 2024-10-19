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
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/random.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>

#include "defs.h"
#include "log.h"

#include "decode.h"
#include "pct6_table.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#include <linux/jhash.h>
#else
#include "jhash.h"
#endif


static u_int32_t rnd;
static unsigned long check_period = 0;
static rwlock_t pct6table_lock = RW_LOCK_UNLOCKED; //protect all list_head struct

struct pct6_table_t *pct6_table;


static unsigned int pct6_hash(u_int32_t addr)
{
	return jhash_1word(addr, rnd) & (MAX_HASH_SIZE - 1);
}

int pct6_update_timeout(struct pct6_entry_t *f)
{
    tm_write_lock(&f->lock);
    list_move_tail(&f->lru, &pct6_table->lru_list);
    f->time_out = jiffies + PCT_LIFE_TIME;
    tm_write_unlock(&f->lock);
    return 0;
}

int pct6_update_state(struct pct6_entry_t *f, int state)
{
    tm_write_lock(&f->lock);
    f->state = state;
    tm_write_unlock(&f->lock);

    return 0;
}

int pct6_delete(struct pct6_entry_t *f)
{
    tm_write_lock(&pct6table_lock);

    list_move(&f->list, &pct6_table->free_list);
    list_del(&f->lru);
    f->time_out = 0;

    tm_write_unlock(&pct6table_lock);
 
    return 0;
}

struct pct6_entry_t *pct6_find(struct in6_addr *addr)
{
    struct list_head *p;
    struct pct6_entry_t *f;

    unsigned int hash = pct6_hash(addr->s6_addr[3]);

    tm_read_lock(&pct6table_lock);
    list_for_each(p, &pct6_table->hash_list[hash])
    {
        f = list_entry(p, struct pct6_entry_t, list);

				if (ipv6_addr_equal(&f->target, addr))
				{
            tm_read_unlock(&pct6table_lock);
            atomic_inc(&f->refcnt);
            return f;
    		}
    }
    tm_read_unlock(&pct6table_lock);
    return NULL;
}


int pct6_add(const char *host, struct in6_addr *addr, int is_static)
{
	struct pct6_entry_t *f;
	struct list_head *p;
	unsigned long next_time_out;
	unsigned int hash = pct6_hash(addr->s6_addr[3]);

	if (time_after(jiffies, check_period))
	{
		next_time_out = jiffies + PCT_LIFE_TIME;

		tm_write_lock(&pct6table_lock);
		list_for_each(p, &pct6_table->lru_list)
		{
			f = list_entry(p, struct pct6_entry_t, lru);
			if (time_after(jiffies, f->time_out))
			{
				/* never timeout the static entry */
				if (f->is_static)
					continue;

				list_move(&f->list, &pct6_table->free_list);
				p = p->prev;
				list_del(&f->lru);
			}
			else
			{
				next_time_out = f->time_out;
				break;
			}
		}
		tm_write_unlock(&pct6table_lock);

		check_period = next_time_out;
	}

	tm_write_lock(&pct6table_lock);
	if (list_empty(&pct6_table->free_list))
	{
		f = list_entry(pct6_table->lru_list.next, struct pct6_entry_t, lru);
		list_move(&f->list, &pct6_table->free_list);
		list_del(&f->lru);
	}

	f = list_entry(pct6_table->free_list.next, struct pct6_entry_t, list);

	list_move(&f->list, &pct6_table->hash_list[hash]);
	list_add_tail(&f->lru, &pct6_table->lru_list);
	f->time_out = jiffies + PCT_LIFE_TIME;

	f->state = STATE_INIT;
	memcpy(&f->target, addr, sizeof(struct in6_addr));

	memset(f->host, 0, MAX_HOST_SIZE);
	memcpy(f->host, host, MAX_HOST_SIZE-1);
	f->host[MAX_HOST_SIZE-1] = '\0';

	f->is_static = is_static;	

	f->lock = RW_LOCK_UNLOCKED;
	atomic_set(&f->refcnt, 1);

	tm_write_unlock(&pct6table_lock);

	return 0;
}


static int table_init(void)
{
    int i;
    struct pct6_entry_t *f;

    INIT_LIST_HEAD(&pct6_table->free_list);
    INIT_LIST_HEAD(&pct6_table->lru_list);

    for (i = 0; i < MAX_HASH_SIZE; i++)
    {
        INIT_LIST_HEAD(&pct6_table->hash_list[i]);
    }

    for (i = 0; i < MAX_TRACKING_SIZE; i++)
    {
        f = &pct6_table->entry[i];

        list_add_tail(&f->list, &pct6_table->free_list);
        INIT_LIST_HEAD(&f->lru);
        f->time_out = 0;

        f->id = i;

        atomic_set(&f->refcnt, 0);
        f->lock = RW_LOCK_UNLOCKED;

    }

    return 0;
}


int pct6_init(void)
{
    pct6_table = kmalloc( sizeof(struct pct6_table_t)+sizeof(struct pct6_entry_t)*MAX_TRACKING_SIZE, GFP_KERNEL );
    if (pct6_table == NULL)
    {
        pk_err("init pct module failed");
        return -1;
    }

    pct6_table->entry = (struct pct6_entry_t*)((int)pct6_table + sizeof(struct pct6_table_t));

    if (table_init() == -1)
    {
        return -1;
    }

    check_period = jiffies + PCT_LIFE_TIME;
	get_random_bytes(&rnd, sizeof(rnd));

	pk_info("init pct module ..");

    return 0;
}

void pct6_fini(void)
{
	pk_info("exit pct module ..");
    kfree(pct6_table);	
}
