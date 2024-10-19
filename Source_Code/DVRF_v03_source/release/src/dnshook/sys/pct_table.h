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

#ifndef __PCT_TABLE_H__
#define __PCT_TABLE_H__
#include <linux/list.h>
#include <linux/skbuff.h>

#include "decode.h"

/* tlhhh 2010-10-29. 
 * PCT table will store all passed connections, need to hold them until next DNS query */
#define PCT_LIFE_TIME	(2400*HZ)    /* max life time */

struct pct_entry_t
{
    struct list_head list;
    struct list_head lru; //last recent use list
    unsigned long time_out;

    u_int8_t id;
    u_int8_t state;
	u_int8_t is_static;

    u_int32_t target;
	char host[MAX_HOST_SIZE];

    atomic_t refcnt;
    rwlock_t lock;
};

struct pct_table_t
{
    struct list_head hash_list[MAX_HASH_SIZE];
    struct list_head lru_list;
    struct list_head free_list;
    struct pct_entry_t *entry;
};

int pct_add(const char *host, u_int32_t addr, int is_static);
int pct_delete(struct pct_entry_t *f);

struct pct_entry_t *pct_find(u_int32_t addr);
int pct_update_timeout(struct pct_entry_t *f);
int pct_update_state(struct pct_entry_t *f, int state);


int  pct_init(void);
void pct_fini(void);

#endif	//__PCT_TABLE_H__
