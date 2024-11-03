
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

#ifndef __TBLOCK_H__
#define __TBLOCK_H__

#include <linux/list.h>
#include <linux/timer.h>

#include "unblock.h"

#define TBLOCK_HASH_SIZE 64

struct tblock_t
{
	struct tblock_t	*next_hash;
	struct tblock_t	**pprev_hash;

	atomic_t			use_count;
	struct mac_addr		addr;
	//unsigned char	tfilter;
};


struct g_tblock_table
{
	struct tblock_t	*hash[TBLOCK_HASH_SIZE];
	//atomic_t			entry_count;
	//struct timer_list	ec_timer;
};


void tblock_fini(void);
int tblock_init(void);

int tblk_insert(unsigned char *mac);
struct tblock_t *tblk_get(unsigned char *mac);
//void tblk_update_by_mac(const unsigned char *mac);
void tblk_delete_by_mac(const unsigned char *mac);
void tblk_delete(struct tblock_t *t);
void tblk_flush(void);
void tblk_free(struct tblock_t *t);

void tblk_remove_proc_entry(void);
int tblk_create_proc_entry(void);
ssize_t tblk_proc_write( struct file *filp, const char *buff, unsigned long len, void *data );
int get_hwaddr(const char *str, unsigned char *hwaddr);

#endif	//__TBLOCK_H__

