
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

#ifndef __UNBLOCK_H__
#define __UNBLOCK_H__

#include <linux/list.h>
#include <linux/timer.h>

#define UNBLOCK_HASH_SIZE 256
#define	MAX_HOST_SIZE	256

struct mac_addr
{
	unsigned char	addr[6];
	unsigned char	pad[2];
};

struct unblock_t
{
	struct unblock_t	*next_hash;
	struct unblock_t	**pprev_hash;

	atomic_t			use_count;
	unsigned long		ageing_timer;
	struct mac_addr		addr;
	char				url[MAX_HOST_SIZE];
	unsigned char		is_wtp;

};


struct g_unblock_table
{
	struct unblock_t	*hash[UNBLOCK_HASH_SIZE];
	//atomic_t			entry_count;
	//struct timer_list	ec_timer;
};

void set_flush_supending(int yes);
int get_flush_supending(void);

void unblock_fini(void);
int unblock_init(void);

int ublk_insert(unsigned char *addr, char *url, int is_wtp);
struct unblock_t *ublk_get(unsigned char *addr, int *expired);
struct unblock_t *ublk_get_with_url(unsigned char *addr, char *url, int *expired);
void ublk_delete_by_url(const char *url);
void ublk_delete_by_mac(const unsigned char *mac);
void ublk_delete(struct unblock_t *f);
void ublk_flush(int only_expired);
void ublk_free(struct unblock_t *f);
int has_expired(const struct unblock_t *ublk);
//static void expired_poll(unsigned long data);

void tm_remove_proc_entry(void);
int tm_create_proc_entry(void);
ssize_t tm_proc_write( struct file *filp, const char *buff, unsigned long len, void *data );


#endif	//__UNBLOCK_H__

