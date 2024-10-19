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

/* 2010-08-01 LingHong Tan 
 *
 * Time block a client, according to read from /proc/tblock_proc
 */

#ifndef __KERNEL__
#define __KERNEL__
#endif
#ifndef MODULE
#define MODULE
#endif
#define LINUX
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <asm/uaccess.h>

#include "tblock.h"
#include "log.h"

//#define EXPIRED_POLL_TIME (15*HZ)
#define MAX_UNBLOCK_TIME (3600*HZ)
#define MAX_HOST_SIZE  256
#define ETHER_ADDR_LEN	6

struct g_tblock_table *g_tblk_t;

static rwlock_t	hash_lock = RW_LOCK_UNLOCKED;

extern int ether_atoe(const char *a, unsigned char *e);

int get_hwaddr(const char *str, unsigned char *hwaddr)
{
	if ( !str || !strcmp(str, "") )
		return -1;
	
	ether_atoe(str, hwaddr);

	if (is_valid_ether_addr((unsigned char *)hwaddr))
		return 0;

	return -1;
}

//static kmem_cache_t *tblk_cache;
//static u32 tblk_salt __read_mostly;

/* userspace --> kernel */
ssize_t tblk_proc_write( struct file *filp, const char *buff, unsigned long len, void *data )
{
	unsigned char hwaddr[ETHER_ADDR_LEN];
	//char url[MAX_HOST_SIZE];
	//char c;
	char tblock_string[300];
	char *p = tblock_string;
	//int is_wtp = 0;
	//struct tblock_t *tblk = NULL;
	//int expired = 0;

	memset(tblock_string, 0, sizeof(tblock_string));
	
	//pk_debug("buff=%s, len=%lu\n", buff, len);

	if( len > sizeof(tblock_string)-1 )
	{
		return -EFAULT;
	}

	if( copy_from_user(tblock_string, buff, len) )
	{
		return -EFAULT;
	}
	
	pk_debug( "tblock_string=%s\n", tblock_string);

	if ( strncmp(tblock_string, "del", strlen("del")) == 0 ) {
		p += strlen("del");

		while ( p && *p != '\0' ) {
			if (*p == ' ' || *p == ':' || *p == '\t')
				p++;
			else
				break;
		}
		if ( !p )
			return -EFAULT;

		pk_debug("delete tblk entry...");

		if ( get_hwaddr(p, hwaddr) < 0 ) {
			return -EFAULT;
		}
		tblk_delete_by_mac(hwaddr);
	}
	else if ( strncmp(tblock_string, "add", strlen("add")) == 0 ) {
		p += strlen("add");
		
		while ( p && *p != '\0' ) {
			if (*p == ' ' || *p == ':' || *p == '\t')
				p++;
			else
				break;
		}
		if ( !p )
			return -EFAULT;
	
		pk_debug("add tblk entry...");
		if ( get_hwaddr(p, hwaddr) < 0 ) {
			return -EFAULT;
		}
		
		if ( tblk_get(hwaddr) ) {
			pk_debug("%d: alread exist [%02x:%02x:%02x:%02x:%02x:%02x]", __LINE__, 
				hwaddr[0],  hwaddr[1],  hwaddr[2],  hwaddr[3],  hwaddr[4],  hwaddr[5] );
			return len;
		}
		else
			tblk_insert(hwaddr);
	}
	else if ( strncmp(tblock_string, "flush", strlen("flush")) == 0 ) {
		p += strlen("flush");

		pk_debug("flush all tblk entries...");
		tblk_flush();
	}
	else {
		return len;
	}

	return len;	//success
}

static __inline__ int tblk_hash(const unsigned char *mac)
{
	unsigned long x;

	x = mac[0];
	x = (x << 2) ^ mac[1];
	x = (x << 2) ^ mac[2];
	x = (x << 2) ^ mac[3];
	x = (x << 2) ^ mac[4];
	x = (x << 2) ^ mac[5];

	x ^= x >> 8;

	return x & (TBLOCK_HASH_SIZE - 1);
}

static __inline__ void __hash_link(struct tblock_t *ent, int hash)
{
	ent->next_hash = g_tblk_t->hash[hash];
	if (ent->next_hash != NULL)
		ent->next_hash->pprev_hash = &ent->next_hash;
	g_tblk_t->hash[hash] = ent;
	ent->pprev_hash = &g_tblk_t->hash[hash];
}

static __inline__ void __hash_unlink(struct tblock_t *ent)
{
	*(ent->pprev_hash) = ent->next_hash;
	if (ent->next_hash != NULL)
		ent->next_hash->pprev_hash = ent->pprev_hash;
	ent->next_hash = NULL;
	ent->pprev_hash = NULL;
}


void tblk_free(struct tblock_t *f)
{
	//release this entry if none hold it.
	if (atomic_dec_and_test(&f->use_count))
		kfree(f);
}

/* Completely flush all dynamic entries in mac database.*/
void tblk_flush(void)
{
	int i;

	//lock with interrupt disabled, then flush all entries. tlhhh 
	write_lock_bh(&hash_lock);
	
	for (i = 0; i < TBLOCK_HASH_SIZE; i++) 
	{
		struct tblock_t *f;

		f = g_tblk_t->hash[i];
		while (f != NULL) {
			struct tblock_t *g;

			g = f->next_hash;
			pk_debug("Clear: [%02x:%02x:%02x:%02x:%02x:%02x]", 
				f->addr.addr[0], f->addr.addr[1], f->addr.addr[2], f->addr.addr[3], f->addr.addr[4], f->addr.addr[5]);
			__hash_unlink(f);
			tblk_free(f);

			f = g;
		}
	}
	write_unlock_bh(&hash_lock);
}

//Do _not_ call this function when in list_for_each. tlhhh
void tblk_delete(struct tblock_t *f)
{
	if( f == NULL )
		return ;

	write_lock_bh(&hash_lock);
	__hash_unlink(f);
	tblk_free(f);
	write_unlock_bh(&hash_lock);
}

/* Flush all entries refering to a specific mac.
 */
void tblk_delete_by_mac(const unsigned char *mac)
{
	int i;

	write_lock_bh(&hash_lock);
	for (i=0; i<TBLOCK_HASH_SIZE; i++) {
		struct tblock_t *f;

		f = g_tblk_t->hash[i];
		while (f != NULL) {
			struct tblock_t *g;

			g = f->next_hash;
			if ( !memcmp(mac, f->addr.addr, ETHER_ADDR_LEN) ) {
				pk_debug("Delete: [%02x:%02x:%02x:%02x:%02x:%02x]",
					mac[0],  mac[1],  mac[2],  mac[3],  mac[4],  mac[5] );
				__hash_unlink(f);
				tblk_free(f);
			}
			f = g;
		}
	}
	write_unlock_bh(&hash_lock);
}

struct tblock_t *tblk_get(unsigned char *mac)
{
	struct tblock_t *tblk;

	read_lock_bh(&hash_lock);

	tblk = g_tblk_t->hash[tblk_hash(mac)];
	
	while (tblk != NULL) 
	{
		if ( !memcmp(tblk->addr.addr, mac, ETHER_ADDR_LEN) ) 
		{
			//pk_debug("Find: [%02x:%02x:%02x:%02x:%02x:%02x]", 
			//	mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
			atomic_inc(&tblk->use_count);
			read_unlock_bh(&hash_lock);
			return tblk;
		}
		tblk = tblk->next_hash;
	}

	read_unlock_bh(&hash_lock);
	return NULL;
}


int tblk_insert(unsigned char *mac)
{
	struct tblock_t *tblk;
	int hash;

	hash = tblk_hash(mac);
	
	write_lock_bh(&hash_lock);

	tblk = kmalloc(sizeof(*tblk), GFP_ATOMIC);
	if (tblk == NULL) 
	{
		write_unlock_bh(&hash_lock);
		return -ENOMEM;
	}
	else
	{
		memcpy(tblk->addr.addr, mac, ETHER_ADDR_LEN);
		pk_debug("Add: [%02x:%02x:%02x:%02x:%02x:%02x]", 
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		atomic_set(&tblk->use_count, 1);
	}

	__hash_link(tblk, hash);

	write_unlock_bh(&hash_lock);

	return 0;
}


int tblk_create_proc_entry(void)
{
	struct proc_dir_entry *proc_entry;

	proc_entry = create_proc_entry( "tblock_proc", 0644, NULL );

	if (proc_entry == NULL) 
	{
		pk_debug("create tblock proc entry failed!\n");
		return -ENOMEM;
	}
	else
	{
		proc_entry->read_proc = NULL;
		proc_entry->write_proc = tblk_proc_write;

		proc_entry->owner = THIS_MODULE;
	}

	return 0;
}

void tblk_remove_proc_entry(void)
{
	remove_proc_entry("tblock_proc", NULL);
}

int tblock_init(void)
{
	if ((g_tblk_t = kmalloc(sizeof(*g_tblk_t), GFP_ATOMIC)) == NULL)
		return -ENOMEM;

	memset(g_tblk_t, 0, sizeof(*g_tblk_t));


	if( tblk_create_proc_entry() != 0 ) 
	{
		return -ENOMEM;	
	}

//	init_timer(&g_tblk_t->ec_timer);
//	g_tblk_t->ec_timer.function = expired_poll;
//	g_tblk_t->ec_timer.data = (unsigned long)0;

	return 0;
}

void tblock_fini(void)
{
	//del_timer(&g_tblk_t->ec_timer);
	tblk_remove_proc_entry();

	tblk_flush();	//free all entries
	kfree(g_tblk_t);
	
}
