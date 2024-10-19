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
 * Unblock an url or MAC, according to read from /proc/unblock_proc
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

#include "unblock.h"
#include "log.h"

//#define EXPIRED_POLL_TIME (15*HZ)
#define MAX_UNBLOCK_TIME (3600*HZ)
#define MAX_HOST_SIZE  256
#define ETHER_ADDR_LEN	6

struct g_unblock_table *g_ublk_t;

static rwlock_t	hash_lock = RW_LOCK_UNLOCKED;
static rwlock_t	type_lock = RW_LOCK_UNLOCKED;
static int do_flush = 0;

//static kmem_cache_t *ublk_cache;
//static u32 ublk_salt __read_mostly;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#else
extern int strncasecmp(const char *s1, const char *s2, int n);
extern int strcasecmp(const char *a, const char *b);
#endif
int ether_atoe(const char *a, unsigned char *e);

void set_flush_supending(int yes)
{
	write_lock_bh(&type_lock);
	do_flush = yes;
	write_unlock_bh(&type_lock);
}

int get_flush_supending(void)
{
	int needo;

	read_lock_bh(&type_lock);
	needo = do_flush;
	read_unlock_bh(&type_lock);

	return needo;
}

int ether_atoe(const char *a, unsigned char *e) 
{ 
	char *c = (char *) a; 
	int i = 0; 

	memset(e, 0, ETHER_ADDR_LEN); 
	for (;;) 
	{ 
		e[i++] = (unsigned char) simple_strtoul(c, &c, 16); 
		if (!*c++ || i == ETHER_ADDR_LEN) 
			break; 
	} 
	return (i == ETHER_ADDR_LEN); 
}

/* userspace --> kernel */
ssize_t tm_proc_write( struct file *filp, const char *buff, unsigned long len, void *data )
{
	unsigned char hwaddr[ETH_ALEN];
	char url[MAX_HOST_SIZE];
	char c;
	char unblock_string[300];
	char *p = unblock_string;
	int is_wtp = 0;
	struct unblock_t *ublk = NULL;
	int expired = 0;

	memset(unblock_string, 0, sizeof(unblock_string));
	
	pk_debug("buff=%s, len=%lu\n", buff, len);

	if( len > sizeof(unblock_string)-1 )
	{
		return -EFAULT;
	}

	if( copy_from_user(unblock_string, buff, len) )
	{
		return -EFAULT;
	}
	
	pk_debug( "unblock_string=%s\n", unblock_string);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#else
	p = strtok( unblock_string, "|" );
	if( !p )	return -EFAULT;
#endif
	
	c = (char)p[0];		//get action
	if( c == '=' )
	{
		if ( strcmp( unblock_string, "=|flush_ublk" ) == 0 )
		{
			ublk_flush(0);
		}
		else if ( strcmp( unblock_string, "=|flush_ssl" ) == 0 )
		{
			set_flush_supending(1);
		}
		else	//default flush ublk and ssl entries
		{
			set_flush_supending(1);
			ublk_flush(0);
		}
		return len;
	}
	
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	p = strstr( p, "|" );
	if( !p )	return -EFAULT;

	p++;
#else
	p = strtok( NULL, "|" );
	if( !p )	return -EFAULT;
#endif
	ether_atoe(p, hwaddr);	//get hwaddr
	//printk(KERN_DEBUG "%s[%d]: p=[%s]\n", __func__, __LINE__, p);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	p = strstr( p, "|" );
#else
	p = strtok( NULL, "|" );
#endif
	//if( !p )	return -EFAULT;
	if( p == NULL || strcmp(p, "") == 0 )
	{
		url[0] = '\0';
		is_wtp = 0;
	}
	else
	{
		snprintf(url, MAX_HOST_SIZE-1, "%s", p);	//get url
		url[MAX_HOST_SIZE-1] = '\0';
		is_wtp = 1;
	}

	pk_info("c=%c, mac=%02x:%02x:%02x:%02x:%02x:%02x, url=%s\n", 
		c, hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5], url);

	switch( c )
	{
		case '+':	//add MAC to unblock list
			if (is_valid_ether_addr((unsigned char *)hwaddr))
			{
				ublk = !is_wtp ? ublk_get(hwaddr, &expired) : ublk_get_with_url(hwaddr, url, &expired) ;
				//if get an entry, delete it.
				if( ublk != NULL )
					ublk_delete(ublk);

				if( !ublk_insert( hwaddr, url, is_wtp ) )
					return -EFAULT;
			}
			break;

		case '-':	//delete MAC from unblock list
			ublk_delete_by_mac(hwaddr);
			break;

#if 0
		case '=':	//flush all MACs
			ublk_flush(0);
			break;
#endif

		default:
			break;
	}
	
	return len;	//success
}

//static void expired_poll(unsigned long data)
//{
//	printk(KERN_DEBUG "%s[%d]: Every 15s, check if has expired entry\n", __func__, __LINE__);
//	ublk_flush(1);
//	mod_timer(&g_ublk_t->ec_timer, jiffies + EXPIRED_POLL_TIME);
//}

int has_expired(const struct unblock_t *ublk)
{
	return time_before_eq(ublk->ageing_timer + MAX_UNBLOCK_TIME, jiffies);
}


static __inline__ int tm_mac_hash(const unsigned char *mac)
{
	unsigned long x;

	x = mac[0];
	x = (x << 2) ^ mac[1];
	x = (x << 2) ^ mac[2];
	x = (x << 2) ^ mac[3];
	x = (x << 2) ^ mac[4];
	x = (x << 2) ^ mac[5];

	x ^= x >> 8;

	return x & (UNBLOCK_HASH_SIZE - 1);
}

static __inline__ void __hash_link(struct unblock_t *ent, int hash)
{
	ent->next_hash = g_ublk_t->hash[hash];
	if (ent->next_hash != NULL)
		ent->next_hash->pprev_hash = &ent->next_hash;
	g_ublk_t->hash[hash] = ent;
	ent->pprev_hash = &g_ublk_t->hash[hash];
}

static __inline__ void __hash_unlink(struct unblock_t *ent)
{
	*(ent->pprev_hash) = ent->next_hash;
	if (ent->next_hash != NULL)
		ent->next_hash->pprev_hash = ent->pprev_hash;
	ent->next_hash = NULL;
	ent->pprev_hash = NULL;
}


void ublk_free(struct unblock_t *f)
{
	//release this entry if none hold it.
	if (atomic_dec_and_test(&f->use_count))
		kfree(f);
}

/* Completely flush all dynamic entries in mac database.*/
void ublk_flush(int only_expired)
{
	int i;

	//lock with interrupt disabled, then flush all entries. tlhhh 
	write_lock_bh(&hash_lock);
	
	for (i = 0; i < UNBLOCK_HASH_SIZE; i++) 
	{
		struct unblock_t *f;

		f = g_ublk_t->hash[i];
		while (f != NULL) {
			struct unblock_t *g;

			g = f->next_hash;
			if( only_expired  )
			{
				if( has_expired(f) )
				{
					__hash_unlink(f);
					ublk_free(f);
				}
			}
			else
			{				
				__hash_unlink(f);
				ublk_free(f);
			}
			f = g;
		}
	}
	write_unlock_bh(&hash_lock);
}

//Do _not_ call this function when in list_for_each. tlhhh
void ublk_delete(struct unblock_t *f)
{
	if( f == NULL )
		return ;

	write_lock_bh(&hash_lock);
	__hash_unlink(f);
	ublk_free(f);
	write_unlock_bh(&hash_lock);
}

/* Flush all entries refering to a specific mac.
 */
void ublk_delete_by_mac(const unsigned char *mac)
{
	int i;

	write_lock_bh(&hash_lock);
	for (i=0; i<UNBLOCK_HASH_SIZE; i++) {
		struct unblock_t *f;

		f = g_ublk_t->hash[i];
		while (f != NULL) {
			struct unblock_t *g;

			g = f->next_hash;
			if ( !memcmp(mac, f->addr.addr, ETH_ALEN) ) {
				__hash_unlink(f);
				ublk_free(f);
			}
			f = g;
		}
	}
	write_unlock_bh(&hash_lock);
}


/* Flush all entries refering to a specific url.
 * if do_all is set also flush static entries
 */
void ublk_delete_by_url(const char *url)
{
	int i;

	write_lock_bh(&hash_lock);
	for (i=0; i<UNBLOCK_HASH_SIZE; i++) {
		struct unblock_t *f;

		f = g_ublk_t->hash[i];
		while (f != NULL) {
			struct unblock_t *g;

			g = f->next_hash;
			if ( !memcmp(url, f->url, MAX_HOST_SIZE-1) ) {
				__hash_unlink(f);
				ublk_free(f);
			}
			f = g;
		}
	}
	write_unlock_bh(&hash_lock);
}

struct unblock_t *ublk_get(unsigned char *addr, int *expired)
{
	struct unblock_t *ublk;

	read_lock_bh(&hash_lock);

	//printk(KERN_DEBUG "[%d] hash value=%d\n", __LINE__, tm_mac_hash(addr));
	ublk = g_ublk_t->hash[tm_mac_hash(addr)];
	
	while (ublk != NULL) 
	{
		if ( !memcmp(ublk->addr.addr, addr, ETH_ALEN) && !ublk->is_wtp ) 
		{
			if (!has_expired(ublk)) 
				*expired = 0;
			else
				*expired = 1;

			atomic_inc(&ublk->use_count);
			read_unlock_bh(&hash_lock);
			return ublk;
		}
		//printk(KERN_DEBUG "__________%s[%d]_______________\n", __func__, __LINE__);
		ublk = ublk->next_hash;
	}

	read_unlock_bh(&hash_lock);
	return NULL;
}


struct unblock_t *ublk_get_with_url(unsigned char *addr, char *url, int *expired)
{
	struct unblock_t *ublk;

	read_lock_bh(&hash_lock);

	//printk(KERN_DEBUG "[%d] hash value=%d\n", __LINE__, tm_mac_hash(addr));
	ublk = g_ublk_t->hash[tm_mac_hash(addr)];
	while (ublk != NULL) 
	{
		if ( !memcmp(ublk->addr.addr, addr, ETH_ALEN) && 
			!strcasecmp(ublk->url, url ) )
		{
			if (!has_expired(ublk)) 
				*expired = 0;
			else
				*expired = 1;
				
			atomic_inc(&ublk->use_count);
			read_unlock_bh(&hash_lock);
			return ublk;
		}
		//printk(KERN_DEBUG "__________%s[%d]_______________\n", __func__, __LINE__);
		ublk = ublk->next_hash;
	}

	read_unlock_bh(&hash_lock);
	return NULL;
}

int ublk_insert(unsigned char *addr, char *url, int is_wtp)
{
	struct unblock_t *ublk;
	int hash;

	hash = tm_mac_hash(addr);
	//printk(KERN_DEBUG "__________%s[%d]hash=%d_______________\n", __func__, __LINE__, hash);
	write_lock_bh(&hash_lock);

	ublk = kmalloc(sizeof(*ublk), GFP_ATOMIC);
	if (ublk == NULL) 
	{
		write_unlock_bh(&hash_lock);
		return -ENOMEM;
	}
	else
	{
		memcpy(ublk->addr.addr, addr, ETH_ALEN);
		if( !is_wtp )
		{
			ublk->url[0] = '\0';
		}
		else
		{
			memcpy(ublk->url, url, MAX_HOST_SIZE-1);
			ublk->url[MAX_HOST_SIZE-1] = '\0';
		}
		//printk(KERN_DEBUG "___%s[%d]:url=%s____\n", __func__, __LINE__, ublk->url);

		ublk->is_wtp = is_wtp;
		atomic_set(&ublk->use_count, 1);
		ublk->ageing_timer = jiffies;
	}
	//printk(KERN_DEBUG "__________%s[%d]:is_wtp=%d_______________\n", __func__, __LINE__, ublk->is_wtp);
	__hash_link(ublk, hash);

	write_unlock_bh(&hash_lock);

	return 0;
}


int tm_create_proc_entry(void)
{
	struct proc_dir_entry *proc_entry;

	proc_entry = create_proc_entry( "unblock_proc", 0644, NULL );

	if (proc_entry == NULL) 
	{
		printk(KERN_INFO "create unblock proc entry failed!\n");
		return -ENOMEM;
		
	} 
	else
	{
		proc_entry->read_proc = NULL;
		proc_entry->write_proc = tm_proc_write;

		proc_entry->owner = THIS_MODULE;
	}

	return 0;
}

void tm_remove_proc_entry(void)
{
	remove_proc_entry("unblock_proc", NULL);
}

int unblock_init(void)
{
	if ((g_ublk_t = kmalloc(sizeof(*g_ublk_t), GFP_ATOMIC)) == NULL)
		return -ENOMEM;

	memset(g_ublk_t, 0, sizeof(*g_ublk_t));

	if( tm_create_proc_entry() != 0 ) 
	{
		return -ENOMEM;	
	}

//	init_timer(&g_ublk_t->ec_timer);
//	g_ublk_t->ec_timer.function = expired_poll;
//	g_ublk_t->ec_timer.data = (unsigned long)0;
//	printk(KERN_DEBUG "__________%s[%d]_______________\n", __func__, __LINE__);

	return 0;
}

void unblock_fini(void)
{
	//del_timer(&g_ublk_t->ec_timer);
	tm_remove_proc_entry();

	ublk_flush(0);	//free all entries
	kfree(g_ublk_t);
	
}
