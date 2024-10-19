/*
 * Copyright (C) 2009, CyberTAN Corporation
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND CYBERTAN GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. CYBERTAN
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 */

#ifndef __bootnv_h__
#define __bootnv_h__

#include <cy_conf.h>
#include <typedefs.h>
#include <code_pattern.h>
#include <flash_layout.h>

/* FIXME: use following macro to restore old WRT320N MAC address info */
#if ((LINKSYS_MODEL == E300)  || (LINKSYS_MODEL == E30X)  || \
     (LINKSYS_MODEL == E1550) || (LINKSYS_MODEL == E155X) || \
     (LINKSYS_MODEL == E2500) || (LINKSYS_MODEL == E250X) || \
     (LINKSYS_MODEL == E3200) || \
     (LINKSYS_MODEL == E4200) || (LINKSYS_MODEL == E420X))
/* CFE.BIN can be up to 248KB */
#define BOOTNV_TOTAL_SIZE	((32 * 1024) / 4)	/* Entry max size is 1024, less than 256 for general use, so div by 4 */
#define BOOTNV_TOTAL_ENTRY_CNT  32	
#else
/* FIXME: boot code size must be less than BOOT_SIZE - BOOTNV_TOTAL_SIZE */
/* CFE.BIN can be up to 244KB */
#define BOOTNV_TOTAL_SIZE       (12 * 1024)     /* 12-KB */
#define BOOTNV_TOTAL_ENTRY_CNT  12
#endif

#define BOOTNV_ONE_ENTRY_SIZE	1024
#define BOOT_SIZE_BYTES		(BOOT_SIZE)

#ifdef BOOTNV_OLD_SUPPORT
#define BOOTNV_TOTAL_SIZE_OLD       (20 * 1024)     /* 20-KB */
#define BOOTNV_TOTAL_ENTRY_CNT_OLD  20
/* FIXME: use following macro to restore old WRT320N MAC address info */
#define PROC_BOOTNV_OLD		"bootnv_old"
#define PROC_BOOTNV_PATH_OLD	"/proc/" PROC_BOOTNV_OLD
#endif

#define bootnv_unset(k) bootnv_set(k, NULL)

#ifndef UBOOT

#define PROC_BOOTNV		"bootnv"
#define PROC_BOOTNV_PATH	"/proc/" PROC_BOOTNV


#ifndef __bootnvram_h__
#define __bootnvram_h__

#define BOOOTNV_DEBUG
#ifdef BOOOTNV_DEBUG
#ifdef __KERNEL__
#define dprintk	printk
#define DPRINT printk
#else
#define dprintk	printf
#define DPRINT printf
#endif
#else
#define dprintk(format, args...)
#define DPRINT(format, args...)
#endif

#ifdef BOOOTNV_DEBUG
void dump_entries(void);
void dump_text(void);
#endif
int bootnv_addr_init(void);
char *get_entry_value(char *name);
int get_all_entries(void);
int get_all_entries_value(char *buf);
int set_new_entry(char *str);
int build_entries(char *name, char *value);

/*Read only object table*/
struct bootnv_object
{
	char *name;
	int opt; //0 read only
		 //1 write/read
};

#endif /* __bootnvram_h__ */

extern int bootnv_get(const char *key, char *val);
extern int bootnv_set(char *key, char *val);
extern int bootnv_set_va(char *nm, const char *format, ...);
extern int bootnv_main(int argc, char *argv[]);

#endif /* UBOOT */
#endif /* __bootnv_h__ */
