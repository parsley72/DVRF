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

#ifndef __LOG_H__
#define __LOG_H__

#define _DEBUG_     1

#if _DEBUG_
#define pk_crit(fmt, args...)	printk(KERN_CRIT "[%s]: " fmt "\n", __FUNCTION__, ## args)
#define pk_err(fmt, args...)		printk(KERN_ERR "[%s]: " fmt "\n", __FUNCTION__, ## args)
#define pk_warn(fmt, args...)	printk(KERN_WARNING "[%s]: " fmt "\n", __FUNCTION__, ## args)
#define pk_info(fmt, args...)	printk(KERN_INFO "[%s]: " fmt "\n", __FUNCTION__, ## args)
#define pk_debug(fmt, args...)	printk(KERN_DEBUG "[%s]: " fmt "\n", __FUNCTION__, ## args)
#else
#define pk_crit(fmt, args...)
#define pk_err(fmt, args...)
#define pk_warn(fmt, args...)
#define pk_info(fmt, args...)
#define pk_debug(fmt, args...)
#endif

#endif	//__LOG_H__
