
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

#ifndef __SKB_H__
#define __SKB_H__

#include <linux/version.h>
#include <linux/ip.h>
		
typedef enum
{
    ACK_PACKET,
    FIN_ACK_PACKET,
    RST_PACKET
} TCP_TYPE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#define IP_HDR(x)	ip_hdr(x)
#define IP6_HDR(x)	ipv6_hdr(x)
#define ETH_HDR(x)	eth_hdr(x)
#else
#define IP_HDR(x) (x)->nh.iph
#define ETH_HDR(x) (x)->mac.ethernet
#endif

struct sk_buff *rebuild_packet(struct sk_buff *oldskb, int len, TCP_TYPE flag, int swap);
unsigned int redirect_packet(struct sk_buff *pskb, char *header);
int output_packet(struct sk_buff *pskb);
int reset_server(struct sk_buff* oldskb);
int ack_client(struct sk_buff* oldskb);
int send_blkpage(const char *location, struct sk_buff* oldskb);
#ifdef __CONFIG_IPV6__
struct sk_buff *rebuild_packet6(
	struct sk_buff *oldskb, int len, TCP_TYPE flag, const int* tcphoff, int swap);
unsigned int redirect_packet6(struct sk_buff *pskb, char *header);
int reset_server6(struct sk_buff* oldskb);
int ack_client6(struct sk_buff* oldskb);
int send_blkpage6(const char *location, struct sk_buff* oldskb);
#endif

#endif	//__SKB_H__
