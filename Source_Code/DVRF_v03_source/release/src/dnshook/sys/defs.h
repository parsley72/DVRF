
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

#ifndef __DEFS_H__
#define __DEFS_H__

#include <asm/types.h>

/* tlhhh 2010-10-30. we are in ISR, __do_softirq already disabled bh.*/
//#ifdef CONFIG_SMP	/* SMP need this? NO */
#if 0
#define tm_read_lock(l) read_lock_bh(l)
#define tm_write_lock(l) write_lock_bh(l)
#define tm_read_unlock(l) read_unlock_bh(l)
#define tm_write_unlock(l) write_unlock_bh(l)
#else
#define tm_read_lock(l) read_lock(l)
#define tm_write_lock(l) write_lock(l)
#define tm_read_unlock(l) read_unlock(l)
#define tm_write_unlock(l) write_unlock(l)
#endif
	
#define MAX_TRACKING_SIZE	100
#define MAX_HASH_SIZE 128
#define MAX_LIFE_TIME  (240*HZ)    /* max life time */

#define MAX_URL_LENGTH 512
#define MAX_URL_SIZE 256
#define MAX_HOST_SIZE 256
#define MAX_PACKET_SIZE 1024
#define ETHER_ADDR_LEN	6
#define HTTP_REDIRECT_HEADER \
    "HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\nContent-Type: text/html\r\n\r\n"
//#define MAX_TCP_WINDOW 65535
	
// url rate request
#define PTRGET_URLREQUEST(pPacket) ((nlink_urlreq_t *)pPacket->data)

#define PTRGET_NLREQ_HTTPHEADER(pPacket) PTRGET_URLREQUEST(pPacket)->header
#define PTRGET_NLREQ_URL(pPacket) PTRGET_URLREQUEST(pPacket)->header.path
#define PTRGET_NLREQ_URLSIZE(pPacket) PTRGET_URLREQUEST(pPacket)->header.path_len
#define PTRGET_NLREQ_HOST(pPacket) PTRGET_URLREQUEST(pPacket)->header.host
#define PTRGET_NLREQ_HOSTSIZE(pPacket) PTRGET_URLREQUEST(pPacket)->header.host_len
#define PTRGET_NLREQ_HANDLE(pPacket) PTRGET_URLREQUEST(pPacket)->socket
#define PTRGET_NLREQ_SADDR(pPacket) PTRGET_URLREQUEST(pPacket)->socket.saddr.s_addr4
#define PTRGET_NLREQ_DADDR(pPacket) PTRGET_URLREQUEST(pPacket)->socket.daddr.s_addr4
#define PTRGET_NLREQ_SOURCE(pPacket) PTRGET_URLREQUEST(pPacket)->socket.source
#define PTRGET_NLREQ_DEST(pPacket) PTRGET_URLREQUEST(pPacket)->socket.dest
#define PTRGET_NLREQ_FAMILY(pPacket) PTRGET_URLREQUEST(pPacket)->socket.family
#define PTRGET_NLREQ_MAC(pPacket) PTRGET_URLREQUEST(pPacket)->mac
#ifdef __CONFIG_IPV6__
#define PTRGET_NLREQ_IPFAMILY(pPacket)	PTRGET_URLREQUEST(pPacket)->socket.ip_family
#define PTRGET_NLREQ_SADDR6(pPacket)	PTRGET_URLREQUEST(pPacket)->socket.saddr.s_addr6
#define PTRGET_NLREQ_DADDR6(pPacket)	PTRGET_URLREQUEST(pPacket)->socket.daddr.s_addr6
#endif

// url rate response
#define PTRGET_URLRESULT(pPacket) ((nlink_urlresp_t *)pPacket->data)

#define PTRGET_NLRES_BLOCKLOC(pPacket) PTRGET_URLRESULT(pPacket)->blkpage_loc
#define PTRGET_NLRES_BLOCKLOCSIZE(pPacket) PTRGET_URLRESULT(pPacket)->blkpage_len
#define PTRGET_NLRES_RESULTCODE(pPacket) PTRGET_URLRESULT(pPacket)->result
#define PTRGET_NLRES_HANDLE(pPacket) PTRGET_URLRESULT(pPacket)->socket
#define PTRGET_NLRES_SADDR(pPacket) PTRGET_URLRESULT(pPacket)->socket.saddr.s_addr4
#define PTRGET_NLRES_DADDR(pPacket) PTRGET_URLRESULT(pPacket)->socket.daddr.s_addr4
#define PTRGET_NLRES_SOURCE(pPacket) PTRGET_URLRESULT(pPacket)->socket.source
#define PTRGET_NLRES_DEST(pPacket) PTRGET_URLRESULT(pPacket)->socket.dest
#define PTRGET_NLRES_FAMILY(pPacket) PTRGET_URLRESULT(pPacket)->socket.family
#ifdef __CONFIG_IPV6__
#define PTRGET_NLRES_IPFAMILY(pPacket)	PTRGET_URLRESULT(pPacket)->socket.ip_family
#define PTRGET_NLRES_SADDR6(pPacket)	PTRGET_URLRESULT(pPacket)->socket.saddr.s_addr6
#define PTRGET_NLRES_DADDR6(pPacket)	PTRGET_URLRESULT(pPacket)->socket.daddr.s_addr6
#endif

// hook control request
#define PTRGET_HOOKCTRLREQUEST(pPacket) ((nlink_ctlreq_t *)pPacket->data)
#define PTRGET_NLREQ_HOOKENABLED(pPacket) PTRGET_HOOKCTRLREQUEST(pPacket)->enabled
// hook control response
#define PTRGET_FUNCRESULT(pPacket) ((nlink_ctlresp_t *)pPacket->data)
#define PTRGET_NLRES_FUNCRESULT(pPacket) PTRGET_FUNCRESULT(pPacket)->result


enum entry_state
{
    STATE_INIT = 0,
    STATE_SYN_RCVD,
    STATE_ESTAB,
    STATE_RATING,
    STATE_PASS,
	STATE_WHITE_PASS,
    STATE_BLOCK,
    STATE_REDIRECT,
    STATE_FIN_WAIT1,
    STATE_FIN_WAIT2,
    STATE_CLOSING,
    STATE_TIME_WAIT,
};
	
typedef struct
{
    char            path[MAX_URL_SIZE];
    int             path_len;			
    char            host[MAX_HOST_SIZE];
    int             host_len;
} req_info_t;

typedef struct
{
    union {
	__u32 saddr;
	__u32 saddr6[4];
    } in;
} my_addr;
#define s_addr4 in.saddr
#define s_addr6 in.saddr6

typedef struct
{
    unsigned short family;
    my_addr saddr;
    my_addr daddr;
    __u16 source;
    __u16 dest;
} sk_info_t;

#ifdef __CONFIG_IPV6__
typedef struct sk_info6
{
    enum
    {
	IPV4_P,
	IPV6_P,
    } ip_family;

    __u32 saddr6[4];
    __u32 daddr6[4];
    __u16 source;
    __u16 dest;
} sk_info6_t;
#endif

typedef struct
{
    sk_info_t socket;
    req_info_t header;
    __u8 mac[6];
} nlink_urlreq_t;


typedef struct
{
    sk_info_t socket;
    enum
    {
        NETLINK_PASS,
		NETLINK_WHITE_PASS,
        NETLINK_FAIL
    } result;

    char blkpage_loc[MAX_URL_LENGTH];
    int blkpage_len;

} nlink_urlresp_t;

/* TODO: once kernel recieved init signal, it acks a response back */
typedef struct
{
	int result;
} nlink_ctlresp_t;


typedef struct
{
    int enabled;
} nlink_ctlreq_t;


typedef struct
{
    enum
    {
        NETLINK_REQUEST,
        NETLINK_RESPONSE,
    } type;

    enum
    {
        NETLINK_HOOKCTRL,
        NETLINK_FUNCRESULT,

		NETLINK_RATEURL_WP,
        NETLINK_URLRESULT_WP,
		//added by tlhhh. parentral control for HTTPs and other non-HTTP traffic.
		NETLINK_RATEURL_PC,
		NETLINK_URLRESULT_PC,
		//NETLINK_UNBLOCKURL,   
		//for name cache. 
		//NETLINK_FLUSHCACHE,   
    } subtype;

    char data[];
} nlink_packet_t;

#endif	//__DEFS_H__

