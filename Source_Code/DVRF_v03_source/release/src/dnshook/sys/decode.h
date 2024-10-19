
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

#ifndef __DECODE_H__
#define __DECODE_H__

#include "defs.h"
#include "linux/in.h"
#include "linux/in6.h"

#define MAX_DNS_ANSWER	30	//we only allow 30 dns answers

/*
 * Currently defined opcodes
 */
#define QUERY		0x0		/* standard query */
#define IQUERY		0x1		/* inverse query */
#define STATUS		0x2		/* nameserver status query */
/*#define xxx		0x3*/		/* 0x3 reserved */
#define	NS_NOTIFY_OP	0x4		/* notify secondary of SOA change */

/*
 * Currently defined response codes
 */
#define NOERROR		0		/* no error */
#define FORMERR		1		/* format error */
#define SERVFAIL	2		/* server failure */
#define NXDOMAIN	3		/* non existent domain */
#define NOTIMP		4		/* not implemented */
#define REFUSED		5		/* query refused */

/*
 * Type values for resources and queries
 */
#define T_A			1		/* host address */
#define T_NS		2		/* authoritative server */
#define T_MD		3		/* mail destination */
#define T_MF		4		/* mail forwarder */
#define T_CNAME		5		/* canonical name */
#define T_SOA		6		/* start of authority zone */
#define T_MB		7		/* mailbox domain name */
#define T_MG		8		/* mail group member */
#define T_MR		9		/* mail rename name */
#define T_NULL		10		/* null resource record */
#define T_WKS		11		/* well known service */
#define T_PTR		12		/* domain name pointer */
#define T_HINFO		13		/* host information */
#define T_MINFO		14		/* mailbox information */
#define T_MX		15		/* mail routing information */
#define T_TXT		16		/* text strings */
#define	T_RP		17		/* responsible person */
#define T_AFSDB		18		/* AFS cell database */
#define T_X25		19		/* X_25 calling address */
#define T_ISDN		20		/* ISDN calling address */
#define T_RT		21		/* router */
#define T_NSAP		22		/* NSAP address */
#define T_NSAP_PTR	23		/* reverse NSAP lookup (deprecated) */
#define	T_SIG		24		/* security signature */
#define	T_KEY		25		/* security key */
#define	T_PX		26		/* X.400 mail mapping */
#define	T_GPOS		27		/* geographical position (withdrawn) */
#define	T_AAAA		28		/* IP6 Address */
#define	T_LOC		29		/* Location Information */
	/* non standard */
#define T_UINFO		100		/* user (finger) information */
#define T_UID		101		/* user ID */
#define T_GID		102		/* group ID */
#define T_UNSPEC	103		/* Unspecified format (binary data) */
	/* Query type values which do not appear in resource records */
#define T_AXFR		252		/* transfer zone of authority */
#define T_MAILB		253		/* transfer mailbox records */
#define T_MAILA		254		/* transfer mail agent records */
#define T_ANY		255		/* wildcard match */

/*
 * Values for class field
 */
#define C_IN		1		/* the arpa internet */
#define C_CHAOS		3		/* for chaos net (MIT) */
#define C_HS		4		/* for Hesiod name server (MIT) (XXX) */
	/* Query class values which do not appear in resource records */
#define C_ANY		255		/* wildcard match */

struct dnshdr{
	unsigned	id :16;		/* query identification number */

#if 0	//__BYTE_ORDER == __BIG_ENDIAN
			/* fields in third byte */
	unsigned	qr: 1;		/* response flag */
	unsigned	opcode: 4;	/* purpose of message */
	unsigned	aa: 1;		/* authoritive answer */
	unsigned	tc: 1;		/* truncated message */
	unsigned	rd: 1;		/* recursion desired */
			/* fields in fourth byte */
	unsigned	ra: 1;		/* recursion available */
	unsigned	pr:1;		/* primary server required (non standard) */
	unsigned	unused :2;	/* unused bits (MBZ as of 4.9.3a3) */
	unsigned	rcode :4;	/* response code */

#else	//__LITTLE_ENDIAN
			/* fields in third byte */
	unsigned	rd :1;		/* recursion desired */
	unsigned	tc :1;		/* truncated message */
	unsigned	aa :1;		/* authoritive answer */
	unsigned	opcode :4;	/* purpose of message */
	unsigned	qr :1;		/* response flag */
			/* fields in fourth byte */
	unsigned	rcode :4;	/* response code */
	unsigned	unused :2;	/* unused bits (MBZ as of 4.9.3a3) */
	unsigned	pr:1;		/* primary server required (non standard) */
	unsigned	ra :1;		/* recursion available */
#endif
			/* remaining bytes */
	unsigned	qdcount :16;	/* number of question entries */
	unsigned	ancount :16;	/* number of answer entries */
	unsigned	nscount :16;	/* number of authority entries */
	unsigned	arcount :16;	/* number of resource entries */
} ;

struct my_addr_in
{
	unsigned short family;
	union { 
	 struct in_addr inaddr;
	 struct in6_addr in6addr;
	}in_u; 	 
};

#define my_s_addr			in_u.inaddr.s_addr
#define my_s6_addr		in_u.inaddr.in6_u.u6_addr8
#define my_s6_addr16	in_u.inaddr.in6_u.u6_addr16
#define my_s6_addr32	in_u.inaddr.in6_u.u6_addr32

struct dnsrr {
	u_int8_t domainname[MAX_HOST_SIZE];
	u_int32_t cli_addr;
	u_int8_t anscount;
	struct my_addr_in dnslist[MAX_DNS_ANSWER];
};

unsigned short getshort(unsigned char *s);
char *getdnsname(unsigned char *baseaddr, char **thisname, unsigned char dnsname[]);
char *get_ansip(unsigned char *baseaddr, char *thisrr, unsigned long *answer);
int decode_dns(unsigned char* raw_pkt, int pkt_len, struct dnsrr *tuple);
char * printablename(char *name, int withdots, char hostname[]);
int decode_http(const char *pBuffer,const int nLength, req_info_t *pHead);


/* parse http header; success return 0; otherwise, return -1 */
//extern int ParseHeader(const char *pBuffer, const int nLength, tmHttpHeader_t *pHead);

#endif	//__DECODE_H__
