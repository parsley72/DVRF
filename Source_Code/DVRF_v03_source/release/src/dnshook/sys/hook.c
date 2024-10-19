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


/* linghong.tan     
 * 2010-10-20   add DNS hook.        
 * 2010-11-15   fix guestnetwork can _not_ access the internet.
 * 2010-11-22   fix can not handle fragmented request.
 * 2010-11-23   sanity check for malformed DNS packet.
 */
#ifndef __KERNEL__
#define __KERNEL__
#endif
#ifndef MODULE
#define MODULE
#endif
#define LINUX

#include <linux/init.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#else
#include <linux/config.h>
#endif
#define __CONFIG_IPV6__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter_ipv4.h>
#ifdef __CONFIG_IPV6__
#include <linux/ipv6.h>
#include <linux/netfilter_ipv6.h>
#include <net/ipv6.h>
#include <linux/if_ether.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>
#else
#include <linux/netfilter_ipv4/ip_conntrack.h>
#endif

#include <net/tcp.h>
#include <net/dst.h>
#include <asm/byteorder.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/proc_fs.h>

#include <net/neighbour.h>
#include <net/arp.h>
#include <net/ndisc.h>

#include "defs.h"
#include "log.h"

#include <linux/udp.h>
#include "dns_table.h"
#include "decode.h"


#include "unblock.h"
#include "tblock.h"
#include "ssl_table.h"
#include "ssl6_table.h"

#include "skb.h"
#include "tcp_table.h"
#include "pct_table.h"
#include "pct6_table.h"

extern rwlock_t dnstable_lock;  //protect all list_head struct
extern struct dns_table_t *dns_table;
extern unsigned int dns_hash(char* str, unsigned int len);

extern int send_to_user(unsigned int id, void *in, int length);
extern int nlink_init(int (*f_callback)(void *, int, unsigned int));
extern void nlink_fini(void);


#define TYPE_PROC_WP		0x01
#define TYPE_PROC_PC		0x02

static const char ModuleName[] = "dnshook";

//static int resetConnectionToServer(struct sk_buff* pSkbCopy);
//static int moveTemporarilyToClient(const char *szLocation, struct sk_buff* pSkbCopy);

static rwlock_t wp_lock = RW_LOCK_UNLOCKED;
static int wp_enabled = 0;

static rwlock_t hnd_lock = RW_LOCK_UNLOCKED;
static int hnd_enabled = 0;

static int handle6(void *data, int type, unsigned int len);

static int arp_query(unsigned char *haddr, u32 paddr,
		    const struct net_device *dev)
{
	struct neighbour *neighbor_entry;
	int ret = 0;
	struct net_device *dev_tmp = (struct net_device *)dev;

	neighbor_entry = neigh_lookup(&arp_tbl, &paddr, dev_tmp);

	if (neighbor_entry != NULL) {
		neighbor_entry->used = jiffies;
		if (neighbor_entry->nud_state & NUD_VALID) {
			memcpy(haddr, neighbor_entry->ha, dev_tmp->addr_len);
			ret = 1;
		}
		neigh_release(neighbor_entry);
	}
	return ret;
}

static int nd_query(unsigned char *haddr, struct in6_addr *paddr,
		    const struct net_device *dev)
{
	struct neighbour *neighbor_entry;
	int ret = 0;
	struct net_device *dev_tmp = (struct net_device *)dev;

	neighbor_entry = neigh_lookup(&nd_tbl, paddr, dev_tmp);

	if (neighbor_entry != NULL) {
		neighbor_entry->used = jiffies;
		if (neighbor_entry->nud_state & NUD_VALID) {
			memcpy(haddr, neighbor_entry->ha, dev_tmp->addr_len);
			ret = 1;
		}
		neigh_release(neighbor_entry);
	}
	return ret;
}

static inline int is_tcp(struct sk_buff *skb)
{
    struct iphdr *iph;
    struct tcphdr *tcph;

	iph = IP_HDR(skb);
    
    if (iph->protocol != IPPROTO_TCP)
    {
        return 0;
    }

    if (!pskb_may_pull(skb, sizeof(struct tcphdr)))
    {
        return 0;
    }

    iph = IP_HDR(skb);
    tcph = (struct tcphdr *)&(((u_int32_t*)iph)[iph->ihl]);

	if( unlikely(tcph==NULL) )
		return 0;

    if (tcph->doff < sizeof(struct tcphdr)/4)
    {
        return 0;
    }

    if (!pskb_may_pull(skb, tcph->doff*4))
    {
        return 0;
    }
    return 1;
}

static inline int is_http(const struct tcphdr *tcph)
{
    if (ntohs(tcph->source)==80 || ntohs(tcph->dest)==80)
    {
		return 1;
    }
    return 0;
}

static int is_ack(const struct tcphdr *tcph, unsigned int len, const struct net_device *in)
{
    if (!tcph->syn && tcph->ack && !tcph->fin && !len)
    {
        return 1;
    }
    return 0;
}

static int is_finack(const struct tcphdr *tcph, unsigned int len, const struct net_device *in)
{
    if (!tcph->syn && tcph->ack && tcph->fin && !len)
    {
        return 1;
    }
    return 0;
}

static int is_syn(const struct tcphdr *tcph, unsigned int len, const struct net_device *in)
{
    if (tcph->syn && !tcph->ack && !tcph->fin && !len)
    {
        return 1;
    }
    return 0;
}

static inline int is_https(const struct tcphdr *tcph)
{
    if (ntohs(tcph->source)==443 || ntohs(tcph->dest)==443)
    {
        return 1;
    }
    return 0;
}

static inline int is_udp(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct udphdr *udph;
	unsigned short ulen;

	iph = IP_HDR(skb);

	if (iph->protocol != IPPROTO_UDP)
		return 0;

	/*
	 *  Validate the packet.
	 */
	if (!pskb_may_pull(skb, sizeof(struct udphdr)))
		return 0;		/* No space for header. */

	
	iph = IP_HDR(skb);

	//skip ip header length
	udph = (struct udphdr *)&(((u_int32_t*)iph)[iph->ihl]);
	if( unlikely(udph==NULL) )
		return 0;

	ulen = ntohs(udph->len);
	
	if (ulen < sizeof(*udph) || ulen > skb->len)
		return 0;

	
	/* UDP validates ulen. */
	if (ulen < sizeof(*udph) )
		return 0;

	if ( !pskb_may_pull(skb, ulen) )
		return 0;

	//check sum
//	if (udp4_csum_init(skb, uh, proto))
//		return 0;

	return 1;
}

//dns query: return 1, dns response: return 2
static inline int is_dns(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct udphdr *udph;
	struct dnshdr *dnsh;
	int dns_len = 0;

	if (!is_udp(skb))
		return 0;

	iph = IP_HDR(skb);
	udph = (struct udphdr *)&(((u_int32_t*)iph)[iph->ihl]);
	dnsh = (struct dnshdr *)((unsigned char*)udph +sizeof(struct udphdr));
	if( unlikely(dnsh == NULL) )
		return 0;

	
	if ( 53 == ntohs(udph->dest) ||  53 == ntohs(udph->source) )
	{	
		dns_len = skb->tail - (unsigned char *)dnsh;	//dns data length

		if ( dns_len <= sizeof(struct dnshdr) )
		{
			//pk_debug("dns_len=[%d], dnshdr=[%d]", dns_len, sizeof(struct dnshdr));
			return 0;
		}
		return 53 == ntohs(udph->dest) ? 1 : 2;
	}

	return 0;
}

static inline int is_dns6(struct udphdr *udph, int dns_len)
{
	struct dnshdr *dnsh;

	dnsh = (struct dnshdr *)((unsigned char*)udph +sizeof(struct udphdr));
	if( unlikely(dnsh == NULL) )
		return 0;


	if ( 53 == ntohs(udph->dest) ||  53 == ntohs(udph->source) )
	{	
		if ( dns_len <= sizeof(struct dnshdr) )
		{
			//pk_debug("dns_len=[%d], dnshdr=[%d]", dns_len, sizeof(struct dnshdr));
			return 0;
		}
		return 53 == ntohs(udph->dest) ? 1 : 2;
	}
		
	return 0;
}

static inline int is_white_conn(struct sk_buff *skb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	struct nf_conn *ct;
#else
	struct ip_conntrack *ct;
#endif
	enum ip_conntrack_info ctinfo;

	if (skb == NULL) {
		return 0;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	ct = nf_ct_get(skb, &ctinfo);
#else
	ct = ip_conntrack_get(skb, &ctinfo);
#endif
	if (ct == NULL) {
		pk_err("no conntrack!\n");
		return 0;
	}

	return (ct->whitelist);
}

static inline int is_ublk_entry(unsigned char mac[])
{
	struct unblock_t *ublk = NULL;
	int has_expired = 0;

	//ublk = ublk_get_with_url(hwaddr, Request.host, &has_expired);
	/* G5 f/w, unblock:  match MAC enough */
	ublk = ublk_get(mac, &has_expired);

	if( ublk != NULL ) {
		//pk_debug( "Matched unblock list: mac=[%02x:%02x:%02x:%02x:%02x:%02x]", 
		//		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );

		if( has_expired ) {
			ublk_delete(ublk);
			return 0;
		}

		return 1;
	}

	return 0;
}

static inline int is_tblk_entry(unsigned char mac[])
{
	struct tblock_t *tblk = NULL;

	tblk = tblk_get(mac);

	if ( unlikely(tblk != NULL) ) {
		//pk_debug( "Matched tblock list: mac=[%02x:%02x:%02x:%02x:%02x:%02x]", 
		//		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );
		return 1;
	}

	return 0;
}

/*
struct udphdr {
	__be16	source;
	__be16	dest;
	__be16	len;
	__sum16	check;
};
*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#else
int strncasecmp(const char *s1, const char *s2, int n)
{
	int c1, c2;

	do {
		c1 = tolower(*s1++);
		c2 = tolower(*s2++);
	} while ((--n > 0) && c1 == c2 && c1 != 0);
	return c1 - c2;
}

int strcasecmp(const char *a, const char *b)
{
	int ca, cb;

	do {
		ca = *a++ & 0xff;
		cb = *b++ & 0xff;
		if (ca >= 'A' && ca <= 'Z')
			ca += 'a' - 'A';
		if (cb >= 'A' && cb <= 'Z')
			cb += 'a' - 'A';
	} while (ca == cb && ca != '\0');

	return ca - cb;
}
#endif

static unsigned int dns_hook(unsigned int hooknum,
        struct sk_buff **skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph = IP_HDR((*skb));
	struct udphdr *udph;
	struct dnshdr *dnsh;
	struct dnsrr tuple;
	struct dns_entry_t *d;	
	int dns_len;
	int dns_type;
	int filter_type = 0x0;
	
	int flushall = 0;
	read_lock(&hnd_lock);
	if (hnd_enabled)
		filter_type |= TYPE_PROC_PC;
	read_unlock(&hnd_lock);

	read_lock(&wp_lock);
	if (wp_enabled)
		filter_type |= TYPE_PROC_WP;
	read_unlock(&wp_lock);

	//tlhhh. There are no hooks registered, ACCEPT.
	if ( filter_type == 0  )
		return NF_ACCEPT;
		
	if (*skb == NULL)
    {
        return NF_ACCEPT;
    }
    else if (in == NULL)
    {
		return NF_ACCEPT;
    }
	
	flushall = get_flush_supending(); 
	if( unlikely(flushall) )
	{
		pk_debug("flush all ssl tracking");
		ssl_delete_all(0);
		set_flush_supending(0);
	}

	dns_type = is_dns(*skb);
    if (!dns_type)	//0: non-DNS  1: DNS query  2: DNS response
    {
        return NF_ACCEPT;
    }

	//skip ip header length
	udph = (struct udphdr *)&(((u_int32_t*)iph)[iph->ihl]);
	dnsh = (struct dnshdr *)((unsigned char*)udph +sizeof(struct udphdr));
	dns_len = (*skb)->tail - (unsigned char *)dnsh;	//dns data length
	
	memset(&tuple, 0, sizeof(struct dnsrr));

	/* tlhhh. validate DNS packet in is_valid_dns */
	if ( decode_dns((unsigned char*)dnsh, dns_len, (struct dnsrr *)&tuple) < 0 )
		return NF_ACCEPT;
		
	if ( 53 == ntohs(udph->dest) )	//query
	{
		d = dns_find(tuple.domainname);
		if( d == NULL )
		{
			tuple.cli_addr = iph->saddr;
			dns_add(&tuple);
		}
		else	//already exist, update timeout
		{
			if( d->cli_addr == iph->saddr )		//multiple dns queries from the same client
			{
				dns_update_timeout(d);
			}
			else	//same dnsname from a different client
			{
				tuple.cli_addr = iph->saddr;
				dns_add(&tuple);
			}
		}
	}
	else if( 53 == ntohs(udph->source) )		//response
	{
		int i;
		//int count = 0;
		struct list_head *p;
		struct dns_entry_t *cur_entry = NULL;
		struct pct_entry_t *f = NULL;
		unsigned int hash = dns_hash(tuple.domainname, strlen(tuple.domainname));

		/* tlhhh 2010-8-6. 
		 * If found the matched hashkey tracking, 
		 * go through all nodes with different IP in this tracking,
		 * and then add them to s monitor list
		 */
		tm_read_lock(&dnstable_lock);		//must lock. sorry to destroy the DNS module's completion. 
		
		list_for_each(p, &dns_table->hash_list[hash])
		{
			cur_entry = list_entry(p, struct dns_entry_t, list);

			if ( unlikely(cur_entry == NULL) )
				continue;

			if ( memcmp( cur_entry->dnsname, tuple.domainname, strlen(cur_entry->dnsname) ) != 0 )
			{
				pk_debug("Hash [%d] collision with [%s] -- [%s]", hash, cur_entry->dnsname, tuple.domainname);
				continue;
			}

			tm_write_lock(&cur_entry->lock);
			
			if( cur_entry->state == DNS_QUERY_RCVD )
			{
				cur_entry->state = DNS_RESPONSE_RCVD;
			}
			else
			{
				/* ever seen this domain's response, update svr_addr lists. */

				//tm_write_unlock(&cur_entry->lock);
				//continue;
			}

			for ( i=0; i<tuple.anscount; i++ )
			{
				if( (tuple.dnslist[i].family != AF_INET) && (tuple.dnslist[i].family != AF_INET6))
					continue;
				/* update server address accoring to the latest list */
				if(memcmp(&cur_entry->svr_addr[i], &tuple.dnslist[i], sizeof(struct my_addr_in)) == 0)
					continue;

				cur_entry->svr_addr[i] = tuple.dnslist[i];
				
				/* take every DNS answer */
				if( filter_type & TYPE_PROC_WP )
				{
					//pk_debug( "Add PCT tracking: %u.%u.%u.%u <---> %u.%u.%u.%u with [%s]\n", 
					//	NIPQUAD(cur_entry->cli_addr), NIPQUAD(cur_entry->svr_addr[i]), cur_entry->dnsname);
					if(cur_entry->svr_addr[i].family == AF_INET)
					{
						if ( unlikely( strcasecmp(cur_entry->dnsname, "update.linksys.com") == 0 ) )
						{
							f = pct_find( cur_entry->svr_addr[i].my_s_addr);
							if (f)	//already exist this staic entry
							{
								pct_update_timeout(f);
							}
							else	//add static entry
								pct_add( cur_entry->dnsname, cur_entry->svr_addr[i].my_s_addr, 1);
						}
						else
							pct_add( cur_entry->dnsname, cur_entry->svr_addr[i].my_s_addr, 0);
					}
					else /*AF_INET6*/
					{
						struct pct6_entry_t *f6 = NULL;
				
						if ( unlikely( strcasecmp(cur_entry->dnsname, "update.linksys.com") == 0 ) )
						{
							f6 = pct6_find( &cur_entry->svr_addr[i].in_u.in6addr );
							if (f6)	//already exist this staic entry
							{
								pct6_update_timeout(f6);
							}
							else	//add static entry
								pct6_add( cur_entry->dnsname, &cur_entry->svr_addr[i].in_u.in6addr, 1);
						}
						else
							pct6_add( cur_entry->dnsname, &cur_entry->svr_addr[i].in_u.in6addr, 0);
					}
				}
				if( filter_type & TYPE_PROC_PC )
				{
					//pk_debug( "Add SSL tracking: %u.%u.%u.%u <---> %u.%u.%u.%u with [%s]\n", 
						//NIPQUAD(cur_entry->cli_addr), NIPQUAD(cur_entry->svr_addr[i]), cur_entry->dnsname);
					if(	cur_entry->svr_addr[i].family == AF_INET)
						ssl_add( cur_entry->cli_addr, cur_entry->svr_addr[i].my_s_addr, cur_entry->dnsname, STATE_ESTAB );
					else
					{
					    	struct in6_addr zero_addr;
					    	memset(&zero_addr, 0, sizeof(struct in6_addr));
						ssl6_add( &zero_addr, &cur_entry->svr_addr[i].in_u.in6addr, cur_entry->dnsname, STATE_ESTAB );
					}	
				}
			}
					
			tm_write_unlock(&cur_entry->lock);
			
			/* if found an entry, escape */
			break;
		}

		tm_read_unlock(&dnstable_lock);
		
	}

	return NF_ACCEPT;
}

#ifdef __CONFIG_IPV6__
static unsigned int dns6_hook(unsigned int hooknum,
		struct sk_buff **skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct ipv6hdr *ip6h = IP6_HDR((*skb));
	struct udphdr *udph;
	struct dnshdr *dnsh;
	struct dnsrr tuple;
	struct dns_entry_t *d;
	int dns_len;
	int dns_type = 0;
	int filter_type = 0x0;
	int offset;
	u8 proto;

	int flushall = 0;

	read_lock(&hnd_lock);
	if (hnd_enabled)
		filter_type |= TYPE_PROC_PC;
	read_unlock(&hnd_lock);

	read_lock(&wp_lock);
	if (wp_enabled)
		filter_type |= TYPE_PROC_WP;
	read_unlock(&wp_lock);

	//tlhhh. There are no hooks registered, ACCEPT.
	if ( filter_type == 0  )
		return NF_ACCEPT;

	if (*skb == NULL)
	{
		return NF_ACCEPT;
	}
	else if (in == NULL)
	{
		return NF_ACCEPT;
	}

	flushall = get_flush_supending();
	if( unlikely(flushall) )
	{
		pk_debug("flush all ssl tracking");
		ssl6_delete_all(0);
		set_flush_supending(0);
	}

	if (!(ipv6_addr_type(&ip6h->saddr) & IPV6_ADDR_UNICAST) ||
	    !(ipv6_addr_type(&ip6h->daddr) & IPV6_ADDR_UNICAST))
	{
		pk_debug("dns6_hook: IPv6 address is not unicast.\n");
		return NF_ACCEPT;
	}

	proto = ip6h->nexthdr;
	offset = ipv6_skip_exthdr( (*skb), ((u_int8_t*)(ip6h+1) - (*skb)->data), &proto);

	if (proto == IPPROTO_UDP) {
		dns_len = ((*skb)->tail - ((unsigned char *)ip6h + offset)) - 8;
		dns_type = is_dns6((struct udphdr *)((unsigned char *)ip6h + offset), dns_len);
	}
	if (!dns_type)	//0: non-DNS  1: DNS query  2: DNS response
	{
		return NF_ACCEPT;
	}

	//skip ip header length
	udph = (struct udphdr *)((unsigned char *)ip6h + offset);
	dnsh = (struct dnshdr *)((unsigned char*)udph +sizeof(struct udphdr));
	dns_len = ((*skb)->tail - ((unsigned char *)ip6h + offset)) - 8;

	memset(&tuple, 0, sizeof(struct dnsrr));

	/* tlhhh. validate DNS packet in is_valid_dns */
	if ( decode_dns((unsigned char*)dnsh, dns_len, (struct dnsrr *)&tuple) < 0 )
		return NF_ACCEPT;

	if ( 53 == ntohs(udph->dest) )	//query
	{
		d = dns_find(tuple.domainname);
		if( d == NULL )
		{
			tuple.cli_addr = 0;
			dns_add(&tuple);
		}
		else	//already exist, update timeout
		{
			if( d->cli_addr == 0 )	//multiple dns queries from the same client
			{
				dns_update_timeout(d);
			}
			else	//same dnsname from a different client
			{
				tuple.cli_addr = 0;
				dns_add(&tuple);
			}
		}
	}
	else if( 53 == ntohs(udph->source) )		//response
	{
		int i;
		//int count = 0;
		struct list_head *p;
		struct dns_entry_t *cur_entry = NULL;
		struct pct_entry_t *f = NULL;
		unsigned int hash = dns_hash(tuple.domainname, strlen(tuple.domainname));

		/* tlhhh 2010-8-6.
		 * If found the matched hashkey tracking,
		 * go through all nodes with different IP in this tracking,
		 * and then add them to s monitor list
		 */
		tm_read_lock(&dnstable_lock);		//must lock. sorry to destroy the DNS module's completion.

		list_for_each(p, &dns_table->hash_list[hash])
		{
			cur_entry = list_entry(p, struct dns_entry_t, list);

			if ( unlikely(cur_entry == NULL) )
				continue;

			if ( memcmp( cur_entry->dnsname, tuple.domainname, strlen(cur_entry->dnsname) ) != 0 )
			{
				pk_debug("Hash [%d] collision with [%s] -- [%s]", hash, cur_entry->dnsname, tuple.domainname);
				continue;
			}

			tm_write_lock(&cur_entry->lock);

			if( cur_entry->state == DNS_QUERY_RCVD )
			{
				cur_entry->state = DNS_RESPONSE_RCVD;
			}
			else
			{
				/* ever seen this domain's response, update svr_addr lists. */

				//tm_write_unlock(&cur_entry->lock);
				//continue;
			}

			for ( i=0; i<tuple.anscount; i++ )
			{
				if( (tuple.dnslist[i].family != AF_INET) && (tuple.dnslist[i].family != AF_INET6))
					continue;
				/* update server address accoring to the latest list */
				//if (cur_entry->svr_addr[i] == tuple.dnslist[i])
				if(memcmp(&cur_entry->svr_addr[i], &tuple.dnslist[i], sizeof(struct my_addr_in)) == 0)
					continue;

				cur_entry->svr_addr[i] = tuple.dnslist[i];

				/* take every DNS answer */
				if( filter_type & TYPE_PROC_WP )
				{
					//pk_debug( "Add PCT tracking: %u.%u.%u.%u <---> %u.%u.%u.%u with [%s]\n",
					//NIPQUAD(cur_entry->cli_addr), NIPQUAD(cur_entry->svr_addr[i]), cur_entry->dnsname);
					if(	cur_entry->svr_addr[i].family == AF_INET)
					{
						if ( unlikely( strcasecmp(cur_entry->dnsname, "update.linksys.com") == 0 ) )
						{
							f = pct_find( cur_entry->svr_addr[i].my_s_addr);
							if (f)	//already exist this staic entry
							{
								pct_update_timeout(f);
							}
							else	//add static entry
								pct_add( cur_entry->dnsname, cur_entry->svr_addr[i].my_s_addr, 1);
						}
						else
							pct_add( cur_entry->dnsname, cur_entry->svr_addr[i].my_s_addr, 0);
					}
					else /*AF_INET6*/
					{
						struct pct6_entry_t *f6 = NULL;

						if ( unlikely( strcasecmp(cur_entry->dnsname, "update.linksys.com") == 0 ) )
						{
							f6 = pct6_find( &cur_entry->svr_addr[i].in_u.in6addr );
							if (f6)	//already exist this staic entry
							{
								pct6_update_timeout(f6);
							}
							else	//add static entry
								pct6_add( cur_entry->dnsname, &cur_entry->svr_addr[i].in_u.in6addr, 1);
						}
						else
							pct6_add( cur_entry->dnsname, &cur_entry->svr_addr[i].in_u.in6addr, 0);
					}
				}
				if( filter_type & TYPE_PROC_PC )
				{
					//pk_debug( "Add SSL tracking: %u.%u.%u.%u <---> %u.%u.%u.%u with [%s]\n",
					//NIPQUAD(cur_entry->cli_addr), NIPQUAD(cur_entry->svr_addr[i]), cur_entry->dnsname);
					if(	cur_entry->svr_addr[i].family == AF_INET)
						ssl_add( cur_entry->cli_addr, cur_entry->svr_addr[i].my_s_addr, cur_entry->dnsname, STATE_ESTAB );
					else
					{
						struct in6_addr zero_addr;
						memset(&zero_addr, 0, sizeof(struct in6_addr));

						ssl6_add( &zero_addr, &cur_entry->svr_addr[i].in_u.in6addr, cur_entry->dnsname, STATE_ESTAB );
					}
				}
			}

			tm_write_unlock(&cur_entry->lock);

			/* if found an entry, escape */
			break;
		}

		tm_read_unlock(&dnstable_lock);

	}

	return NF_ACCEPT;
}
#endif

static unsigned int forward_hook(unsigned int hooknum,
        struct sk_buff **skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph;
    unsigned char *data = NULL ;
    struct tcp_entry_t *t = NULL;
	struct tcphdr *tcph = NULL;
	unsigned int data_len = 0;
	int filter_type = 0;
	req_info_t Request;
	
	read_lock(&hnd_lock);
	if( hnd_enabled )
		filter_type |= TYPE_PROC_PC;
	read_unlock(&hnd_lock);

	read_lock(&wp_lock);
	if ( wp_enabled )
		filter_type |= TYPE_PROC_WP;
	read_unlock(&wp_lock);

	//tlhhh. There are no hooks registered, ACCEPT.
	if ( filter_type == 0 )
	{
		return NF_ACCEPT;
	}
    if (*skb == NULL)
    {
        return NF_ACCEPT;
    }
    if ((in == NULL) || (out == NULL))
    {
        return NF_ACCEPT;
    }
    else if (strcmp(in->name, out->name) == 0)
    {
        return NF_ACCEPT;
    }
	else if (!is_tcp(*skb))
	{
		return NF_ACCEPT;
	}

	iph = IP_HDR((*skb));
	tcph = (struct tcphdr *)&(((u_int32_t*)iph)[iph->ihl]);
	data =(unsigned char *)&(((u_int32_t*)tcph)[tcph->doff]);
	
	if (unlikely(tcph==NULL || data == NULL))
	{
		return NF_ACCEPT;
	}

	data_len = (*skb)->tail - data;
		
	if (!is_http(tcph))
		return NF_ACCEPT;

	/* fix guestnetwork fail to access the internet */
	if ( filter_type == TYPE_PROC_WP )		/* wp enabled && pc disabled ==> PASS*/
	{
		if ( strncmp(in->name, "br1", 3) == 0 || strncmp(out->name, "br1", 3) == 0 )		//from GuestNetwork
			return NF_ACCEPT;
	}

    if ((t = tcp_find(iph, tcph)) == NULL)
    {
        if ( is_syn(tcph, data_len, in))
        {
			tcp_add(iph, tcph);
        }
		else if ( filter_type == TYPE_PROC_PC )	//Parentral control enabled
		{
			/* find the packet from which interface, then get arp */
			if ( strncmp(in->name, "br0", 3) == 0 || strncmp(in->name, "br1", 3) == 0)		//from LAN
			{
				/* unblock check */
				if ( is_ublk_entry(ETH_HDR(*skb)->h_source) )
					goto ACCEPT;
				
				/* time block check */
				if ( is_tblk_entry(ETH_HDR(*skb)->h_source) ) 
				{
					if (is_white_conn(*skb)) {
						//pk_debug("HTTP whitelist connection, ACCEPT");
						goto ACCEPT;
					}
					/* sorry, time filter block */
					goto DROP;
				}
			}
			else	//from WAN
			{
				//get client ip, then lookup arp cache.
#if 0
				if ( !arp_query( ETH_HDR(*skb)->h_source, iph->daddr, (struct net_device *)out ) )	//out from 'br0'
				{
					pk_debug( "Find in=%s, out=%s [%u.%u.%u.%u-->%u.%u.%u.%u]'s ARP cache failed\n", 
						in->name, out->name, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr) );
				}
#endif
				/* To avoid query ARP, accept all traffic from server */ 
				goto ACCEPT;
			}
		}

		goto ACCEPT;
    }
	
	tcp_update_timeout(t);
	
	switch (t->state)
	{
		case STATE_SYN_RCVD:
			//pk_debug("TCP_SYN_RCVD:");
			if (is_ack(tcph, data_len, in)) /* deal with normal open & simultaneous open */
			{
				tcp_update_state(t, STATE_ESTAB);
			}

			if (unlikely(t->nfconn == NULL)) {
				if (tcp_update_nfconn(t, *skb) < 0)
					goto ACCEPT;
			}
			
			break;

		case STATE_ESTAB:
			//pk_debug("TCP_ESTAB:");
			if (ntohs(tcph->source) == 80)
			{
//				if (is_ack(tcph, data_len, in))		//Pass ACK from server?
//					goto ACCEPT;

				goto ACCEPT;
			}
			
			/* tlhhh 2011-1-15. add "\r\n\r\n", even if already existed */
			t->header_idx = snprintf(t->header_buff, MAX_HEADER_SIZE-1, "%s\r\n\r\n", data);
			t->header_buff[MAX_HEADER_SIZE-1] = '\0';
				
			//pk_debug("header_idx = [%d]", t->header_idx);
			memset(&Request, 0, sizeof(Request));
			
			if ( decode_http(t->header_buff, t->header_idx, &Request) < 0 ) 
			{
				//pk_debug("header can't be recognized, treate as non-standard HTTP");


				/* tlhhh 2010-01-15. 
				 * New implement: if we can not get HOST, this maybe an fragment or 
				 * other non-standard HTTP on 80.
				 * - if WP enabled: DROP this packet.
				 * - if PC enabled: check unblock and time block entries.
				 */
//__unknown_http:

				if ( filter_type & TYPE_PROC_WP ) {
					goto DROP;
				}

				if ( filter_type & TYPE_PROC_PC ) 
				{
					/* unblock check */
					if ( is_ublk_entry(ETH_HDR(*skb)->h_source) )
					{
						tcp_update_state(t, STATE_PASS);
						goto ACCEPT;
					}

					/* time block check */
					if ( is_tblk_entry(ETH_HDR(*skb)->h_source) )
					{
						if (is_white_conn(*skb)) 
						{
							//pk_debug("HTTP whitelist connection, ACCEPT");
							tcp_update_state(t, STATE_PASS);
							goto ACCEPT;
						}
						/* sorry, time filter block */
						goto DROP;
					}
				}

				goto ACCEPT;
			}
			else
			{
				nlink_packet_t *pPacket;
				
				if ( filter_type & TYPE_PROC_PC )	//Only parentral control cares the MAC.
				{
					// if unblock entry, no need to ask userspace.
					if ( is_ublk_entry(ETH_HDR(*skb)->h_source) )	/* All traffic from client(source mac) */
					{
						tcp_update_state(t, STATE_PASS);
						goto ACCEPT;
					}
				}

				//pk_debug("KERNEL: host=%s, path=%s\n",  Request.host, Request.path);
				pPacket = kmalloc(sizeof(nlink_packet_t) + sizeof(nlink_urlreq_t), GFP_ATOMIC);
				if ( pPacket == NULL )	goto ACCEPT;

				/* send rating request to daemon */
				pPacket->type = NETLINK_REQUEST;

				/* if WP enabled, impossible to get PC's traffic except _GuestNetwork_ */
				if ( filter_type & TYPE_PROC_WP &&
					strncmp(in->name, "br1", 3) && 
					strncmp(out->name, "br1", 3) )
				{
					pPacket->subtype = NETLINK_RATEURL_WP;
				}
				else
				{
					pPacket->subtype = NETLINK_RATEURL_PC;
					memcpy( PTRGET_NLREQ_MAC(pPacket), ETH_HDR(*skb)->h_source, ETHER_ADDR_LEN );
				}

				PTRGET_NLREQ_FAMILY(pPacket) = AF_INET; 
				PTRGET_NLREQ_SADDR(pPacket) = iph->saddr;
				PTRGET_NLREQ_DADDR(pPacket) = iph->daddr;
				PTRGET_NLREQ_SOURCE(pPacket) = tcph->source;
				PTRGET_NLREQ_DEST(pPacket) = tcph->dest;

				memcpy(&PTRGET_NLREQ_HTTPHEADER(pPacket), &Request, sizeof(Request));

				tm_write_lock(&t->lock);
				t->skb_copy = skb_copy(*skb, GFP_ATOMIC);
				tm_write_unlock(&t->lock);

				send_to_user(0, pPacket, sizeof(nlink_packet_t) + sizeof(nlink_urlreq_t));
				tcp_update_state(t, STATE_RATING);

				if( pPacket != NULL )	kfree(pPacket);
			}

			/* BUG from cdrouter: can not access qacafe.com if drop the first GET */
			break;
			//goto DROP;

		case STATE_RATING:
			//pk_debug("TCP_RATING:");
			goto DROP;

		case STATE_PASS:
			//pk_debug("TCP_PASS:");
			tcp_delete(t);
			break;
		case STATE_WHITE_PASS:
			//pk_debug("TCP_PASS:");
			tcp_delete(t);
			break;

		case STATE_BLOCK:
			//pk_debug("TCP_BLOCK:");
			//pk_debug(">>>>>> %u.%u.%u.%u --> %u.%u.%u.%u <<<<<<<\n", NIPQUAD(iph->saddr), NIPQUAD(iph->daddr) );
			if (ntohs(tcph->source) == 80)	/* from server */
			{
//				if ( is_ack(tcph, data_len, in) )
//				{
//					pk_debug("ACK FROM server, skip...:");
//					goto ACCEPT;
//				}
				
				pk_debug("packet FROM server, reset it");
				reset_server(*skb);
				goto DROP;
			}
			else
			{
				if ( ack_client(*skb) < 0 )
					goto DROP;

				send_blkpage(t->blk_page, *skb);
				tcp_update_state(t, STATE_REDIRECT);
			}
			
			goto DROP;


		case STATE_REDIRECT:
			//pk_debug("TCP_REDIRECT:");

			/* receive ACK from client side, to close REDIRECT HTTP response TCP */
			if (is_ack(tcph, data_len, in) && ntohs(tcph->dest) == 80)
			{
				struct sk_buff* new_skb = rebuild_packet(*skb, 0, FIN_ACK_PACKET, 1);
				if (new_skb == NULL)
				{
					pk_debug("rebuild FIN_ACK to client failed!");
					goto DROP;
				}

				output_packet(new_skb);
				tcp_update_state(t, STATE_FIN_WAIT1);

				goto DROP;
			}
			goto DROP;

		case STATE_FIN_WAIT1:
			//pk_debug("TCP_FIN_WAIT1:");
			/* bypassing server packet */
			if (ntohs(tcph->source) == 80)
			{
				goto ACCEPT;
			}

			/* ACK from client */
			if (is_ack(tcph, data_len, in))
			{
				tcp_update_state(t, STATE_FIN_WAIT2);
				goto DROP;
			}
			goto DROP;

		case STATE_FIN_WAIT2:
			//pk_debug("TCP_FIN_WAIT2:");

			/* FIXME: FIN from client */
			/* FIXME: send ACK to client */

			/* FIN, ACK from client */
			if (is_finack(tcph, data_len, in))
			{
				/********send ACK to client************/
				//close tcp tracking
				struct sk_buff* new_skb = rebuild_packet(*skb, 1, ACK_PACKET, 1);

				if (new_skb == NULL)
				{
					goto DROP;
				}
				output_packet(new_skb);

				tcp_delete(t);
				//tcp_update_state(t, STATE_BLOCK);
				goto DROP;
			}
			goto DROP;
		default:
			//pk_debug("unknown tcp tracking state.");
			goto DROP;
	}

	
ACCEPT:
    //pk_debug("Accept A Packet");
    return NF_ACCEPT;
DROP:
    //pk_debug("Drop A Packet");
    return NF_DROP;
}

#ifdef __CONFIG_IPV6__
static
unsigned int forward_hook6(unsigned int hooknum,
        struct sk_buff **skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	struct ipv6hdr *ip6h = NULL;
	unsigned char *data = NULL ;
	struct tcp_entry_t *t = NULL;
	struct tcphdr *tcph = NULL;
	unsigned int data_len = 0;
	unsigned int otcplen;
	unsigned int max_free = 0;
	int filter_type = 0;
	int tcphoff;
	u8 proto;
//	struct sk_info6 *socket_info = NULL;

	read_lock(&hnd_lock);
	if( hnd_enabled )
		filter_type |= TYPE_PROC_PC;
	read_unlock(&hnd_lock);
	
	read_lock(&wp_lock);
	if ( wp_enabled ){
		filter_type |= TYPE_PROC_WP;
	}
	read_unlock(&wp_lock);

	if ( filter_type == 0 ){
	// tlhhh. It's no hooks registered, goto ACCEPT.
		goto ACCEPT;
	}
	if (*skb == NULL){
		goto ACCEPT;
	}
	if ((in == NULL) || (out == NULL)){
		goto ACCEPT;
	}
	else if (strcmp(in->name, out->name) == 0){
		goto ACCEPT;
	}
#ifdef GUEST_NETWORK_SUPPORT
	else if (!strncmp(in->name, "br1", 3) || !strncmp(out->name, "br1", 3)){
	// 2011-Feb-22. No need to check traffic from GuestNetwork (if supported)
		goto ACCEPT;
	}
#endif

	ip6h = IP6_HDR((*skb));

	if (!(ipv6_addr_type(&ip6h->saddr) & IPV6_ADDR_UNICAST) ||
	    !(ipv6_addr_type(&ip6h->daddr) & IPV6_ADDR_UNICAST))
	{
		pk_debug("forward_hook6: IPv6 address is not unicast.\n");
		goto ACCEPT;
	}

	proto = ip6h->nexthdr;
	tcphoff = ipv6_skip_exthdr( (*skb), ((u_int8_t*)(ip6h+1) - (*skb)->data), &proto);

	if ((tcphoff <0) || (tcphoff > (*skb)->len)){
		goto ACCEPT;
	}
	
	otcplen = (*skb)->len - tcphoff;

	/* check IPv6 header to filter out non-TCP & too short packet... */
	if (proto != IPPROTO_TCP || otcplen < sizeof(struct tcphdr)) 
	{
		pk_debug("forward_hook6: proto(%d) != IPPROTO_TCP, "
			"or too short. otcplen = %d\n", proto, otcplen);
		goto ACCEPT;
	}

	pk_debug("tcphoff = %d ", tcphoff);

	tcph = (struct tcphdr *)((unsigned char *)ip6h + tcphoff);
	data = (unsigned char *)&( ((u_int32_t *)tcph)[tcph->doff] );
	data_len = (unsigned int) ((*skb)->tail - data);
		
	if (!is_http(tcph)){
		pk_debug("Not HTTP\n");
		goto ACCEPT;
	}
 
//	socket_info = (struct sk_info6 *) kmalloc( sizeof(struct sk_info6), GFP_ATOMIC );
//	if (socket_info == NULL){ goto DROP; }
//
//	socket_info->ip_family = IPV6_P;
//	memcpy(socket_info->saddr6, ip6h->saddr.s6_addr32, sizeof(__u32) *4);
//	memcpy(socket_info->daddr6, ip6h->daddr.s6_addr32 ,sizeof(__u32) *4);

	if ((t = tcp_find6(ip6h, tcph)) == NULL){
	        if (is_syn(tcph, data_len, in)){
			pk_debug("forward_hook6: add tcp SYN\n");
			tcp_add6(ip6h, tcph);
	        }
		else if ( filter_type == TYPE_PROC_PC ) //Parentral control enabled
		{
			/* find the packet from which interface, then get arp */
			if ( strncmp(in->name, "br0", 3) == 0 || strncmp(in->name, "br1", 3) == 0)		//from LAN
			{
				/* unblock check */
				if ( is_ublk_entry(ETH_HDR(*skb)->h_source) )
					goto ACCEPT;
				
				/* time block check */
				if ( is_tblk_entry(ETH_HDR(*skb)->h_source) ) 
				{
					if (is_white_conn(*skb)) {
						//pk_debug("HTTP whitelist connection, ACCEPT");
						goto ACCEPT;
					}
					/* sorry, time filter block */
					goto DROP;
				}
			}
			else //from WAN
			{
				//get client ip, then lookup arp cache.
#if 0
				if ( !arp_query( ETH_HDR(*skb)->h_source, iph->daddr, (struct net_device *)out ) )	//out from 'br0'
				{
					pk_debug( "Find in=%s, out=%s [%u.%u.%u.%u-->%u.%u.%u.%u]'s ARP cache failed\n", 
						in->name, out->name, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr) );
				}
#endif
				/* To avoid query ARP, accept all traffic from server */ 
				goto ACCEPT;
			}
		}
	        goto ACCEPT;
	}

	tcp_update_timeout6(t);

	switch (t->state)
	{
		case STATE_SYN_RCVD:
			pk_debug("STATE_SYN_RCVD:");
			if (is_ack(tcph, data_len, in)){
				// deal with normal open & simultaneous open
				tcp_update_state6(t, STATE_ESTAB);
			}
			break;

		case STATE_ESTAB:
			pk_debug("STATE_ESTAB:");
			if (ntohs(tcph->source) == 80){
				goto DROP;
			}
			
			max_free = MAX_HEADER_SIZE - (t->header_idx) -1;
			if (max_free <= 4){ goto DROP; }

			if (data_len > max_free){
				pk_debug("IPv6 header exceed buffer size(>2047), Cut Off!");
				memcpy(&t->header_buff[ t->header_idx ], data, (max_free - 4));
				t->header_idx += (max_free - 4);
				memcpy(&t->header_buff[ t->header_idx ], "\r\n\r\n", 4);
				t->header_idx += 4;
			}
			else{
				/* copy data into buffer */
				memcpy(&t->header_buff[ t->header_idx ], data, data_len);
				t->header_idx += data_len;
			}

			if ( unlikely(strlen(t->header_buff) <= 4) ){ goto DROP; }

			/* check if the last 4 bytes are \r\n\r\n in the header buffer */
			if (strncmp("\r\n\r\n", (t->header_buff + strlen(t->header_buff) - 4), 4) == 0)
			{
				req_info_t Request;
				nlink_packet_t *pPacket;
//				struct ethhdr *eth_hdr=NULL;
//				char site_local_addr[]={"FEC0::0011:22FF:FE33:4455"};

				if (decode_http(t->header_buff, t->header_idx, &Request) < 0){
					pk_debug("header can't be recognized");

					if ( filter_type & TYPE_PROC_WP ) {
						goto DROP;
					}

					if ( filter_type & TYPE_PROC_PC ) 
					{
						/* unblock check */
						if ( is_ublk_entry(ETH_HDR(*skb)->h_source) )
						{
							tcp_update_state6(t, STATE_PASS);
							goto ACCEPT;
						}

						/* time block check */
						if ( is_tblk_entry(ETH_HDR(*skb)->h_source) )
						{
							if (is_white_conn(*skb)) 
							{
								//pk_debug("HTTP whitelist connection, ACCEPT");
								tcp_update_state6(t, STATE_PASS);
								goto ACCEPT;
							}
							/* sorry, time filter block */
					tcp_update_state6(t, STATE_BLOCK);
					goto DROP;
				}
					}
					goto ACCEPT;
				}
				
				if (Request.host == NULL || strcmp(Request.host, "") == 0 ){
					goto DROP;
				}

				if ( filter_type & TYPE_PROC_PC )	//Only parentral control cares the MAC.
				{
					// if unblock entry, no need to ask userspace.
					if ( is_ublk_entry(ETH_HDR(*skb)->h_source) )	/* All traffic from client(source mac) */
					{
						tcp_update_state6(t, STATE_PASS);
						goto ACCEPT;
					}
				}

				//pk_debug("KERNEL: host=%s, path=%s\n",  Request.host, Request.path);
				pPacket = kmalloc(sizeof(nlink_packet_t) + sizeof(nlink_urlreq_t), GFP_ATOMIC);
				if ( pPacket == NULL )	goto ACCEPT;

				/* send rating request to daemon */
				pPacket->type = NETLINK_REQUEST;

				/* if WP enabled, impossible to get PC's traffic except _GuestNetwork_ */
				if ( filter_type & TYPE_PROC_WP &&
					strncmp(in->name, "br1", 3) && 
					strncmp(out->name, "br1", 3) )
				{
					pPacket->subtype = NETLINK_RATEURL_WP;
				}
				else
				{
					pPacket->subtype = NETLINK_RATEURL_PC;
					memcpy( PTRGET_NLREQ_MAC(pPacket), ETH_HDR(*skb)->h_source, ETHER_ADDR_LEN );
				}

				PTRGET_NLREQ_FAMILY(pPacket) = AF_INET6;
				memcpy(&PTRGET_NLREQ_SADDR6(pPacket), ip6h->saddr.s6_addr32, sizeof(__u32) *4);
				memcpy(&PTRGET_NLREQ_DADDR6(pPacket), ip6h->daddr.s6_addr32 ,sizeof(__u32) *4);
				//PTRGET_NLREQ_SADDR(pPacket) = iph->saddr;
				//PTRGET_NLREQ_DADDR(pPacket) = iph->daddr;
				PTRGET_NLREQ_SOURCE(pPacket) = tcph->source;
				PTRGET_NLREQ_DEST(pPacket) = tcph->dest;

				memcpy(&PTRGET_NLREQ_HTTPHEADER(pPacket), &Request, sizeof(Request));

				tm_write_lock(&t->lock);
				t->skb_copy = skb_copy(*skb, GFP_ATOMIC);
				tm_write_unlock(&t->lock);

				send_to_user(0, pPacket, sizeof(nlink_packet_t) + sizeof(nlink_urlreq_t));
				tcp_update_state(t, STATE_RATING);

				if( pPacket != NULL )	kfree(pPacket);
			}
#if 0				
				//eth_hdr = ETH_HDR((*skb));
				eth_hdr = (struct ethhdr *)skb_mac_header((*skb));
				sprintf(site_local_addr,
					"FEC0::%02X%02X:%02XFF:FE%02X:%02X%02X",
					(eth_hdr->h_dest[0]^0x02),
					 eth_hdr->h_dest[1],
					 eth_hdr->h_dest[2],
					 eth_hdr->h_dest[3],
					 eth_hdr->h_dest[4],
					 eth_hdr->h_dest[5]);
                               	/* 2011-03-31 add 
                                * IR-B0016858: DUT always ask user name & password when try to 
                                * visit a website using IPv6 address in factory default state (wireless_warning_page) */
				snprintf(t->blk_page, MAX_URL_LENGTH,
					"http://[%s]:52000/Unsecured.asp?%s%s",
					//nvram_safe_get("lan_ipv6_ipaddr"),
					site_local_addr,
					Request.host,
					Request.path);
				t->blk_page[MAX_URL_LENGTH -1] = '\0';

				tm_write_lock(&t->lock);
				t->skb_copy = skb_copy(*skb, GFP_ATOMIC);
				tm_write_unlock(&t->lock);

//				tcp_update_state6(t, STATE_RATING);
				tcp_update_state6(t, STATE_BLOCK);
			}
			else // needs other fragments...
			{ goto ACCEPT; }

			goto DROP;
#endif // 0
			break;
		case STATE_RATING:
			pk_debug("STATE_RATING:");
			goto DROP;

		case STATE_PASS:
			pk_debug("STATE_PASS:");
			tcp_delete(t);
			break;

		case STATE_WHITE_PASS:
			//pk_debug("TCP_PASS:");
			tcp_delete(t);
			break;

		case STATE_BLOCK:
			pk_debug("STATE_BLOCK:");
			if (ntohs(tcph->source) == 80){
				/* server-side: reset connection of server-side */
				reset_server6(*skb);
				goto DROP;
			}
			else{
				if (ack_client6(*skb) < 0){ goto DROP; }
				/* client-side: respond "HTTP 302 Found" */
				send_blkpage6(t->blk_page, *skb);
				tcp_update_state6(t, STATE_REDIRECT);
			}
			goto DROP;

		case STATE_REDIRECT:
			pk_debug("STATE_REDIRECT:");
			/* client-side: recv ACK of "HTTP 302 Found" and respond FIN ACK */
			if (is_ack(tcph, data_len, in) && ntohs(tcph->dest) == 80)
			{
				struct sk_buff* new_skb = NULL;
				new_skb = rebuild_packet6(*skb, data_len, FIN_ACK_PACKET, &tcphoff, 1);
				if (new_skb == NULL){
					pk_debug("rebuild FIN ACK to client failed!");
					goto DROP;
				}
				output_packet(new_skb);
				tcp_update_state6(t, STATE_FIN_WAIT1);
				goto DROP;
			}
			goto DROP;

		case STATE_FIN_WAIT1:
			pk_debug("STATE_FIN_WAIT1:");
			// bypassing server packet
			if (ntohs(tcph->source) == 80){
				goto ACCEPT;
			}

			// ACK from client
			if (is_ack(tcph, data_len, in)){
				tcp_update_state6(t, STATE_FIN_WAIT2);
				goto DROP;
			}
			goto DROP;

		case STATE_FIN_WAIT2:
			pk_debug("STATE_FIN_WAIT2:");

			/* FIXME: FIN from client */
			/* FIXME: send ACK to client */

			/* client-side: recv FIN ACK and respond ACK */
			if (is_finack(tcph, data_len, in))
			{
				struct sk_buff* new_skb = NULL;
				new_skb = rebuild_packet6(*skb, data_len, ACK_PACKET, &tcphoff, 1);
				if (new_skb == NULL){
					pk_debug("rebuild ACK to client failed!");
					goto DROP;
				}
				output_packet(new_skb);
				/* It's time to close TCP tracking of this session */
				tcp_delete6(t);
				goto DROP;
			}
			goto DROP;

		default:
			pk_debug("unknown TCP tracking state.");
			goto DROP;
	}

ACCEPT:
//    if( socket_info != NULL)
//	kfree(socket_info);
    return NF_ACCEPT;

DROP:
//    if( socket_info != NULL)
//	kfree(socket_info);
    return NF_DROP;
}
#endif /* __CONFIG_IPV6__ */

/* Hook to filter non-HTTP traffic for Wireless Warning Page 
*/
static unsigned int pct_forward_hook(unsigned int hooknum,
        struct sk_buff **skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph;
	struct pct_entry_t *f = NULL;
	u_int32_t addr = 0;
	struct tcphdr *tcph = NULL;
	req_info_t Request;
	nlink_packet_t *pPacket;
	
	if (*skb == NULL)
    {
        return NF_ACCEPT;
    }
    if ((in == NULL) || (out == NULL))
    {
        return NF_ACCEPT;
    }
    else if (strcmp(in->name, out->name) == 0)
    {
        return NF_ACCEPT;
    }
	
	iph = IP_HDR((*skb));
	
	if (is_dns(*skb))
	{
		return NF_ACCEPT;
	}
	else if (is_tcp(*skb) )
	{
		tcph = (struct tcphdr *)&(((u_int32_t*)iph)[iph->ihl]);
			
		if ( is_http(tcph) )
			return NF_ACCEPT;
	}
	
	/* fix guestnetwork fail to access the internet */
	if ( strncmp(in->name, "br1", 3) == 0 || strncmp(out->name, "br1", 3) == 0 )		//from GuestNetwork
		return NF_ACCEPT;

	/* find the packet from which interface */
	if ( strncmp(in->name, "br0", 3) == 0 )		//from LAN
	{
		addr = iph->daddr;
	}
	else	//from WAN
	{
		addr = iph->saddr;
	}
	
	f = pct_find(addr);
	/* if track is not existed, drop any traffic. */
	if ( f == NULL )
		return NF_DROP;
	
	pct_update_timeout(f);

	switch( f->state )
	{
		case STATE_INIT:	//initial state.

			memset( &Request, 0, sizeof(Request) );
			memcpy( Request.host, f->host, MAX_HOST_SIZE-1 );
			Request.host[MAX_HOST_SIZE-1] = '\0';

			pPacket = kmalloc(sizeof(nlink_packet_t) + sizeof(nlink_urlreq_t), GFP_ATOMIC);
			if( pPacket == NULL )	return NF_ACCEPT;

			/* send rating request to daemon */
			pPacket->type = NETLINK_REQUEST;
			pPacket->subtype = NETLINK_RATEURL_WP;

			PTRGET_NLREQ_SADDR(pPacket) = 0;
			PTRGET_NLREQ_DADDR(pPacket) = addr;
			PTRGET_NLREQ_SOURCE(pPacket) = 0;
			PTRGET_NLREQ_DEST(pPacket) = 0;
			//memcpy(PTRGET_NLREQ_MAC(pPacket), t->mac, 6);
			memcpy(&PTRGET_NLREQ_HTTPHEADER(pPacket), &Request, sizeof(Request));

			send_to_user(0, pPacket, sizeof(nlink_packet_t) + sizeof(nlink_urlreq_t));
			pct_update_state(f, STATE_RATING);

			if( pPacket != NULL )	kfree(pPacket);
			break;

		case STATE_RATING:
			return NF_DROP;
			
		case STATE_PASS:
			return NF_ACCEPT;
			
		case STATE_BLOCK:
		default:
			pct_delete(f);
			return NF_DROP;	
	}
	
	//default drop traffic.
	return NF_DROP;	
}
#ifdef __CONFIG_IPV6__
/* 2011-0421
 * Hook (at NF_IP6_FORWARD) to filter non-HTTP traffic for WIRELESS_WARNING_PAGE
 */
static unsigned int
pct_forward_hook6(unsigned int hooknum,
	struct sk_buff **skb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff *))
{
	u8 nexthdr;
	int offset;
	struct ipv6hdr _ipv6h, *ip6 = NULL;

	if ((*skb) == NULL){
		return NF_ACCEPT;
	}
	if ((in == NULL) || (out == NULL)){
		return NF_ACCEPT;
	}
	else if (strcmp(in->name, out->name) == 0){
		return NF_ACCEPT;
	}
#ifdef GUEST_NETWORK_SUPPORT
	else if ( !strncmp(in->name, "br1", 3) || !strncmp(out->name, "br1", 3)){
	// Spec. of the 3rd Generation F/W: It needs NOT to be implemented on GuestNetwork.
		return NF_ACCEPT;
	}
#endif

	offset = skb_network_offset( (*skb));
	ip6 = skb_header_pointer( (*skb), offset, sizeof(_ipv6h), &_ipv6h);
	if (ip6 == NULL){
		return NF_ACCEPT;
	}
	nexthdr = ip6->nexthdr;
	offset += sizeof(_ipv6h);
	offset = ipv6_skip_exthdr( (*skb), offset, &nexthdr);
	if (offset < 0){
		return NF_ACCEPT;
	}
	switch (nexthdr){
	case IPPROTO_TCP: {
		struct tcphdr _tcph, *th = NULL;
		th = skb_header_pointer( (*skb), offset, sizeof(_tcph), &_tcph);
		if ( th && ( ntohs(th->source) == 80 || ntohs(th->dest) == 80))
		// Just bypass HTTPv6 (let forward_hook6 handle other details...)
			return NF_ACCEPT;

		break;
		}
		

	case IPPROTO_UDP: {
		struct udphdr _udph, *uh = NULL;
		uh = skb_header_pointer( (*skb), offset, sizeof(_udph), &_udph);
		if ( uh && ( ntohs(uh->source) == 53 || ntohs(uh->dest) == 53))
		// Just bypass DNSv6 query & response (don't block)
			return NF_ACCEPT;

		break;
		}
	}

	// 2011-0421 ToDo: CCP Whitelist & Parent Control mechanism

	return NF_DROP;
}
#endif /*__CONFIG_IPV6__*/

/* Hook to filter non-HTTP traffic for Parental Control
*/
static unsigned int https_forward_hook(unsigned int hooknum,
        struct sk_buff **skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned char *data;
    unsigned int data_len;
    struct ssl_entry_t *s = NULL;
	req_info_t Request;
	nlink_packet_t *pPacket;
	unsigned char hwaddr[ETHER_ADDR_LEN];

	/* if wp enabled, accept all traffic, that already checked by PCT hook except GUESTNETWORK's traffic */
	read_lock(&wp_lock);
	if (wp_enabled  && in && strncmp(in->name, "br1", 3) != 0)
	{
		read_unlock(&wp_lock);
		return NF_ACCEPT;
	}
	read_unlock(&wp_lock);


    if (*skb == NULL)
    {
        return NF_ACCEPT;
    }
    if ((in == NULL) || (out == NULL))
    {
        return NF_ACCEPT;
    }
    else if (strcmp(in->name, out->name) == 0)
    {
        return NF_ACCEPT;
    }
	
	iph = IP_HDR((*skb));
	
	if (is_dns(*skb))
	{
		return NF_ACCEPT;
	}
	else if (is_tcp(*skb) )
	{
		tcph = (struct tcphdr *)&(((u_int32_t*)iph)[iph->ihl]);
		data =(unsigned char *)&(((u_int32_t*)tcph)[tcph->doff]);
		data_len = (*skb)->tail - data;
			
		if ( is_http(tcph) )
		{
			return NF_ACCEPT;
		}
	}

	memset(hwaddr, 0, sizeof(hwaddr));
	
	/* find the packet from which interface, then get arp */
	if ( strncmp(in->name, "br0", 3) == 0 || strncmp(in->name, "br1", 3) == 0 )		//from Guestnetwork/LAN
	{
		memcpy( hwaddr, ETH_HDR(*skb)->h_source, ETHER_ADDR_LEN );
	}
	else	//from WAN
	{
		//get client ip, then lookup arp cache.
		if ( !arp_query( hwaddr, iph->daddr, out) )	//out from 'br0'
		{
			pk_debug( "Find in=%s, out=%s [%u.%u.%u.%u-->%u.%u.%u.%u]'s ARP cache failed\n", 
				in->name, out->name, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr) );
			goto ACCEPT;
		}
	}

	if ( is_ublk_entry(hwaddr) )
		goto ACCEPT;

	
	//pk_debug( "%u.%u.%u.%u <---> %u.%u.%u.%u",  NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));

	/* Here are HTTPs and other non-HTTP traffic */
	if ((s = ssl_find_with_trust(iph)) == NULL)
	{
		if ((s = ssl_find(iph)) == NULL ) {

			/* time block check */
			if ( is_tblk_entry(hwaddr) )
			{
				if (is_white_conn(*skb)) {
					//pk_debug("non-HTTP whitelist connection, ACCEPT");
					goto ACCEPT;
				}
				/* sorry, time filter block */
				goto DROP;
			}
			
			return NF_ACCEPT;
		}
		
		if (unlikely(s->nfconn == NULL)) {
			if (ssl_update_nfconn(s, *skb) < 0)
				goto DROP;
		}
		
		/* if there no connection can _not_ be trusted. reset conntrack state to ESTAB, 
		 * and ask userspace to check the state.
		 */
		ssl_update_state(s, STATE_ESTAB);
	}
	else	//trustable
	{
		ssl_update_timeout(s);

		if (unlikely(s->nfconn == NULL)) {
			if (ssl_update_nfconn(s, *skb) < 0)
				goto DROP;
		}

		/* tlhhh. Generally, if state is trustable, 
		 * there are only two results: PASS or BLOCK. 
		 * so, DROP conntracks on other states.
		 */
		switch (s->state)
		{
			case STATE_PASS:
				//pk_debug("TRUST_SSL_TRACKING_PASS:");
				goto ACCEPT;

			case STATE_WHITE_PASS:
				//pk_debug("TRUST_SSL_TRACKING_WHITE_PASS:");
				goto ACCEPT;

			case STATE_BLOCK:
			default:
				//pk_debug("TRUST_SSL_TRACKING_BLOCK:");
				goto DROP;
		}
		goto DROP;
	}
	
	ssl_update_timeout(s);
	
	switch (s->state)
	{
		case STATE_ESTAB:
			
			memset(&Request, 0, sizeof(req_info_t));
			strcpy(Request.path, "/");
			memcpy(Request.host, s->host, MAX_HOST_SIZE-1);
			Request.host[MAX_HOST_SIZE-1] = '\0';

			/* send rating request to daemon */
			pPacket = kmalloc(sizeof(nlink_packet_t) + sizeof(nlink_urlreq_t), GFP_ATOMIC);
			if( pPacket == NULL )
			{
				goto ACCEPT;
			}

			pPacket->type = NETLINK_REQUEST;
			pPacket->subtype = NETLINK_RATEURL_PC;
			
			PTRGET_NLREQ_FAMILY(pPacket) = AF_INET; 
			PTRGET_NLREQ_SADDR(pPacket) = s->saddr;	
			PTRGET_NLREQ_DADDR(pPacket) = s->daddr;
			PTRGET_NLREQ_SOURCE(pPacket) = 0;
			PTRGET_NLREQ_DEST(pPacket) = 0;

			memcpy( PTRGET_NLREQ_MAC(pPacket), hwaddr, ETHER_ADDR_LEN );
			memcpy(&PTRGET_NLREQ_HTTPHEADER(pPacket), &Request, sizeof(Request));


			send_to_user(0, pPacket, sizeof(nlink_packet_t) + sizeof(nlink_urlreq_t));

			if( pPacket != NULL )	kfree(pPacket);

			ssl_update_state(s, STATE_RATING);
			goto DROP;

		case STATE_RATING:
			/* we are waiting for rating result */
			//pk_debug("SSL_TRACKING_RATING:");
			goto DROP;

		case STATE_PASS:
			//pk_debug("SSL_TRACKING_PASS:");
			/* we dont need to monitor a PASS connection. */
			//ssl_delete(s);
			break;
		
		case STATE_WHITE_PASS:
			break;

		case STATE_BLOCK:
		default:
			//pk_debug("SSL_TRACKING_BLOCK:");
			goto DROP;
	}

ACCEPT:
	return NF_ACCEPT;
DROP:
	return NF_DROP;
}

static unsigned int https6_forward_hook(unsigned int hooknum,
        struct sk_buff **skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
  struct ipv6hdr *ip6h;
	int offset;
  struct tcphdr *tcph;
  unsigned char *data;
  unsigned int data_len;
  struct ssl6_entry_t *s = NULL;
	req_info_t Request;
	nlink_packet_t *pPacket;
	unsigned char hwaddr[ETHER_ADDR_LEN];
	u8 proto;
	

	/* if wp enabled, accept all traffic, that already checked by PCT hook except GUESTNETWORK's traffic */
	read_lock(&wp_lock);
	if (wp_enabled  && in && strncmp(in->name, "br1", 3) != 0)
	{
		read_unlock(&wp_lock);
		return NF_ACCEPT;
	}
	read_unlock(&wp_lock);


    if (*skb == NULL)
    {
        return NF_ACCEPT;
    }
    if ((in == NULL) || (out == NULL))
    {
        return NF_ACCEPT;
    }
    else if (strcmp(in->name, out->name) == 0)
    {
        return NF_ACCEPT;
    }
	
	ip6h = IP6_HDR((*skb));
	if (!(ipv6_addr_type(&ip6h->saddr) & IPV6_ADDR_UNICAST) ||
	    !(ipv6_addr_type(&ip6h->daddr) & IPV6_ADDR_UNICAST))
	{
		pk_debug("forward_hook6: IPv6 address is not unicast.\n");
		goto ACCEPT;
	}

	proto = ip6h->nexthdr;
	offset = ipv6_skip_exthdr( (*skb), ((u_int8_t*)(ip6h+1) - (*skb)->data), &proto);
	
	if (proto == IPPROTO_UDP)	
	{	
		data_len = ((*skb)->tail - ((unsigned char *)ip6h + offset)) - 8;
		if(is_dns6((struct udphdr *)((unsigned char *)ip6h + offset), data_len))			
			return NF_ACCEPT;
	}
	else if (proto == IPPROTO_TCP)
	{
		tcph = (struct tcphdr *)((unsigned char *)ip6h + offset);
		data =(unsigned char *)&(((u_int32_t*)tcph)[tcph->doff]);
		data_len = (*skb)->tail - data;
			
		if ( is_http(tcph) )
		{
			return NF_ACCEPT;
		}
	}


	memset(hwaddr, 0, sizeof(hwaddr));
	
	/* find the packet from which interface, then get arp */
	if ( strncmp(in->name, "br0", 3) == 0 || strncmp(in->name, "br1", 3) == 0 )		//from Guestnetwork/LAN
	{
		memcpy( hwaddr, ETH_HDR(*skb)->h_source, ETHER_ADDR_LEN );
	}
	else	//from WAN
	{
		//get client ip, then lookup arp cache.
		if ( !nd_query( hwaddr, &ip6h->daddr, out) )	//out from 'br0'
		{
			pk_debug("nd_query failed.\n");
			goto ACCEPT;
		}
	}

	if ( is_ublk_entry(hwaddr) )
		goto ACCEPT;

	
	//pk_debug( "%u.%u.%u.%u <---> %u.%u.%u.%u",  NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));

	/* Here are HTTPs and other non-HTTP traffic */
	if ((s = ssl6_find_with_trust(ip6h)) == NULL)
	{
		if ((s = ssl6_find(ip6h)) == NULL ) {

			/* time block check */
			if ( is_tblk_entry(hwaddr) )
			{
				if (is_white_conn(*skb)) {
					//pk_debug("non-HTTP whitelist connection, ACCEPT");
					goto ACCEPT;
				}
				/* sorry, time filter block */
				goto DROP;
			}
			
			return NF_ACCEPT;
		}
		
		if (unlikely(s->nfconn == NULL)) {
			if (ssl6_update_nfconn(s, *skb) < 0)
				goto DROP;
		}
		
		/* if there no connection can _not_ be trusted. reset conntrack state to ESTAB, 
		 * and ask userspace to check the state.
		 */
		ssl6_update_state(s, STATE_ESTAB);
	}
	else	//trustable
	{
		ssl6_update_timeout(s);

		if (unlikely(s->nfconn == NULL)) {
			if (ssl6_update_nfconn(s, *skb) < 0)
				goto DROP;
		}

		/* tlhhh. Generally, if state is trustable, 
		 * there are only two results: PASS or BLOCK. 
		 * so, DROP conntracks on other states.
		 */
		switch (s->state)
		{
			case STATE_PASS:
				//pk_debug("TRUST_SSL_TRACKING_PASS:");
				goto ACCEPT;

			case STATE_WHITE_PASS:
				//pk_debug("TRUST_SSL_TRACKING_WHITE_PASS:");
				goto ACCEPT;

			case STATE_BLOCK:
			default:
				//pk_debug("TRUST_SSL_TRACKING_BLOCK:");
				goto DROP;
		}
		goto DROP;
	}
	
	ssl6_update_timeout(s);
	
	switch (s->state)
	{
		case STATE_ESTAB:
			
			memset(&Request, 0, sizeof(req_info_t));
			strcpy(Request.path, "/");
			memcpy(Request.host, s->host, MAX_HOST_SIZE-1);
			Request.host[MAX_HOST_SIZE-1] = '\0';

			/* send rating request to daemon */
			pPacket = kmalloc(sizeof(nlink_packet_t) + sizeof(nlink_urlreq_t), GFP_ATOMIC);
			if( pPacket == NULL )
			{
				goto ACCEPT;
			}

			pPacket->type = NETLINK_REQUEST;
			pPacket->subtype = NETLINK_RATEURL_PC;
			
			PTRGET_NLREQ_FAMILY(pPacket) = AF_INET6;
			memcpy(&PTRGET_NLREQ_SADDR6(pPacket), ip6h->saddr.s6_addr32, sizeof(__u32) *4);
			memcpy(&PTRGET_NLREQ_DADDR6(pPacket), ip6h->daddr.s6_addr32 ,sizeof(__u32) *4);
			PTRGET_NLREQ_SOURCE(pPacket) = 0;
			PTRGET_NLREQ_DEST(pPacket) = 0;

			memcpy( PTRGET_NLREQ_MAC(pPacket), hwaddr, ETHER_ADDR_LEN );
			memcpy(&PTRGET_NLREQ_HTTPHEADER(pPacket), &Request, sizeof(Request));


			send_to_user(0, pPacket, sizeof(nlink_packet_t) + sizeof(nlink_urlreq_t));

			if( pPacket != NULL )	kfree(pPacket);

			ssl6_update_state(s, STATE_RATING);
			goto DROP;

		case STATE_RATING:
			/* we are waiting for rating result */
			//pk_debug("SSL_TRACKING_RATING:");
			goto DROP;

		case STATE_PASS:
			//pk_debug("SSL_TRACKING_PASS:");
			/* we dont need to monitor a PASS connection. */
			//ssl_delete(s);
			break;
		
		case STATE_WHITE_PASS:
			break;

		case STATE_BLOCK:
		default:
			//pk_debug("SSL_TRACKING_BLOCK:");
			goto DROP;
	}

ACCEPT:
	return NF_ACCEPT;
DROP:
	return NF_DROP;
}

static struct nf_hook_ops hook_ops =
{
    .hook       = forward_hook,
    .pf         = PF_INET,
    .hooknum    = NF_IP_FORWARD,
    //.priority   = NF_IP_PRI_FILTER,
    .priority   = NF_IP_PRI_FIRST,
};
#ifdef __CONFIG_IPV6__
static struct nf_hook_ops hook_ops6 =
{
	.hook		= forward_hook6,
	.pf		= PF_INET6,
	.hooknum	= NF_IP6_FORWARD,
	.priority	= NF_IP6_PRI_FIRST,	
};
#endif

//tlhhh
static struct nf_hook_ops dns_hook_ops =
{
    .hook       = dns_hook,
    .pf         = PF_INET,
    .hooknum    = NF_IP_PRE_ROUTING,
    .priority   = NF_IP_PRI_FIRST,
};

#ifdef __CONFIG_IPV6__
static struct nf_hook_ops dns6_hook_ops =
{
	.hook       = dns6_hook,
	.pf         = PF_INET6,
	.hooknum    = NF_IP6_PRE_ROUTING,
	.priority   = NF_IP6_PRI_FIRST,
};
#endif

static struct nf_hook_ops pct_hook_ops =
{
    .hook       = pct_forward_hook,
    .pf         = PF_INET,
    .hooknum    = NF_IP_FORWARD,
    .priority   = NF_IP_PRI_FIRST + 1,
};
#ifdef __CONFIG_IPV6__
static struct nf_hook_ops pct_hook_ops6 =
{
    .hook       = pct_forward_hook6,
    .pf         = PF_INET6,
    .hooknum    = NF_IP6_FORWARD,
    .priority   = NF_IP6_PRI_FIRST +1,
};
#endif


static struct nf_hook_ops https_hook_ops =
{
    .hook       = https_forward_hook,
    .pf         = PF_INET,
    .hooknum    = NF_IP_FORWARD,
    .priority   = NF_IP_PRI_FIRST + 2,
};

static struct nf_hook_ops https6_hook_ops =
{
    .hook       = https6_forward_hook,
    .pf         = PF_INET6,
    .hooknum    = NF_IP6_FORWARD,
    .priority   = NF_IP6_PRI_FIRST + 2,
};

static int hnd_hook(void)
{
	write_lock(&hnd_lock);
	
	if (hnd_enabled != 0)
    {
        pk_warn("hook already registered");
        write_unlock(&hnd_lock);
        return 0;
    }
	
	//tlhhh
	if (nf_register_hook(&https_hook_ops) < 0)
	{
		pk_err("nf_register_hook fail");
		write_unlock(&hnd_lock);
		return -EFAULT;
	}
	
	if (nf_register_hook(&https6_hook_ops) < 0)
	{
		pk_err("nf_register_hook fail");
		write_unlock(&hnd_lock);
		return -EFAULT;
	}
	
	hnd_enabled = 1;
	
	pk_info("Parental Control => Enable");
	write_unlock(&hnd_lock);

	return 0;
}

static int hnd_unhook(void)
{
    write_lock(&hnd_lock);
	
	if (hnd_enabled != 1)
    {
        pk_warn("hook already unregistered");
        write_unlock(&hnd_lock);
        return 0;
    }
	
	//tlhhh
	nf_unregister_hook(&https_hook_ops);
	nf_unregister_hook(&https6_hook_ops);

	hnd_enabled = 0;

	pk_info("Parental Control => Disable");
	write_unlock(&hnd_lock);

	return 0;
}

static int wp_hook(void)
{
    write_lock(&wp_lock);

    if (wp_enabled != 0)
    {
        pk_warn("hook already registered");
        write_unlock(&wp_lock);
        return 0;
    }

	//tlhhh
	if (nf_register_hook(&pct_hook_ops) < 0)
	{
        pk_err("nf_register_hook fail");
        write_unlock(&wp_lock);
        return -EFAULT;
    }

	if ( nf_register_hook(&pct_hook_ops6) < 0){
		pk_err("nf_register_hook6 fail");
		write_unlock(&wp_lock);
		return -EFAULT;
	}

    wp_enabled = 1;

    pk_info("Wireless warning page => Enable");

    write_unlock(&wp_lock);
    return 0;
}

static int wp_unhook(void)
{
    write_lock(&wp_lock);
    if (wp_enabled != 1)
    {
        pk_warn("hook already unregistered");
        write_unlock(&wp_lock);
        return 0;
    }
    nf_unregister_hook(&pct_hook_ops);
    nf_unregister_hook(&pct_hook_ops6);

    wp_enabled = 0;

    pk_info("exit netfiler hook on demand");
    write_unlock(&wp_lock);

    return 0;
}

static int receive_from_user(void *data, int type, unsigned int len)
{
    struct iphdr iph;
    struct tcphdr tcph;
    struct tcp_entry_t *t = NULL;
    struct ssl_entry_t *s = NULL;
    struct pct_entry_t *f = NULL;
    nlink_packet_t *packet = (nlink_packet_t *)data;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	struct nf_conn *nfconn = NULL;
#else
	struct ip_conntrack *nfconn = NULL;
#endif

		if(PTRGET_NLRES_FAMILY(packet) == AF_INET6)
		  return handle6(data, type, len);

    if ( (packet->type != NETLINK_RESPONSE) || 
		(packet->subtype != NETLINK_URLRESULT_PC && packet->subtype != NETLINK_URLRESULT_WP) )
    {
        pk_err("unexpected packet type incoming to hook, %d, %d", 
                packet->type,
                packet->subtype);
        return -1;
    }

    iph.saddr = PTRGET_NLRES_SADDR(packet);
    iph.daddr = PTRGET_NLRES_DADDR(packet);
    tcph.source = PTRGET_NLRES_SOURCE(packet);
    tcph.dest = PTRGET_NLRES_DEST(packet);
			
	if( packet->subtype == NETLINK_URLRESULT_WP )
	{
		if ( iph.saddr == 0 && tcph.source == 0 && tcph.dest == 0 )
		{
			//pk_debug("URL result for [wireless warning page] non-HTTP traffic");

			f = pct_find(iph.daddr);

			if (f != NULL)
			{
				switch (PTRGET_NLRES_RESULTCODE(packet))
				{
					case NETLINK_PASS:
						//pk_debug("pct tracking accept");
						pk_debug("[WP]non-HTTP: host=%s --> PASS", f->host);
						pct_update_state(f, STATE_PASS);
						break;
					case NETLINK_FAIL:
						//pk_debug("pct tracking deny");
						pk_debug("[WP]non-HTTP: host=%s --> BLOCK", f->host);
						pct_update_state(f, STATE_BLOCK);
						break;
					default:
						pct_update_state(f, STATE_BLOCK);
						//pk_debug("unknown packet result type");
						break;
				}
			}
			else
			{
				pk_debug("no pct tracking found");
			}

			return 0;
		}
	}
	else if (packet->subtype == NETLINK_URLRESULT_PC )
	{
		if ( tcph.source == 0 && tcph.dest == 0 )
		{
			//pk_debug("URL result for [parental_control] non-HTTP traffic");
			
			s = ssl_find(&iph);

			if (s != NULL)
			{

				switch (PTRGET_NLRES_RESULTCODE(packet))
				{
					case NETLINK_PASS:
						//pk_debug("ssl tracking accept");
						pk_debug("[PC]non-HTTP: host=%s --> PASS", s->host);
						ssl_update_state(s, STATE_PASS);
						ssl_update_trust(s, 1);

						break;
					case NETLINK_WHITE_PASS:
						//pk_debug("ssl tracking accept");
						pk_debug("[PC]non-HTTP: host=%s --> WHITE_PASS", s->host);
						ssl_update_state(s, STATE_WHITE_PASS);
						ssl_update_trust(s, 1);

						tm_write_lock(&s->lock);	/* need be locked */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
						nfconn = (struct nf_conn *)s->nfconn;
#else
						nfconn = (struct ip_conntrack *)s->nfconn;
#endif
						if (nfconn) {
							nfconn->whitelist = 1;	//mark this connection to whitelist.
						}
						tm_write_unlock(&s->lock);

						break;
					case NETLINK_FAIL:
						//pk_debug("ssl tracking deny");
						pk_debug("[PC]non-HTTP: host=%s --> BLOCK", s->host);
						ssl_update_state(s, STATE_BLOCK);
						ssl_update_trust(s, 1);

						break;
					default:
						//pk_debug("unknown packet result type=%d", PTRGET_NLRES_RESULTCODE(packet));
						break;
				}
			}
			else
			{
				pk_debug("no ssl tracking found");
			}

			return 0;
		}
	}
	else
	{
		return 0;
	}
	
	t = tcp_find(&iph, &tcph);

	if (t != NULL)
	{
		tm_write_lock(&t->lock);
		strncpy(t->blk_page, PTRGET_NLRES_BLOCKLOC(packet), MAX_URL_LENGTH - 1);
		t->blk_page[MAX_URL_LENGTH - 1] = '\0';

		//remove tcp_update_state to avoid deadlock. tlhhh 2010-10-29.
		switch (PTRGET_NLRES_RESULTCODE(packet))
		{
			case NETLINK_PASS:
				//pk_debug("tcp tracking accept");
				pk_debug("[%s]HTTP: connection=[%u.%u.%u.%u - %u.%u.%u.%u] --> PASS", 
						packet->subtype == NETLINK_URLRESULT_WP ? "WP" :"PC", 
						NIPQUAD(PTRGET_NLRES_SADDR(packet)), 
						NIPQUAD(PTRGET_NLRES_DADDR(packet)) );

				t->state =  STATE_PASS;
				output_packet(t->skb_copy);

				break;
			case NETLINK_WHITE_PASS:
				pk_debug("[%s]HTTP: connection=[%u.%u.%u.%u - %u.%u.%u.%u] --> WHITE_PASS", 
						packet->subtype == NETLINK_URLRESULT_WP ? "WP" :"PC", 
						NIPQUAD(PTRGET_NLRES_SADDR(packet)), 
						NIPQUAD(PTRGET_NLRES_DADDR(packet)) );
				
				t->state =  STATE_WHITE_PASS;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
				nfconn = (struct nf_conn *)t->nfconn;
#else
				nfconn = (struct ip_conntrack *)t->nfconn;
#endif
				if (nfconn) {
					nfconn->whitelist = 1;	//mark this connection white.
				}

				output_packet(t->skb_copy);

				break;
			case NETLINK_FAIL:
				//pk_debug("tcp tracking deny" );
				pk_debug("[%s]HTTP: connection=[%u.%u.%u.%u - %u.%u.%u.%u] --> BLOCK", 
						packet->subtype == NETLINK_URLRESULT_WP ? "WP" :"PC", 
						NIPQUAD(PTRGET_NLRES_SADDR(packet)), 
						NIPQUAD(PTRGET_NLRES_DADDR(packet)) );
				t->state =  STATE_BLOCK;
				
				ack_client(t->skb_copy);	//skb_copy from client
				send_blkpage(PTRGET_NLRES_BLOCKLOC(packet), t->skb_copy);

				kfree_skb(t->skb_copy);
				
				t->state =  STATE_REDIRECT;
				break;
			default:
				//pk_debug("%s:unknown packet result type");
				break;
		}
		tm_write_unlock(&t->lock);
	}
	else
	{
		pk_debug("no tcp tracking found");
	}

		
    return 0;
}

static int handle6(void *data, int type, unsigned int len)
{
    struct ipv6hdr ip6h;
    struct tcphdr tcph;
    struct tcp_entry_t *t = NULL;
    struct ssl6_entry_t *s = NULL;
    struct pct6_entry_t *f = NULL;
    nlink_packet_t *packet = (nlink_packet_t *)data;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	struct nf_conn *nfconn = NULL;
#else
	struct ip_conntrack *nfconn = NULL;
#endif
	__u32 zeroaddr[4]={0L, 0L, 0L, 0L};		

    if ( (packet->type != NETLINK_RESPONSE) || 
		(packet->subtype != NETLINK_URLRESULT_PC && packet->subtype != NETLINK_URLRESULT_WP) )
    {
        pk_err("unexpected packet type incoming to hook, %d, %d", 
                packet->type,
                packet->subtype);
        return -1;
    }

    memcpy((unsigned char *)&ip6h.saddr, (unsigned char *)&PTRGET_NLRES_SADDR(packet), sizeof(__u32) *4);
    memcpy((unsigned char *)&ip6h.daddr, (unsigned char *)&PTRGET_NLRES_DADDR(packet), sizeof(__u32) *4);
    tcph.source = PTRGET_NLRES_SOURCE(packet);
    tcph.dest = PTRGET_NLRES_DEST(packet);
			
		if( packet->subtype == NETLINK_URLRESULT_WP )
		{
			if ( memcmp((unsigned char *)&ip6h.saddr, (unsigned char *)&zeroaddr, sizeof(__u32) *4) && 
					 tcph.source == 0 && tcph.dest == 0 )
			{
			//pk_debug("URL result for [wireless warning page] non-HTTP traffic");

			f = pct6_find(&ip6h.daddr);

			if (f != NULL)
			{
				
				switch (PTRGET_NLRES_RESULTCODE(packet))
				{
					case NETLINK_PASS:
						//pk_debug("pct tracking accept");
						pk_debug("[WP]non-HTTP: host=%s --> PASS", f->host);
						pct6_update_state(f, STATE_PASS);
						break;
					case NETLINK_FAIL:
						//pk_debug("pct tracking deny");
						pk_debug("[WP]non-HTTP: host=%s --> BLOCK", f->host);
						pct6_update_state(f, STATE_BLOCK);
						break;
					default:
						pct6_update_state(f, STATE_BLOCK);
						//pk_debug("unknown packet result type");
						break;
				}
			}
			else
			{
				pk_debug("no pct tracking found");
			}

			return 0;
		}
	}
	else if (packet->subtype == NETLINK_URLRESULT_PC )
	{
		if ( tcph.source == 0 && tcph.dest == 0 )
		{
			//pk_debug("URL result for [parental_control] non-HTTP traffic");
			
			s = ssl6_find(&ip6h);

			if (s != NULL)
			{

				switch (PTRGET_NLRES_RESULTCODE(packet))
				{
					case NETLINK_PASS:
						//pk_debug("ssl tracking accept");
						pk_debug("[PC]non-HTTP: host=%s --> PASS", s->host);
						ssl6_update_state(s, STATE_PASS);
						ssl6_update_trust(s, 1);

						break;
					case NETLINK_WHITE_PASS:
						//pk_debug("ssl tracking accept");
						pk_debug("[PC]non-HTTP: host=%s --> WHITE_PASS", s->host);
						ssl6_update_state(s, STATE_WHITE_PASS);
						ssl6_update_trust(s, 1);

						tm_write_lock(&s->lock);	/* need be locked */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
						nfconn = (struct nf_conn *)s->nfconn;
#else
						nfconn = (struct ip_conntrack *)s->nfconn;
#endif
						if (nfconn) {
							nfconn->whitelist = 1;	//mark this connection to whitelist.
						}
						tm_write_unlock(&s->lock);

						break;
					case NETLINK_FAIL:
						//pk_debug("ssl tracking deny");
						pk_debug("[PC]non-HTTP: host=%s --> BLOCK", s->host);
						ssl6_update_state(s, STATE_BLOCK);
						ssl6_update_trust(s, 1);

						break;
					default:
						//pk_debug("unknown packet result type=%d", PTRGET_NLRES_RESULTCODE(packet));
						break;
				}
			}
			else
			{
				pk_debug("no ssl tracking found");
			}

			return 0;
		}
	}
	else
	{
		return 0;
	}
	
	t = tcp_find6(&ip6h, &tcph);

	if (t != NULL)
	{
		tm_write_lock(&t->lock);
		strncpy(t->blk_page, PTRGET_NLRES_BLOCKLOC(packet), MAX_URL_LENGTH - 1);
		t->blk_page[MAX_URL_LENGTH - 1] = '\0';

		//remove tcp_update_state to avoid deadlock. tlhhh 2010-10-29.
		switch (PTRGET_NLRES_RESULTCODE(packet))
		{
			case NETLINK_PASS:
				t->state =  STATE_PASS;
				output_packet(t->skb_copy);

				break;
			case NETLINK_WHITE_PASS:				
				t->state =  STATE_WHITE_PASS;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
				nfconn = (struct nf_conn *)t->nfconn;
#else
				nfconn = (struct ip_conntrack *)t->nfconn;
#endif
				if (nfconn) {
					nfconn->whitelist = 1;	//mark this connection white.
				}

				output_packet(t->skb_copy);

				break;
			case NETLINK_FAIL:
				t->state =  STATE_BLOCK;
				
				ack_client(t->skb_copy);	//skb_copy from client
				send_blkpage6(PTRGET_NLRES_BLOCKLOC(packet), t->skb_copy);

				kfree_skb(t->skb_copy);
				
				t->state =  STATE_REDIRECT;
				break;
			default:
				//pk_debug("%s:unknown packet result type");
				break;
		}
		tm_write_unlock(&t->lock);
	}
	else
	{
		pk_debug("no tcp tracking found");
	}

		
    return 0;
}

/* userspace --> kernel */
ssize_t wp_proc_write( struct file *filp, const char *buff, unsigned long len, void *data )
{
	unsigned char string[2];

	memset(string, 0, sizeof(string));
	
	if( len > sizeof(string) )
		return len;
	if( !buff )
		return len;

	if( copy_from_user(string, buff, len) )
	{
		return -EFAULT;
	}
	string[1] = '\0';

	switch( *string )
	{
		case '0':
			pk_debug("--- Disable wireless warning page ---");
			wp_unhook();	//disable
			break;
		case '1':
			pk_debug("--- Enable wireless warning page ---");
			wp_hook();	//enable
			break;
		default:
			pk_debug("--- string=0x%x ---", *string);
			break;	//do nothing
	}

	return len;
}

ssize_t pc_proc_write( struct file *filp, const char *buff, unsigned long len, void *data )
{
	unsigned char string[2];

	memset(string, 0, sizeof(string));

	if( len > sizeof(string) )
		return len;
	if( !buff )
		return len;

	if( copy_from_user(string, buff, len) )
	{
		return -EFAULT;
	}
	string[1] = '\0';

	switch( *string )
	{
		case '0':
			pk_debug("--- Disable HND ---");
			hnd_unhook();	//disable
			break;
		case '1':
			pk_debug("--- Enable HND ---");
			hnd_hook();	//enable
			break;
		default:
			pk_debug("--- string=0x%x ---", *string);
			break;	//do nothing
	}

	return len;
}

int create_proc(int type)
{
	struct proc_dir_entry *proc_entry;

	if ( type & TYPE_PROC_WP )
		proc_entry = create_proc_entry( "wl_warning_page", 0644, NULL );
	else if (type & TYPE_PROC_PC )
		proc_entry = create_proc_entry( "hnd_proc", 0644, NULL );
	else
		return 0;

	if (proc_entry == NULL) 
	{
		pk_err("create proc entry failed!");
		return -ENOMEM;
		
	}
	else
	{
		proc_entry->read_proc = NULL;
		proc_entry->write_proc = type & TYPE_PROC_WP ? wp_proc_write : pc_proc_write;

		proc_entry->owner = THIS_MODULE;
	}

	return 0;
}

void remove_proc(int type)
{
	if ( type & TYPE_PROC_WP )
		remove_proc_entry("wl_warning_page", NULL);
	else if ( type & TYPE_PROC_PC )
		remove_proc_entry("hnd_proc", NULL);

	return;
}

static int __init init(void)
{
	if( tblock_init()!= 0)
	{
		pk_err("tblock_init fail");
		return -EFAULT;
	}

	if( unblock_init()!= 0)
	{
		pk_err("unblock_init fail");
		return -EFAULT;
	}
	
    if (cbt_tcp_init() == -1)
    {
        pk_err("tcp_init fail");
        return -EFAULT;
    }
    pk_info("tcp_init ok");

    if (dns_init() == -1)
    {
        pk_err("dns_init fail");
        return -EFAULT;
    }
    pk_info("dns_init ok");

	if (pct_init() == -1)
    {
        pk_err("pct_init fail");
        return -EFAULT;
    }
    pk_info("pct_init ok");
	
    if (pct6_init() == -1)
    {
        pk_err("pct6_init fail");
        return -EFAULT;
    }
    pk_info("pct6_init ok");
    
	//tlhhh. preallocate SSL tracking table.
	if (ssl_init() == -1)
    {
        pk_err("ssl_init fail");
        return -EFAULT;
    }
    pk_info("ssl_init ok");

    if (ssl6_init() == -1)
    {
        pk_err("ssl6_init fail");
        return -EFAULT;
    }
    pk_info("ssl6_init ok");
	
    if (nf_register_hook(&hook_ops) < 0)
    {
        pk_err("nf_register_hook fail");
        return -EFAULT;
    }
#ifdef __CONFIG_IPV6__
    if(nf_register_hook(&hook_ops6)<0)
    {
		pk_err("nf_register_hook(hook_ops6) fail");
		return -EFAULT;
    }
#endif
	//tlhhh. register dns_hook as static
	if (nf_register_hook(&dns_hook_ops) < 0)
    {
        pk_err("nf_register_hook(dns_hook_ops) fail");
        return -EFAULT;
    }

#ifdef __CONFIG_IPV6__
	if (nf_register_hook(&dns6_hook_ops) < 0)
	{
		pk_err("nf_register_hook(dns6_hook_ops) fail");
		return -EFAULT;
	}
#endif
	
	if( create_proc(TYPE_PROC_WP) != 0 ) 
	{
		return -ENOMEM;	
	}

	if( create_proc(TYPE_PROC_PC) != 0 ) 
	{
		return -ENOMEM;	
	}
	
    nlink_init(receive_from_user);

    return 0;
}

static void __exit uninit(void)
{
    nlink_fini();
    
	remove_proc(TYPE_PROC_PC);
	remove_proc(TYPE_PROC_WP);
	
	//tlhhh. unregister dns_hook when this module will be rmmoded.
	nf_unregister_hook(&dns_hook_ops);
#ifdef __CONFIG_IPV6__
	nf_unregister_hook(&dns6_hook_ops);
#endif
	nf_unregister_hook(&hook_ops);
#ifdef __CONFIG_IPV6__
	nf_unregister_hook(&hook_ops6);
#endif

    ssl_fini();
    pct_fini();
    ssl6_fini();
    pct6_fini();
    dns_fini();
	cbt_tcp_fini();

    wp_unhook();
    hnd_unhook();
	
	unblock_fini();
	tblock_fini();
}

module_init(init);
module_exit(uninit);
MODULE_LICENSE("GPL");

