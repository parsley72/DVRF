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

#ifndef __KERNEL__
#define __KERNEL__
#endif
#ifndef MODULE
#define MODULE
#endif
#define LINUX

#include <linux/init.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/tcp.h>
#include <linux/netfilter_ipv4.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#include <linux/netfilter.h>
#else
#include <linux/netfilter_ipv4/ip_conntrack.h>
#endif
#include <linux/ctype.h>
#include <net/tcp.h>
#include <net/dst.h>
#include <asm/byteorder.h>
#define __CONFIG_IPV6__

#ifdef __CONFIG_IPV6__
#include <net/ipv6.h>
#include <net/ip6_route.h>
#endif

#include "log.h"
#include "defs.h"
#include "tcp_table.h"
#include "skb.h"

#define TSWAP(x, y) do { \
	typeof(x) __t; \
		__t = (x);	\
		(x) = (y);	\
		(y) = __t;	\
} while (0)

#define DEFTTL	64
#define TSWAP6(x,y) { \
	struct in6_addr tmp; \
	ipv6_addr_copy(&tmp,&(x)); \
	ipv6_addr_copy(&(x),&(y)); \
	ipv6_addr_copy(&(y),&tmp); \
}

/*
 *	--> <SEQ=x><ACK=y><LEN=len>	-->
 *	<-- <SEQ=y><ACK=x+len>		<--
 */
static void calc_seq(struct tcphdr *tcph, u_int32_t len)
{
    u_int32_t tmp;

    tmp = tcph->ack_seq;
    //ack for received bytes
    tcph->ack_seq = htonl(ntohl(tcph->seq) + len);
    //client want to receive byte.
    tcph->seq = tmp;
}

/* find route for this packet */
static int route_packet(struct sk_buff *pskb)
{
    struct rtable *rt;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	/* tlhhh. fusion code for 2.6 interface */
	struct flowi fl = { 
		.nl_u = { 
			.ip4_u ={ 
				.daddr = IP_HDR(pskb)->daddr,
				.saddr = 0,
				.tos = RT_TOS(ip_hdr(pskb)->tos) | RTO_CONN,
			} },
	};

	if (ip_route_output_key(&rt, &fl) < 0)
		return -1;
#else
	struct rt_key key;

	key.dst = IP_HDR(pskb)->daddr;
	key.src = 0;
	key.tos = RT_TOS(pskb->nh.iph->tos) | RTO_CONN;
	key.oif = 0;

	//tlhhh. Deprecated ip_route_output.
	if (ip_route_output_key(&rt, &key) != 0)
		return -1;
#endif

    dst_release(pskb->dst);		//drop old route
    pskb->dst = &rt->u.dst;
    pskb->dev = pskb->dst->dev;
    pskb->protocol = htons(ETH_P_IP);
    return 0;
}

/* rebuild a packet according the incoming skb
 * flag : tcp packet's flag
 * @swap: if switch the direction
 */
struct sk_buff *rebuild_packet(struct sk_buff *oldskb, int len, TCP_TYPE flag, int swap)
{
    struct sk_buff *nskb;
    struct tcphdr *otcph, *tcph;
    unsigned int otcplen;
    
    /* IP header checks: fragment, too short. */
    if (IP_HDR(oldskb)->frag_off & htons(IP_OFFSET)
            || oldskb->len < (IP_HDR(oldskb)->ihl<<2) + sizeof(struct tcphdr))
    {
        pk_debug("Invalid IP header");
        return NULL;
    }

    otcph = (struct tcphdr *)((u_int32_t*)IP_HDR(oldskb) + IP_HDR(oldskb)->ihl);
    otcplen = oldskb->len - IP_HDR(oldskb)->ihl*4;

    /* No RST for RST. */
    if (otcph->rst)
    {
        return NULL;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    /* Check checksum. */
    if (tcp_v4_check(otcplen, IP_HDR(oldskb)->saddr,IP_HDR(oldskb)->daddr,
                    csum_partial((char *)otcph, otcplen, 0)) != 0)
#else
	if (tcp_v4_check(otcph, otcplen, IP_HDR(oldskb)->saddr,IP_HDR(oldskb)->daddr,
                    csum_partial((char *)otcph, otcplen, 0)) != 0)
#endif
    {
        return NULL;
    }

    /* Copy skb (even if skb is about to be dropped, we can't just
       clone it because there may be other things, such as tcpdump,
       interested in it) */
    nskb = skb_copy(oldskb, GFP_ATOMIC);
    if (!nskb)
    {
        return NULL;
    }

    /* This packet will not be the same as the other: clear nf fields */
    if (swap)
    {
        nf_conntrack_put(nskb->nfct);
        nskb->nfct = NULL;
    }
    nskb->nfcache = 0;

    tcph = (struct tcphdr *)((u_int32_t*)IP_HDR(nskb) + IP_HDR(nskb)->ihl);

    /* Swap source and dest */

    if (swap)
    {
		TSWAP(IP_HDR(nskb)->saddr, IP_HDR(nskb)->daddr);
		TSWAP(tcph->source, tcph->dest);
    }

    /* Truncate to length (no data) */
    tcph->doff = sizeof(struct tcphdr)/4;
    skb_trim(nskb, IP_HDR(nskb)->ihl*4 + sizeof(struct tcphdr));
    IP_HDR(nskb)->tot_len = htons(nskb->len);

    if (swap)
    {
		calc_seq(tcph, len);
    }

    /* Reset flags */
    ((u_int8_t *)tcph)[13] = 0;
    switch (flag)
    {
		case ACK_PACKET:
			tcph->ack = 1;
			break;
		case FIN_ACK_PACKET:
			tcph->fin = 1;
			tcph->ack = 1;
			break;
		case RST_PACKET:
			tcph->rst = 1;
			tcph->ack_seq = 0;
			tcph->ack = 0;
			break;
    }

    tcph->urg_ptr = 0;

    /* TCP checksum */
    tcph->check = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    tcph->check = tcp_v4_check(sizeof(struct tcphdr), IP_HDR(nskb)->saddr, IP_HDR(nskb)->daddr,
						csum_partial((char *)tcph, sizeof(struct tcphdr), 0));
#else
	tcph->check = tcp_v4_check(tcph, sizeof(struct tcphdr), IP_HDR(nskb)->saddr, IP_HDR(nskb)->daddr,
						csum_partial((char *)tcph, sizeof(struct tcphdr), 0));	
#endif

    /* TTL, DF */
    IP_HDR(nskb)->ttl = MAXTTL;
    /* do not fragment */
    IP_HDR(nskb)->frag_off = htons(IP_DF);
    IP_HDR(nskb)->id = 0;

    /* IP checksum */
    IP_HDR(nskb)->check = 0;
    IP_HDR(nskb)->check = ip_fast_csum((unsigned char *)IP_HDR(nskb),
                                       IP_HDR(nskb)->ihl);

    /* Routing to output*/
    if (route_packet(nskb) == -1)
    {
        goto free_nskb;
    }

    /* Should never happens */
//    if (nskb->len > nskb->dst->pmtu)	//ip_fragment?
//        goto free_nskb;

    return nskb;

free_nskb:
    kfree_skb(nskb);
    return NULL;
}

/* build redirect header packet */
unsigned int redirect_packet(struct sk_buff *pskb, char *header)
{
    struct iphdr *iph = IP_HDR(pskb);
    int iphl = iph->ihl;
    struct tcphdr *tcph = (struct tcphdr *)&(((u_int32_t*)iph)[iphl]);
    int tcphl = tcph->doff;
    unsigned char *data = (unsigned char *)&(((u_int32_t*)tcph)[tcphl]);
	//int i;
    /* skb data length */
    u_int32_t datasize = pskb->tail - data;
    /* tcp payload length */
    u_int32_t headersize = strlen(header);

    tcph->window = MAX_TCP_WINDOW;	//use default window.

    /* Shrink skb size into new length (no data) */
    //skb_trim(pSkb, iphl*4 + tcphl*4);	
    skb_trim(pskb, iphl*4 + sizeof(struct tcphdr));	//Ignore any tcp options, just use the standard tcp header. tlhhh
    data = skb_put(pskb, headersize);

	memset(data, 0, headersize);
    strncpy(data, header, headersize);
	
    tcph->doff = sizeof(struct tcphdr)/4;
    IP_HDR(pskb)->tot_len = htons(pskb->len);

    tcph->urg = 0;
    tcph->ack = 1;
    tcph->psh = 1;
    tcph->rst = 0;
    tcph->syn = 0;
    tcph->fin = 0;

    /* calculate reply seq & ack_seq */
    calc_seq(tcph, datasize);

    /* Swap source and dest */
	TSWAP(iph->saddr, iph->daddr);
	TSWAP(tcph->source, tcph->dest);

    /* Adjust TCP checksum */
    tcph->check = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    tcph->check = tcp_v4_check(pskb->len - 4*iph->ihl, iph->saddr, iph->daddr,
							csum_partial((char *)tcph, pskb->len-4*iph->ihl, 0));
#else
    tcph->check = tcp_v4_check(tcph, pskb->len - 4*iph->ihl, iph->saddr, iph->daddr,
							csum_partial((char *)tcph, pskb->len-4*iph->ihl, 0));
#endif

    /* TTL, DF */
    IP_HDR(pskb)->ttl = MAXTTL;
    /* Set DF, id = 0 */
    IP_HDR(pskb)->frag_off = htons(0);
    IP_HDR(pskb)->id = 0;

    /* IP checksum */
    IP_HDR(pskb)->check = 0;
    IP_HDR(pskb)->check = ip_fast_csum((unsigned char *)IP_HDR(pskb),
                                       IP_HDR(pskb)->ihl);

    if (route_packet(pskb) == -1)
        return -1;

    return 0;
}

/* tlhhh. send packet to L2 */
int output_packet(struct sk_buff *pskb)
{
    struct dst_entry *dst = pskb->dst;
    struct hh_cache *hh = dst->hh;

    if (hh)
    {
        read_lock_bh(&hh->hh_lock);
        memcpy(pskb->data - 16, hh->hh_data, 16);
        read_unlock_bh(&hh->hh_lock);

        skb_push(pskb, hh->hh_len);
        return hh->hh_output(pskb);
    }
    else if (dst->neighbour)
        return dst->neighbour->output(pskb);

    if (net_ratelimit())
        pk_debug( "No header cache and no neighbour, output failed!\n");

    kfree_skb(pskb);
    return -EINVAL;
}

/* reset server's connection */
int reset_server(struct sk_buff* oldskb)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned char *data;
    unsigned int datalen;
    struct sk_buff* nskb = NULL;

    iph = IP_HDR(oldskb);
    tcph = (struct tcphdr *)&(((u_int32_t*)iph)[iph->ihl]);
    data =(unsigned char *)&(((u_int32_t*)tcph)[tcph->doff]);
    datalen = oldskb->tail - data;

	/* just reset, set data length to 0 and swap the direction */
    nskb = rebuild_packet(oldskb, 0, RST_PACKET, 1);
    if (nskb == NULL)
    {
        return -1;
    }

    if (output_packet(nskb) < 0)
    {
		pk_err("RST to server failed\n");
		return -1;
    }

    return 0;
}

/* ack client */
int ack_client(struct sk_buff* oldskb)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned char *data;
    unsigned int datalen;
    struct sk_buff* nskb = NULL;

    iph = IP_HDR(oldskb);
    tcph = (struct tcphdr *)&(((u_int32_t*)iph)[iph->ihl]);
    data =(unsigned char *)&(((u_int32_t*)tcph)[tcph->doff]);
    datalen = oldskb->tail - data;

	/* tlhhh. ack the received bytes, pass the data length */
    nskb = rebuild_packet(oldskb, datalen, ACK_PACKET, 1);
    if (nskb == NULL)
    {
        return -1;
    }

    if (output_packet(nskb) < 0)
    {
		pk_err("ACK to client failed");
		return -1;
    }

    return 0;
}

/* respond HTTP 302 Found to client */
int send_blkpage(const char *location, struct sk_buff* oldskb)
{
    /* tlhhh. hard-code length. 
	 * FIXME: if MAX_PACKET_SIZE > MTU, 
	 * then ip_fragment will be needed. 
	 */
    char buff[MAX_PACKET_SIZE];
    struct sk_buff* nskb = NULL;
    
    nskb = skb_copy(oldskb, GFP_ATOMIC);

	memset( buff, 0, sizeof(buff) );
    snprintf(buff, MAX_PACKET_SIZE, HTTP_REDIRECT_HEADER, location);
    buff[MAX_PACKET_SIZE - 1] = '\0';

    redirect_packet(nskb, buff);
    
    if (output_packet(nskb) < 0)
    {
        pk_err("send block page failed!\n");
		return -1;
    }

    return 0;
}

#ifdef __CONFIG_IPV6__
static int
route_packet6(struct sk_buff *pskb, struct tcphdr* tcph)
{
	struct ipv6hdr *hdr = ipv6_hdr(pskb);
	struct dst_entry *dst;
	struct flowi fl;

	memset(&fl, 0, sizeof(fl));
	ipv6_addr_copy(&fl.fl6_src, &hdr->saddr);
	ipv6_addr_copy(&fl.fl6_dst, &hdr->daddr);
	fl.fl_ip_sport = tcph->source;
	fl.fl_ip_dport = tcph->dest;
	security_skb_classify_flow(pskb, &fl);
	dst = ip6_route_output(NULL, &fl);
	if (dst == NULL){
		pk_debug("dst == NULL");
		return -1;
	}

	if ( dst->error || xfrm_lookup(&dst, &fl , NULL, 0)){
		pk_debug("dst->error");
		return -1;
	}

    dst_release(pskb->dst);		//drop old route
    pskb->dst = dst;
    pskb->dev = pskb->dst->dev;
    pskb->protocol = htons(ETH_P_IPV6);
    return 0;
}


struct sk_buff*
rebuild_packet6(
		struct sk_buff *oldskb,
		int len,
		TCP_TYPE flag,
		const int *tcphoff,
		int swap)
{
    struct sk_buff *nskb;
    struct tcphdr *otcph, *tcph;
    unsigned int otcplen;
    struct ipv6hdr *ip6h;

    ip6h = IP6_HDR(oldskb);
	
    /* IP header checks: fragment & too short. */
    if ( oldskb->len < (sizeof(struct ipv6hdr) + sizeof(struct tcphdr))){
        pk_debug("Invalid IP header");
        return NULL;
    }

    otcph = (struct tcphdr *)((unsigned char *)ip6h+ *tcphoff);
    otcplen = oldskb->len - sizeof(struct ipv6hdr);

    /* No RST for RST. */
    if (otcph->rst){ return NULL; }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    /* Check checksum. */
    if (csum_ipv6_magic(
		&(IP6_HDR(oldskb)->saddr),
		&(IP6_HDR(oldskb)->daddr),
		otcplen,
		IPPROTO_TCP,
		skb_checksum(oldskb, *tcphoff, otcplen, 0)) != 0)
#else
	if (tcp_v4_check(
		otcph,
		otcplen,
		IP_HDR(oldskb)->saddr,
		IP_HDR(oldskb)->daddr,
		csum_partial((char *)otcph, otcplen, 0)) != 0)
#endif
    {
	pk_debug("tcp_v6_check error");	
        return NULL;
    }

    /* Copy skb (even if skb is about to be dropped, we can't just
       clone it because there may be other things, such as tcpdump,
       interested in it) */
    nskb = skb_copy(oldskb, GFP_ATOMIC);
    if (!nskb){ return NULL; }

    /* This packet will not be the same as the other: clear nf fields */
    if (swap){
        nf_conntrack_put(nskb->nfct);
        nskb->nfct = NULL;
    }
    nskb->nfcache = 0;

    tcph = (struct tcphdr *)((u_int8_t*)IP6_HDR(nskb) + *tcphoff);

    /* Swap source and dest */
    if (swap){
	TSWAP6(IP6_HDR(nskb)->saddr, IP6_HDR(nskb)->daddr);	
	TSWAP(tcph->source, tcph->dest);
    }

    /* Truncate to length (no data) */
    tcph->doff = sizeof(struct tcphdr) /4;
    skb_trim(nskb, sizeof(struct ipv6hdr) + sizeof(struct tcphdr));
    IP6_HDR(nskb)->payload_len = htons(sizeof(struct tcphdr));

    if (swap){
	calc_seq(tcph, len);
    }

    /* Reset flags */
    ((u_int8_t *)tcph)[13] = 0;
    switch (flag)
    {
	case ACK_PACKET:
		tcph->ack = 1;
		break;
	case FIN_ACK_PACKET:
		tcph->fin = 1;
		tcph->ack = 1;
		break;
	case RST_PACKET:
		tcph->rst = 1;
		tcph->ack_seq = 0;
		tcph->ack = 0;
		break;
    }

    tcph->urg_ptr = 0;

    /* TCP checksum */
    tcph->check = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	tcph->check = csum_ipv6_magic(
			&(IP6_HDR(nskb)->saddr),
			&(IP6_HDR(nskb)->daddr),
			sizeof(struct tcphdr),
			IPPROTO_TCP,
			csum_partial((char*)tcph, sizeof(struct tcphdr), 0));
#else
	tcph->check = tcp_v4_check(
			tcph,
			sizeof(struct tcphdr),
			IP_HDR(nskb)->saddr,
			IP_HDR(nskb)->daddr,
			csum_partial((char *)tcph, sizeof(struct tcphdr), 0));
#endif

    /* HOP_LIMIT, DF */
    IP6_HDR(nskb)->hop_limit = DEFTTL;
    IP6_HDR(nskb)->nexthdr = NEXTHDR_TCP;

    /* Routing to output*/
    if (route_packet6(nskb, tcph) == -1){
        goto free_nskb;
    }
    return nskb;

free_nskb:
    kfree_skb(nskb);
    return NULL;
}


unsigned int
redirect_packet6(struct sk_buff *pskb, char *header)
{
	struct ipv6hdr *ip6h = IP6_HDR(pskb);
	struct tcphdr *tcph;
	unsigned char* data;
	u8 proto;
	int tcphoff;
	u_int32_t datasize, headersize;
	
	proto = ip6h->nexthdr;
	tcphoff = ipv6_skip_exthdr( pskb, ((u_int8_t *)(ip6h+1) - pskb->data), &proto);
	tcph = (struct tcphdr *)((unsigned char *) ip6h+tcphoff );
	data = (unsigned char *)&(((u_int32_t *)tcph)[ tcph->doff ]);

    /* length of skb data */
    datasize = pskb->tail - data;
    /* length of TCP payload */
    headersize = strlen(header);

    tcph->window = MAX_TCP_WINDOW;

    /* Shrink skb size into new length (no data) */
    // Ignore any tcp options, just use the standard tcp header. tlhhh
    skb_trim(pskb, sizeof(struct ipv6hdr) + sizeof(struct tcphdr));
    data = skb_put(pskb, headersize);

    memset(data, 0, headersize);
    strncpy(data, header, headersize);
	
    tcph->doff = sizeof(struct tcphdr) /4;

    tcph->urg = 0;
    tcph->ack = 1;
    tcph->psh = 1;
    tcph->rst = 0;
    tcph->syn = 0;
    tcph->fin = 0;

    /* Calculate reply seq & ack_seq */
    calc_seq(tcph, datasize);

    /* Swap source and dest */
    TSWAP6(ip6h->saddr, ip6h->daddr);
    TSWAP(tcph->source, tcph->dest);

    /* Adjust TCP checksum */
    tcph->check = 0;
    pskb->csum = csum_partial((char*)tcph, pskb->len - sizeof(struct ipv6hdr), 0);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    tcph->check = csum_ipv6_magic(
				&ip6h->saddr,
				&ip6h->daddr,
				(pskb->len - sizeof(struct ipv6hdr)),
				IPPROTO_TCP,
				pskb->csum);

#else
    tcph->check = tcp_v4_check(
				tcph,
				(pskb->len - (4 * iph->ihl)),
				iph->saddr,
				iph->daddr,
				csum_partial((char *)tcph, (pskb->len - (4 * iph->ihl)), 0));
#endif /* LINUX_VERSION_CODE */
    pk_debug("tcph->check = %x, sizeof(struct tcphdr) = %d, csum_partial = %x",
	tcph->check,
	sizeof(struct tcphdr),
	csum_partial((char *)tcph, sizeof(struct tcphdr), 0));
    pk_debug("csum_ipv6_magic = %x",
	csum_ipv6_magic(
		&ip6h->saddr,
		&ip6h->daddr,
		(pskb->len - sizeof(struct ipv6hdr)),
		IPPROTO_TCP,
		csum_partial((char *)tcph, sizeof(struct tcphdr), 0)));

    /* TTL, DF */
    IP6_HDR(pskb)->hop_limit = DEFTTL;
    IP6_HDR(pskb)->nexthdr = NEXTHDR_TCP;
    IP6_HDR(pskb)->payload_len = htons(sizeof(struct tcphdr)+headersize);

    if (route_packet6(pskb, tcph) == -1)
        return -1;

    return 0;
}


int
send_blkpage6(const char *location, struct sk_buff* oldskb)
{
    /* tlhhh. hard-code length. 
	 * FIXME: if MAX_PACKET_SIZE > MTU, 
	 * then ip_fragment will be needed. 
	 */
    char buff[MAX_PACKET_SIZE];
    struct sk_buff* nskb = NULL;

    nskb = skb_copy(oldskb, GFP_ATOMIC);

    memset(buff, 0, sizeof(buff));
    snprintf(buff, MAX_PACKET_SIZE, HTTP_REDIRECT_HEADER, location);
    buff[MAX_PACKET_SIZE - 1] = '\0';

    redirect_packet6(nskb, buff);
    
    if (output_packet(nskb) < 0){
        pk_err("send block page failed!\n");
	return -1;
    }

    return 0;
}


int
reset_server6(struct sk_buff* oldskb)
{
    struct ipv6hdr *ip6h;
    struct tcphdr *tcph;
    unsigned char *data;
    unsigned int datalen;
    struct sk_buff* nskb = NULL;
    u8 proto=0;
    int tcphoff=0;

    ip6h = IP6_HDR(oldskb);
	
    proto = ip6h->nexthdr;
    tcphoff = ipv6_skip_exthdr( oldskb, ((u_int8_t*)(ip6h+1) - oldskb->data), &proto);
    tcph = (struct tcphdr *)((unsigned char*)ip6h+tcphoff);
    data =(unsigned char *)&(((u_int32_t*)tcph)[ tcph->doff ]);
    datalen = oldskb->tail - data;

    /* tlhhh. ack the received bytes, pass the data length */
    nskb = rebuild_packet6(oldskb, datalen, ACK_PACKET, &tcphoff, 1); //1 for IPV6
    if (nskb == NULL){
        return -1;
    }

    if (output_packet(nskb) < 0){
	pk_err("RST to server failed\n");
	return -1;
    }

    return 0;
}


int
ack_client6(struct sk_buff* oldskb)
{
    struct ipv6hdr *ip6h;
    struct tcphdr *tcph;
    unsigned char *data;
    unsigned int datalen;
    struct sk_buff* nskb = NULL;
    u8 proto=0;
    int tcphoff=0;

    ip6h = IP6_HDR(oldskb);
	
    proto = ip6h->nexthdr;
    tcphoff = ipv6_skip_exthdr( oldskb,((u_int8_t*)(ip6h+1) - oldskb->data), &proto);
    tcph = (struct tcphdr *)((unsigned char*)ip6h + tcphoff);
    data =(unsigned char *)&(((u_int32_t*)tcph)[ tcph->doff ]);
    datalen = oldskb->tail - data;

    /* tlhhh. ack the received bytes, pass the data length */
    nskb = rebuild_packet6(oldskb, datalen, ACK_PACKET, &tcphoff, 1); //1 for IPV6
    if (nskb == NULL){ return -1; }

    if (output_packet(nskb) < 0){
	pk_err("ACK to client failed");
	return -1;
    }

    return 0;
}
#endif /* __CONFIG_IPV6__ */
