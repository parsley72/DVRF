/* SIP extension for UDP NAT alteration.
 *
 * (C) 2005 by Christian Hentschel <chentschel@arnet.com.ar>
 * based on RR's ip_nat_ftp.c and other modules.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/udp.h>
#include <linux/inet.h>

#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_helper.h>
#include <net/netfilter/nf_nat_rule.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <linux/netfilter/nf_conntrack_sip.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Christian Hentschel <chentschel@arnet.com.ar>");
MODULE_DESCRIPTION("SIP NAT helper");
MODULE_ALIAS("ip_nat_sip");

/* Kelly add @ 2009.08.27 */
/* If local have support SIP voice,
 * it will be a conflict when the IP Phone use the same RTP port in the LAN.
 * SIP ALG need to change port with SDP to avoid the same RTP port.
 * netfilter need to track RTP session.
 */
static unsigned int max_rtp_port = 16482;
module_param(max_rtp_port, uint, 0400);
MODULE_PARM_DESC(max_rtp_port, "The maximum RTP port number with local SIP voice.");
static unsigned int min_rtp_port = 16384;
module_param(min_rtp_port, uint, 0400);
MODULE_PARM_DESC(min_rtp_port, "The minimum RTP port number with local SIP voice.");
/* end Kelly add @ 2009.08.27 */


#if 0
#define DEBUGP(format, args...) printk("%s:" format, \
				       __FUNCTION__ , ## args)
#else
#define DEBUGP(format, args...)
#endif

#define SIP_DEBUG_DUMP_NF_EXPECT_TUPLE(tp)	DEBUGP(" expect point = 0x%p\n",(tp));	\
DEBUGP(" expect %u.%u.%u.%u:%hu->%u.%u.%u.%u:%hu\n",\
       NIPQUAD((tp)->tuple.src.u3.ip),					\
       ntohs((tp)->tuple.src.u.udp.port),				\
       NIPQUAD((tp)->tuple.dst.u3.ip),					\
       ntohs((tp)->tuple.dst.u.udp.port));				\
DEBUGP(" mask %u.%u.%u.%u:%hu->%u.%u.%u.%u:%hu\n",	\
       NIPQUAD((tp)->mask.src.u3.ip),					\
       ntohs((tp)->mask.src.u.udp.port),				\
       NIPQUAD((tp)->mask.dst.u3.ip),					\
       ntohs((tp)->mask.dst.u.udp.port))

#define SIP_DEBUG_DUMP_NF_EXPECT_NAT_NEEDED(tp)	DEBUGP(" expect point = 0x%p\n",(tp));	\
DEBUGP(" expect save_ip %u.%u.%u.%u saved_proto %hu \n",	\
       NIPQUAD((tp)->saved_ip),								\
       ntohs((tp)->saved_proto.udp.port));					\
DEBUGP(" expect dir = %s\n",((tp)->dir==IP_CT_DIR_REPLY) ? "IP_CT_DIR_REPLY" : "IP_CT_DIR_ORIGINAL")

#define SIP_DEBUG_DUMP_NF_CT_TUPLEHASH(tp) DEBUGP(" tuplehash(IP_CT_DIR_ORIGINAL) %u.%u.%u.%u:%hu->%u.%u.%u.%u:%hu\n",	\
	       NIPQUAD((tp)->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip),		\
	       ntohs((tp)->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port),	\
	       NIPQUAD((tp)->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip),		\
	       ntohs((tp)->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.udp.port));	\
DEBUGP(" tuplehash(IP_CT_DIR_REPLY) %u.%u.%u.%u:%hu->%u.%u.%u.%u:%hu\n",\
	       NIPQUAD((tp)->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip),	\
	       ntohs((tp)->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.udp.port),	\
	       NIPQUAD((tp)->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip),	\
	       ntohs((tp)->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.udp.port))

static unsigned int ip_nat_sip_expect(struct sk_buff **skb,
				      const char **dptr,
				      unsigned int *datalen,
				      struct nf_conntrack_expect *exp,
				      unsigned int matchoff,
				      unsigned int matchlen);

struct addr_map {
	struct {
		char		src[sizeof("nnn.nnn.nnn.nnn:nnnnn")];
		char		dst[sizeof("nnn.nnn.nnn.nnn:nnnnn")];
		unsigned int	srclen, srciplen;
		unsigned int	dstlen, dstiplen;
	} addr[IP_CT_DIR_MAX];
};

#if 0
static int nf_expect_nat_needed_cmp(const struct nf_conntrack_expect *exp1,
				       const struct nf_conntrack_expect *exp2)
{
	DEBUGP(" Enter\n");

		if (((exp1) == NULL) || ((exp2) == NULL))
			return -1;
		if ((((exp1)->saved_ip) == ((exp2)->saved_ip)) &&
			(((exp1)->saved_proto.udp.port) == ((exp2)->saved_proto.udp.port)) &&					
			(((exp1)->dir) == ((exp2)->dir)))
			return 1;
		else	
			return 0;
}
#endif

static void addr_map_init(struct nf_conn *ct, struct addr_map *map)
{
	struct nf_conntrack_tuple *t;
	enum ip_conntrack_dir dir;
	unsigned int n;

	for (dir = 0; dir < IP_CT_DIR_MAX; dir++) {
		t = &ct->tuplehash[dir].tuple;

		n = sprintf(map->addr[dir].src, "%u.%u.%u.%u",
			    NIPQUAD(t->src.u3.ip));
		map->addr[dir].srciplen = n;
		n += sprintf(map->addr[dir].src + n, ":%u",
			     ntohs(t->src.u.udp.port));
		map->addr[dir].srclen = n;

		n = sprintf(map->addr[dir].dst, "%u.%u.%u.%u",
			    NIPQUAD(t->dst.u3.ip));
		map->addr[dir].dstiplen = n;
		n += sprintf(map->addr[dir].dst + n, ":%u",
			     ntohs(t->dst.u.udp.port));
		map->addr[dir].dstlen = n;
	}
}

static int parse_addr(const char *cp, const char **endp,
		      union nf_conntrack_address *addr, const char *limit)
{
	const char *end;
	int ret = 0;

	ret = in4_pton(cp, limit - cp, (u8 *)&addr->ip, -1, &end);

	if (ret == 0 || end == cp)
		return 0;
		
	if (endp)
		*endp = end;
	return 1;
}

static int parse_addrinfo(const char *dptr, union nf_conntrack_address *addr, __be16 *port,
		      const char *limit)
{
	unsigned int pn;

	if (!parse_addr(dptr, &dptr, addr, limit)) {
		return -1;
	}

	/* Port number */
	if (dptr < limit && *dptr == ':') {
		dptr++;
		
		pn = simple_strtoul(dptr, NULL, 10);
		if (pn < 1024 || pn > 65535)
			return -1;

		*port = htons(pn);		
	}
	return 0;
}

static int map_sip_addr(struct sk_buff **pskb, enum ip_conntrack_info ctinfo,
			struct nf_conn *ct, const char **dptr, size_t dlen,
			enum sip_header_pos pos, struct addr_map *map)
{
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	unsigned int matchlen, matchoff, addrlen;
	char *addr;

	if (ct_sip_get_info(ct, *dptr, dlen, &matchoff, &matchlen, pos) == -1)
		return 1;
	
	DEBUGP(" dptr %.*s,  map->addr[dir].src %s,  map->addr[dir].dst %s\n", 30, *dptr+matchoff, map->addr[dir].src, map->addr[dir].dst);

	if ((matchlen == map->addr[dir].srciplen ||
	     matchlen == map->addr[dir].srclen) &&
	    memcmp(*dptr + matchoff, map->addr[dir].src, matchlen) == 0) {
		addr    = map->addr[!dir].dst;
		addrlen = map->addr[!dir].dstlen;
	} else if ((matchlen == map->addr[dir].dstiplen ||
		    matchlen == map->addr[dir].dstlen) &&
		   memcmp(*dptr + matchoff, map->addr[dir].dst, matchlen) == 0) {
		addr    = map->addr[!dir].src;
		addrlen = map->addr[!dir].srclen;
	} else if (POS_CONTACT == pos || POS_VIA == pos) {
		struct nf_conntrack_expect *exp;
		int family = ct->tuplehash[!dir].tuple.src.l3num;
		union nf_conntrack_address ct_addr;
		enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
		__be16 port;

		if(dir != IP_CT_DIR_ORIGINAL)
			return 1;

		if(parse_addrinfo(*dptr + matchoff, &ct_addr, &port, *dptr + dlen) == -1)
			return 1;

		exp = nf_conntrack_expect_alloc(ct);
		if (exp == NULL)
			return NF_DROP;
		nf_conntrack_expect_init(exp, family,
				 &ct->tuplehash[!dir].tuple.src.u3, &ct_addr,
				 IPPROTO_UDP, NULL, &port);
		exp->tuple.src.u.udp.port = 0;
		exp->tuple.src.u3.ip = 0;
		exp->mask.src.u.udp.port = 0;
		exp->mask.src.u3.ip = 0;
		exp->saved_ip = 0;
		exp->saved_proto.udp.port = 0;
		exp->sip_call_id_hash = 0;
		if (nfct_help(ct))
			exp->helper = nfct_help(ct)->helper;
		ip_nat_sip_expect(pskb, dptr, &dlen, exp, matchoff, matchlen);
		nf_conntrack_expect_put(exp);
		
		return 1;
	} else
		return 1;

	if (!nf_nat_mangle_udp_packet(pskb, ct, ctinfo,
				      matchoff, matchlen, addr, addrlen))
		return 0;

	*dptr = (*pskb)->data + ip_hdrlen(*pskb) + sizeof(struct udphdr);
	return 1;
}

static unsigned int ip_nat_sip(struct sk_buff **pskb,
			       enum ip_conntrack_info ctinfo,
			       struct nf_conn *ct,
			       const char **dptr)
{
	enum sip_header_pos pos;
	struct addr_map map;
	int dataoff, datalen;

	DEBUGP(" Enter\n");
	dataoff = ip_hdrlen(*pskb) + sizeof(struct udphdr);
	datalen = (*pskb)->len - dataoff;
	if (datalen < sizeof("SIP/2.0") - 1)
		return NF_DROP;

	addr_map_init(ct, &map);

	/* Basic rules: requests and responses. */
	if (strncmp(*dptr, "SIP/2.0", sizeof("SIP/2.0") - 1) != 0) {
		/* 10.2: Constructing the REGISTER Request:
		 *
		 * The "userinfo" and "@" components of the SIP URI MUST NOT
		 * be present.
		 */
		if (datalen >= sizeof("REGISTER") - 1 &&
		    strncmp(*dptr, "REGISTER", sizeof("REGISTER") - 1) == 0)
			pos = POS_REG_REQ_URI;
		else
			pos = POS_REQ_URI;

		if (!map_sip_addr(pskb, ctinfo, ct, dptr, datalen, pos, &map))
			return NF_DROP;
	}

	if (!map_sip_addr(pskb, ctinfo, ct, dptr, datalen, POS_FROM, &map) ||
	    !map_sip_addr(pskb, ctinfo, ct, dptr, datalen, POS_TO, &map) ||
	    !map_sip_addr(pskb, ctinfo, ct, dptr, datalen, POS_VIA, &map) ||
	    !map_sip_addr(pskb, ctinfo, ct, dptr, datalen, POS_CONTACT, &map))
		return NF_DROP;
	return NF_ACCEPT;
}

#if 0
static unsigned int mangle_sip_packet(struct sk_buff **pskb,
				      enum ip_conntrack_info ctinfo,
				      struct nf_conn *ct,
				      const char **dptr, size_t dlen,
				      char *buffer, int bufflen,
				      enum sip_header_pos pos)
{
	unsigned int matchlen, matchoff;

	if (ct_sip_get_info(ct, *dptr, dlen, &matchoff, &matchlen, pos) <= 0)
		return 0;

	if (!nf_nat_mangle_udp_packet(pskb, ct, ctinfo,
				      matchoff, matchlen, buffer, bufflen))
		return 0;

	/* We need to reload this. Thanks Patrick. */
	*dptr = (*pskb)->data + ip_hdrlen(*pskb) + sizeof(struct udphdr);
	return 1;
}

static int mangle_content_len(struct sk_buff **pskb,
			      enum ip_conntrack_info ctinfo,
			      struct nf_conn *ct,
			      const char *dptr)
{
	unsigned int dataoff, matchoff, matchlen;
	char buffer[sizeof("65536")];
	int bufflen;

	dataoff = ip_hdrlen(*pskb) + sizeof(struct udphdr);

	/* Get actual SDP lenght */
	if (ct_sip_get_info(ct, dptr, (*pskb)->len - dataoff, &matchoff,
			    &matchlen, POS_SDP_HEADER) > 0) {

		/* since ct_sip_get_info() give us a pointer passing 'v='
		   we need to add 2 bytes in this count. */
		int c_len = (*pskb)->len - dataoff - matchoff + 2;

		/* Now, update SDP length */
		if (ct_sip_get_info(ct, dptr, (*pskb)->len - dataoff, &matchoff,
				    &matchlen, POS_CONTENT) > 0) {

			bufflen = sprintf(buffer, "%u", c_len);
			return nf_nat_mangle_udp_packet(pskb, ct, ctinfo,
							matchoff, matchlen,
							buffer, bufflen);
		}
	}
	return 0;
}

static unsigned int mangle_sdp(struct sk_buff **pskb,
			       enum ip_conntrack_info ctinfo,
			       struct nf_conn *ct,
			       __be32 newip, u_int16_t port,
			       const char *dptr)
{
	char buffer[sizeof("nnn.nnn.nnn.nnn")];
	unsigned int dataoff, bufflen;

	dataoff = ip_hdrlen(*pskb) + sizeof(struct udphdr);

	/* Mangle owner and contact info. */
	bufflen = sprintf(buffer, "%u.%u.%u.%u", NIPQUAD(newip));
	if (!mangle_sip_packet(pskb, ctinfo, ct, &dptr, (*pskb)->len - dataoff,
			       buffer, bufflen, POS_OWNER_IP4))
		return 0;

	if (!mangle_sip_packet(pskb, ctinfo, ct, &dptr, (*pskb)->len - dataoff,
			       buffer, bufflen, POS_CONNECTION_IP4))
		return 0;

	/* Mangle media port. */
	bufflen = sprintf(buffer, "%u", port);
	if (!mangle_sip_packet(pskb, ctinfo, ct, &dptr, (*pskb)->len - dataoff,
			       buffer, bufflen, POS_MEDIA))
		return 0;

	return mangle_content_len(pskb, ctinfo, ct, dptr);
}
#endif
static void ip_nat_sip_expected(struct nf_conn *ct,
			      struct nf_conntrack_expect *exp)
{
	struct nf_nat_range range;

	SIP_DEBUG_DUMP_NF_EXPECT_TUPLE(exp);
	SIP_DEBUG_DUMP_NF_EXPECT_NAT_NEEDED(exp);

	DEBUGP(" nf_conn = 0x%p , ct->tuplehash(Enter)\n",ct);
	SIP_DEBUG_DUMP_NF_CT_TUPLEHASH(ct);
	/* This must be a fresh one. */
	BUG_ON(ct->status & IPS_NAT_DONE_MASK);
#if 0
	/* Change src to where master sends to */
	range.flags = IP_NAT_RANGE_MAP_IPS;
	range.min_ip = range.max_ip
		= ct->master->tuplehash[!exp->dir].tuple.dst.u3.ip;
	/* hook doesn't matter, but it has to do source manip */
	nf_nat_setup_info(ct, &range, NF_IP_POST_ROUTING);
#endif

	/* For DST manip, map port here to where it's expected. */
	range.flags = (IP_NAT_RANGE_MAP_IPS | IP_NAT_RANGE_PROTO_SPECIFIED);
	range.min = range.max = exp->saved_proto;
	range.min_ip = range.max_ip = exp->saved_ip;
	/* hook doesn't matter, but it has to do destination manip */
	nf_nat_setup_info(ct, &range, NF_IP_PRE_ROUTING);
	SIP_DEBUG_DUMP_NF_CT_TUPLEHASH(ct);

	/* Change src to where master sends to, but only if the connection
	 * actually came from the same source. */
	if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip ==
		ct->master->tuplehash[exp->dir].tuple.src.u3.ip) {
		range.flags = IP_NAT_RANGE_MAP_IPS;
		range.min_ip = range.max_ip
			= ct->master->tuplehash[!exp->dir].tuple.dst.u3.ip;
		/* hook doesn't matter, but it has to do source manip */
		nf_nat_setup_info(ct, &range, NF_IP_POST_ROUTING);
	}

	DEBUGP(" nf_conn = 0x%p , ct->tuplehash(Leave)\n",ct);
	SIP_DEBUG_DUMP_NF_CT_TUPLEHASH(ct);
	
}

/* So, this packet has hit the connection tracking matching code.
   Mangle it, and change the expectation to match the new version. */
#if 0
static unsigned int ip_nat_sdp(struct sk_buff **pskb,
			       enum ip_conntrack_info ctinfo,
			       struct nf_conntrack_expect *exp,
			       const char *dptr)
{
	struct nf_conn *ct = exp->master;
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	__be32 newip;
	u_int16_t port;

	DEBUGP("ip_nat_sdp():\n");

	/* Connection will come from reply */
	newip = ct->tuplehash[!dir].tuple.dst.u3.ip;

	exp->saved_ip = exp->tuple.dst.u3.ip;
	exp->tuple.dst.u3.ip = newip;
	exp->saved_proto.udp.port = exp->tuple.dst.u.udp.port;
	exp->dir = !dir;

	/* When you see the packet, we need to NAT it the same as the
	   this one. */
	exp->expectfn = ip_nat_sdp_expect;

	/* Try to get same port: if not, try to change it. */
	for (port = ntohs(exp->saved_proto.udp.port); port != 0; port++) {
		exp->tuple.dst.u.udp.port = htons(port);
		if (nf_conntrack_expect_related(exp) == 0)
			break;
	}

	if (port == 0)
		return NF_DROP;

	if (!mangle_sdp(pskb, ctinfo, ct, newip, port, dptr)) {
		nf_conntrack_unexpect_related(exp);
		return NF_DROP;
	}
	return NF_ACCEPT;
}
#endif
#if 0
static unsigned int ip_nat_sdp(struct sk_buff **pskb,
			       enum ip_conntrack_info ctinfo,
			       struct nf_conntrack_expect *rtp_exp,
			       struct nf_conntrack_expect *rtcp_exp,
			       const char *dptr)
{
	struct nf_conn *ct = rtp_exp->master;
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	__be32 newip;
	u_int16_t port;
	u_int16_t rtp_port_range = 0;
	u_int16_t change_rtp_port = 0;

	DEBUGP(" Enter\n");
	DEBUGP(" CTINFO2DIR(ctinfo) dir = %s\n",(dir==IP_CT_DIR_REPLY) ? "IP_CT_DIR_REPLY" : "IP_CT_DIR_ORIGINAL");
	SIP_DEBUG_DUMP_NF_CT_TUPLEHASH(ct);
	SIP_DEBUG_DUMP_NF_EXPECT_TUPLE(rtp_exp);
 	SIP_DEBUG_DUMP_NF_EXPECT_NAT_NEEDED(rtp_exp);

	/* Connection will come from reply */
	newip = ct->tuplehash[!dir].tuple.dst.u3.ip;

	if (rtcp_exp == NULL) {
		/* Kelly add @ 2010.01.08 */
		/* Maybe have an exit expectation.
		 * I add SIP Header Call-ID information into nf_conntrack_expect
		 * That can ensure correct and exit expectation.
		* For an example:
	 	* 	Caller sent INVITE without Authenticate, and SIP Proxy will response 407.
	 	*	Caller will send again INVITE with Authemticate.
		 *	These SIP INVITE are the same dialog (these are the same Call-ID).
	 	*	So do not need two expectation	
	 	*/
		port = ntohs(rtp_exp->tuple.dst.u.udp.port);
	} else {	
		rtp_exp->saved_ip = rtp_exp->tuple.dst.u3.ip;
		rtp_exp->tuple.dst.u3.ip = newip;
		rtp_exp->saved_proto.udp.port = rtp_exp->tuple.dst.u.udp.port;
		rtp_exp->dir = !dir;
		rtp_exp->expectfn = ip_nat_sdp_expect;

		rtcp_exp->saved_ip = rtp_exp->saved_ip;
		rtcp_exp->tuple.dst.u3.ip = newip;
		rtcp_exp->saved_proto.udp.port = htons(1 + ntohs(rtp_exp->saved_proto.udp.port));
		rtcp_exp->dir = !dir;
		rtcp_exp->expectfn = ip_nat_sdp_expect;

		if (max_rtp_port > min_rtp_port) {
			rtp_port_range = max_rtp_port - min_rtp_port;
			change_rtp_port = rtp_port_range + ntohs(rtp_exp->tuple.dst.u.udp.port);
		} else {
			change_rtp_port = ntohs(rtp_exp->tuple.dst.u.udp.port);
		}

		/* Try to get same pair of ports: if not, try to change them. */
		for (port = change_rtp_port;
	    	 port != 0; port += 2) {
			rtp_exp->tuple.dst.u.udp.port = htons(port);
			if (nf_conntrack_expect_related(rtp_exp) != 0)
				continue;
			rtcp_exp->tuple.dst.u.udp.port = htons(port + 1);
			if (nf_conntrack_expect_related(rtcp_exp) == 0)
				break;
			nf_conntrack_unexpect_related(rtp_exp);
		}

		if (port == 0)
			goto err1;
	}

	if (!mangle_sdp(pskb, ctinfo, ct, newip, port, dptr)) {
		goto err2;
	}

	DEBUGP(" Leave\n");
	SIP_DEBUG_DUMP_NF_CT_TUPLEHASH(ct);
	SIP_DEBUG_DUMP_NF_EXPECT_TUPLE(rtp_exp);
 	SIP_DEBUG_DUMP_NF_EXPECT_NAT_NEEDED(rtp_exp);
	return NF_ACCEPT;
err2:
	if (rtp_exp)
		nf_conntrack_unexpect_related(rtp_exp);
	if (rtcp_exp)
		nf_conntrack_unexpect_related(rtcp_exp);
err1:
	return NF_DROP;
}
#endif
 static unsigned int mangle_packet(struct sk_buff **skb,
					const char **dptr, unsigned int *datalen,
					unsigned int matchoff, unsigned int matchlen,
					const char *buffer, unsigned int buflen)
 {
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(*skb, &ctinfo);

#if 1
	{
		char tmp[32];

		snprintf(tmp,30,"%s",(*dptr)+matchoff);
	 	DEBUGP(" mangle data [%s]len %d with [%s] len %d\n", tmp, matchlen, buffer, buflen);
	}
#endif
	if (!nf_nat_mangle_udp_packet(skb, ct, ctinfo, matchoff, matchlen,
		buffer, buflen))
		return 0;

	/* Reload data pointer and adjust datalen value */
	*dptr = (*skb)->data + ip_hdrlen(*skb) + sizeof(struct udphdr);
	*datalen += buflen - matchlen;
	return 1;
 }
 
static int mangle_content_len(struct sk_buff **skb,
				const char **dptr, unsigned int *datalen)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(*skb, &ctinfo);
	unsigned int matchoff, matchlen;
	char buffer[sizeof("65536")];
	int buflen, c_len;

	/* Get actual SDP length */
	if (ct_sip_get_sdp_header(ct, *dptr, 0, *datalen,
		SDP_HDR_VERSION, SDP_HDR_UNSPEC,
		&matchoff, &matchlen) <= 0)
		return 0;
	c_len = *datalen - matchoff + strlen("v=");
	/* Now, update SDP length */
	if (ct_sip_get_info(ct, *dptr, *datalen, &matchoff,
		&matchlen, POS_CONTENT) <= 0)
		return 0;
				    
	buflen = sprintf(buffer, "%u", c_len);
	return mangle_packet(skb, dptr, datalen, matchoff, matchlen,
		buffer, buflen);
}

static int mangle_sdp_packet(struct sk_buff **skb, const char **dptr,
				unsigned int dataoff, unsigned int *datalen,
				enum sdp_header_types type,
				enum sdp_header_types term,
				char *buffer, int buflen)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(*skb, &ctinfo);
	unsigned int matchlen, matchoff;

	if (ct_sip_get_sdp_header(ct, *dptr, dataoff, *datalen, type, term,
		&matchoff, &matchlen) <= 0)
		return -ENOENT;

#if 0
	{
		char tmp[32];

		snprintf(tmp,30,"%s",(*dptr)+matchoff);
		DEBUGP(" mangle data [%s]len %d with [%s] len %d\n", tmp, datalen, buffer, buflen);
	}
#endif
	return mangle_packet(skb, dptr, datalen, matchoff, matchlen,
			buffer, buflen) ? 0 : -EINVAL;
}

static unsigned int ip_nat_sdp_addr(struct sk_buff **skb, const char **dptr,
						unsigned int dataoff,
						unsigned int *datalen,
						enum sdp_header_types type,
						enum sdp_header_types term,
						const union nf_conntrack_address *addr)
{
	char buffer[sizeof("nnn.nnn.nnn.nnn")];
	unsigned int buflen;

	buflen = sprintf(buffer, "%u.%u.%u.%u", NIPQUAD(addr->ip));
#if 0
	{
		char tmp[64];

		DEBUGP("mangle with [%s] len %d\n", buffer, buflen);

		snprintf(tmp,60,"%s",(*dptr)+dataoff);
		DEBUGP(" from data [%s]n", tmp);
	}
#endif
	if (mangle_sdp_packet(skb, dptr, dataoff, datalen, type, term,
		buffer, buflen))
		return 0;

	return mangle_content_len(skb, dptr, datalen);
}

static unsigned int ip_nat_sdp_port(struct sk_buff **skb,
						const char **dptr,
						unsigned int *datalen,
						unsigned int matchoff,
						unsigned int matchlen,
						u_int16_t port)
{
	char buffer[sizeof("nnnnn")];
	unsigned int buflen;

	buflen = sprintf(buffer, "%u", port);
#if 0
	{
		char tmp[32];

		DEBUGP(" dptr 0x%x mediaoff %d\n", *dptr, matchoff);

		snprintf(tmp,30,"%s",(*dptr)+matchoff);
	 	DEBUGP(" mangle data [%s]len %d with [%s]\n", tmp, matchlen, buffer);
	}
#endif
	if (!mangle_packet(skb, dptr, datalen, matchoff, matchlen,
		buffer, buflen))
		return 0;

	return mangle_content_len(skb, dptr, datalen);
}

static unsigned int ip_nat_sdp_session(struct sk_buff **skb, const char **dptr,
						unsigned int dataoff,
						unsigned int *datalen,
						const union nf_conntrack_address *addr)
{
	char buffer[sizeof("nnn.nnn.nnn.nnn")];
	unsigned int buflen;
	int ret=0;

	/* Mangle session description owner and contact addresses */
	buflen = sprintf(buffer, "%u.%u.%u.%u", NIPQUAD(addr->ip));
	if (mangle_sdp_packet(skb, dptr, dataoff, datalen,
		SDP_HDR_OWNER_IP4, SDP_HDR_MEDIA, buffer, buflen))
		return 0;

	ret = mangle_sdp_packet(skb, dptr, dataoff, datalen,
			SDP_HDR_CONNECTION_IP4, SDP_HDR_MEDIA,
			buffer, buflen);
	DEBUGP(" mangle_sdp_packet result : %d\n", ret);
	
	switch(ret) {

	case 0:
	/*
	 * RFC 2327:
	 *
	 * Session description
	 *
	 * c=* (connection information - not required if included in all media)
	 */
	case -ENOENT:
		break;
	default:
		return 0;
	}

	return mangle_content_len(skb, dptr, datalen);
}

/* So, this packet has hit the connection tracking matching code.
   Mangle it, and change the expectation to match the new version. */
static unsigned int ip_nat_sdp_media(struct sk_buff **skb,
                                     const char **dptr,
                                     unsigned int *datalen,
                                     struct nf_conntrack_expect *rtp_exp,
                                     struct nf_conntrack_expect *rtcp_exp,
                                     unsigned int mediaoff,
                                     unsigned int medialen,
                                     union nf_conntrack_address *rtp_addr)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(*skb, &ctinfo);
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	u_int16_t port;

	DEBUGP(" Enter\n");
#if 1
	DEBUGP(" CTINFO2DIR(ctinfo) dir = %s\n",(dir==IP_CT_DIR_REPLY) ? "IP_CT_DIR_REPLY" : "IP_CT_DIR_ORIGINAL");
	SIP_DEBUG_DUMP_NF_CT_TUPLEHASH(ct);
	SIP_DEBUG_DUMP_NF_EXPECT_TUPLE(rtp_exp);
 	SIP_DEBUG_DUMP_NF_EXPECT_NAT_NEEDED(rtp_exp);
#endif
	/* Connection will come from reply */
	if (ct->tuplehash[dir].tuple.src.u3.ip == ct->tuplehash[!dir].tuple.dst.u3.ip)
		rtp_addr->ip = rtp_exp->tuple.dst.u3.ip;
	else
		rtp_addr->ip = ct->tuplehash[!dir].tuple.dst.u3.ip;

	if (rtcp_exp == NULL) {
		/* Kelly add @ 2010.01.08 */
		/* Maybe have an exit expectation.
		 * I add SIP Header Call-ID information into nf_conntrack_expect
		 * That can ensure correct and exit expectation.
		* For an example:
	 	* 	Caller sent INVITE without Authenticate, and SIP Proxy will response 407.
	 	*	Caller will send again INVITE with Authemticate.
		 *	These SIP INVITE are the same dialog (these are the same Call-ID).
	 	*	So do not need two expectation	
	 	*/
		port = ntohs(rtp_exp->tuple.dst.u.udp.port);
	} else {	
		rtp_exp->saved_ip = rtp_exp->tuple.dst.u3.ip;
		rtp_exp->tuple.dst.u3.ip = rtp_addr->ip;
		rtp_exp->saved_proto.udp.port = rtp_exp->tuple.dst.u.udp.port;
		rtp_exp->dir = !dir;
		rtp_exp->expectfn = ip_nat_sip_expected;

		rtcp_exp->saved_ip = rtcp_exp->tuple.dst.u3.ip;
		rtcp_exp->tuple.dst.u3.ip = rtp_addr->ip;
		rtcp_exp->saved_proto.udp.port = rtcp_exp->tuple.dst.u.udp.port;
		rtcp_exp->dir = !dir;
		rtcp_exp->expectfn = ip_nat_sip_expected;

		port = ntohs(rtp_exp->tuple.dst.u.udp.port);
		if (port == 65534)	// reset the port number to 10000.
			port = 10000;
		/* Try to get same pair of ports: if not, try to change them. */
		for ( ; port != 0 ; port += 2) {
			rtp_exp->tuple.dst.u.udp.port = htons(port);
			if (nf_conntrack_expect_related(rtp_exp) != 0)
				continue;
			rtcp_exp->tuple.dst.u.udp.port = htons(port + 1);
			if (nf_conntrack_expect_related(rtcp_exp) == 0)
				break;
			nf_conntrack_unexpect_related(rtp_exp);
		}
	}
	
	if (port == 0)
		goto err1;

#if 0
	{
		char tmp[32];

		DEBUGP(" dptr 0x%x mediaoff %d\n", (*dptr), mediaoff);

		snprintf(tmp,30,"%s",(*dptr)+mediaoff);
	 	DEBUGP(" mangle data [%s]len %d with [%d]\n", tmp, medialen, port);
	}
#endif

	/* Update media port. */
#if 0
	DEBUGP("rtp_exp->tuple.dst.u.udp.port [%d]\n", rtp_exp->tuple.dst.u.udp.port);
	DEBUGP("rtp_exp->saved_proto.udp.port [%d]\n", rtp_exp->saved_proto.udp.port);
#endif
	if (/*rtp_exp->tuple.dst.u.udp.port != rtp_exp->saved_proto.udp.port &&*/
		!ip_nat_sdp_port(skb, dptr, datalen, mediaoff, medialen, port))
		goto err2;

	DEBUGP(" NF_ACCEPT\n");
#if 1
	SIP_DEBUG_DUMP_NF_CT_TUPLEHASH(ct);
	SIP_DEBUG_DUMP_NF_EXPECT_TUPLE(rtp_exp);
 	SIP_DEBUG_DUMP_NF_EXPECT_NAT_NEEDED(rtp_exp);
#endif

	return NF_ACCEPT;

err2:
	nf_conntrack_unexpect_related(rtp_exp);
	nf_conntrack_unexpect_related(rtcp_exp);
err1:
	DEBUGP(" NF_DROP\n");
	return NF_DROP;
}

/*merge from 26.35.6*/
static unsigned int ip_nat_sip_expect(struct sk_buff **skb,
				      const char **dptr, unsigned int *datalen,
				      struct nf_conntrack_expect *exp,
				      unsigned int matchoff,
				      unsigned int matchlen)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(*skb, &ctinfo);
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	__be32 newip;
	u_int16_t port;
	char buffer[sizeof("nnn.nnn.nnn.nnn:nnnnn")];
	unsigned buflen;
	
	/* Connection will come from reply */
	if (ct->tuplehash[dir].tuple.src.u3.ip == ct->tuplehash[!dir].tuple.dst.u3.ip)
		newip = exp->tuple.dst.u3.ip;
	else
		newip = ct->tuplehash[!dir].tuple.dst.u3.ip;

	/* If the signalling port matches the connection's source port in the
	 * original direction, try to use the destination port in the opposite
	 * direction. */
	if (exp->tuple.dst.u.udp.port ==
	    ct->tuplehash[dir].tuple.src.u.udp.port)
		port = ntohs(ct->tuplehash[!dir].tuple.dst.u.udp.port);
	else
		port = ntohs(exp->tuple.dst.u.udp.port);

	exp->saved_ip = exp->tuple.dst.u3.ip;
	exp->tuple.dst.u3.ip = newip;
	exp->saved_proto.udp.port = exp->tuple.dst.u.udp.port;
	exp->dir = !dir;
	exp->expectfn = ip_nat_sip_expected;

	for (; port != 0; port++) {
		exp->tuple.dst.u.udp.port = htons(port);
		if (nf_conntrack_expect_related(exp) == 0)
			break;
	}

	if (port == 0)
		return NF_DROP;
	
	if (exp->tuple.dst.u3.ip != exp->saved_ip ||
	    exp->tuple.dst.u.udp.port != exp->saved_proto.udp.port) {
		buflen = sprintf(buffer, "%u.%u.%u.%u:%u", NIPQUAD(newip), port);
	
		if (!mangle_packet(skb, dptr, datalen,
				   matchoff, matchlen, buffer, buflen))
			goto err;
	}
	return NF_ACCEPT;

err:
	nf_conntrack_unexpect_related(exp);
	return NF_DROP;
}
/*end merge from 26.35.6*/

static void __exit nf_nat_sip_fini(void)
{
	rcu_assign_pointer(nf_nat_sip_hook, NULL);
	rcu_assign_pointer(nf_nat_sdp_addr_hook, NULL);
	rcu_assign_pointer(nf_nat_sdp_port_hook, NULL);
	rcu_assign_pointer(nf_nat_sdp_session_hook, NULL);
	rcu_assign_pointer(nf_nat_sdp_media_hook, NULL);
	synchronize_rcu();
}

static int __init nf_nat_sip_init(void)
{
	BUG_ON(nf_nat_sip_hook != NULL);
	BUG_ON(nf_nat_sdp_addr_hook != NULL);
	BUG_ON(nf_nat_sdp_port_hook != NULL);
	BUG_ON(nf_nat_sdp_session_hook != NULL);
	BUG_ON(nf_nat_sdp_media_hook != NULL);
	rcu_assign_pointer(nf_nat_sip_hook, ip_nat_sip);
	rcu_assign_pointer(nf_nat_sdp_addr_hook, ip_nat_sdp_addr);
	rcu_assign_pointer(nf_nat_sdp_port_hook, ip_nat_sdp_port);
	rcu_assign_pointer(nf_nat_sdp_session_hook, ip_nat_sdp_session);
	rcu_assign_pointer(nf_nat_sdp_media_hook, ip_nat_sdp_media);
	return 0;
}

module_init(nf_nat_sip_init);
module_exit(nf_nat_sip_fini);
