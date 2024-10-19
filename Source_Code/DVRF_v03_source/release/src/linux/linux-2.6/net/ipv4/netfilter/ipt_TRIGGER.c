/*======================================================================
 *
 *          Copyright (C) 2010-2011 CyberTan Corporation
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *  Version: NA
 *
 * ----------------------------------------------------------------------------------
 *  File          :   ipt_TRIGGER .c
 *
 *  Description   :   This is kernel module for port-triggering. 
 *
 *   The module follows the Netfilter framework, called extended packet  
 *   matching modules.  
 *
 ======================================================================*/

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/dst.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_TRIGGER.h>
#include <net/netfilter/nf_nat_rule.h>
#ifdef CONFIG_BRIDGE_NETFILTER
#include <linux/netfilter_bridge.h>
#endif
#define ASSERT_READ_LOCK(x)
#define ASSERT_WRITE_LOCK(x)

/* Use lock to protect */
static DEFINE_RWLOCK(trigger_lock);
LIST_HEAD(trigger_list);

#if 0
#define DEBUGP printk
#else
#define DEBUGP(format, args...)
#endif

/* Return pointer to first true entry, if any, or NULL.  A macro
   required to allow inlining of cmpfn. */
#define LIST_FIND(head, cmpfn, type, args...)		\
({							\
	const struct list_head *__i, *__j = NULL;	\
							\
	ASSERT_READ_LOCK(head);				\
	list_for_each(__i, (head))			\
		if (cmpfn((const type)__i , ## args)) {	\
			__j = __i;			\
			break;				\
		}					\
	(type)__j;					\
})

#define DUMP_TUPLE(tp)						\
DEBUGP("tuple %p: %u %u.%u.%u.%u:%hu -> %u.%u.%u.%u:%hu\n",	\
       (tp), (tp)->dst.protonum,				\
       NIPQUAD((tp)->src.u3.ip), ntohs((tp)->src.u.all),		\
       NIPQUAD((tp)->dst.u3.ip), ntohs((tp)->dst.u.all))

struct ipt_trigger {
	struct list_head list;		/* Trigger list */
	struct timer_list timeout;	/* Timer for list destroying */
	u_int32_t srcip;		/* Outgoing source address */
	u_int32_t dstip;		/* Outgoing destination address */
	u_int16_t mproto;		/* Trigger protocol */
	u_int16_t rproto;		/* Related protocol */
	struct ipt_trigger_ports ports;	/* Trigger and related ports */
	u_int8_t reply;			/* Confirm a reply connection */
};

/*================Taide add 2010_8_9=================*/
#include <linux/netfilter_ipv4/ipt_LOG.h>

static struct nf_loginfo default_loginfo = {
	.type	= NF_LOG_TYPE_LOG,
	.u = {
		.log = {
			.level    = NF_LOG_IPOPT,
			.logflags = NF_LOG_MASK,
		},
	},
};


static void dump_packet(const struct nf_loginfo *info,
			const struct sk_buff *skb,
			unsigned int iphoff)
{
	struct iphdr _iph, *ih;
	unsigned int logflags;

	if (info->type == NF_LOG_TYPE_LOG)
		logflags = info->u.log.logflags;
	else
		logflags = NF_LOG_MASK;

	ih = skb_header_pointer(skb, iphoff, sizeof(_iph), &_iph);
	if (ih == NULL) {
		printk("TRUNCATED");
		return;
	}

	/* Important fields:
	 * TOS, len, DF/MF, fragment offset, TTL, src, dst, options. */
	/* Max length: 40 "SRC=255.255.255.255 DST=255.255.255.255 " */
	printk("SRC=%u.%u.%u.%u DST=%u.%u.%u.%u ",
	       NIPQUAD(ih->saddr), NIPQUAD(ih->daddr));

	/* Max length: 46 "LEN=65535 TOS=0xFF PREC=0xFF TTL=255 ID=65535 " */
	printk("LEN=%u TOS=0x%02X PREC=0x%02X TTL=%u ID=%u ",
	       ntohs(ih->tot_len), ih->tos & IPTOS_TOS_MASK,
	       ih->tos & IPTOS_PREC_MASK, ih->ttl, ntohs(ih->id));

	/* Max length: 6 "CE DF MF " */
	if (ntohs(ih->frag_off) & IP_CE)
		printk("CE ");
	if (ntohs(ih->frag_off) & IP_DF)
		printk("DF ");
	if (ntohs(ih->frag_off) & IP_MF)
		printk("MF ");

	/* Max length: 11 "FRAG:65535 " */
	if (ntohs(ih->frag_off) & IP_OFFSET)
		printk("FRAG:%u ", ntohs(ih->frag_off) & IP_OFFSET);

	if ((logflags & IPT_LOG_IPOPT)
	    && ih->ihl * 4 > sizeof(struct iphdr)) {
		unsigned char _opt[4 * 15 - sizeof(struct iphdr)], *op;
		unsigned int i, optsize;

		optsize = ih->ihl * 4 - sizeof(struct iphdr);
		op = skb_header_pointer(skb, iphoff+sizeof(_iph),
					optsize, _opt);
		if (op == NULL) {
			printk("TRUNCATED");
			return;
		}

		/* Max length: 127 "OPT (" 15*4*2chars ") " */
		printk("OPT (");
		for (i = 0; i < optsize; i++)
			printk("%02X", op[i]);
		printk(") ");
	}

	switch (ih->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr _tcph, *th;

		/* Max length: 10 "PROTO=TCP " */
		printk("PROTO=TCP ");

		if (ntohs(ih->frag_off) & IP_OFFSET)
			break;

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		th = skb_header_pointer(skb, iphoff + ih->ihl * 4,
					sizeof(_tcph), &_tcph);
		if (th == NULL) {
			printk("INCOMPLETE [%u bytes] ",
			       skb->len - iphoff - ih->ihl*4);
			break;
		}

		/* Max length: 20 "SPT=65535 DPT=65535 " */
		printk("SPT=%u DPT=%u ",
		       ntohs(th->source), ntohs(th->dest));
		/* Max length: 30 "SEQ=4294967295 ACK=4294967295 " */
		if (logflags & IPT_LOG_TCPSEQ)
			printk("SEQ=%u ACK=%u ",
			       ntohl(th->seq), ntohl(th->ack_seq));
		/* Max length: 13 "WINDOW=65535 " */
		printk("WINDOW=%u ", ntohs(th->window));
		/* Max length: 9 "RES=0x3F " */
		printk("RES=0x%02x ", (u8)(ntohl(tcp_flag_word(th) & TCP_RESERVED_BITS) >> 22));
		/* Max length: 32 "CWR ECE URG ACK PSH RST SYN FIN " */
		if (th->cwr)
			printk("CWR ");
		if (th->ece)
			printk("ECE ");
		if (th->urg)
			printk("URG ");
		if (th->ack)
			printk("ACK ");
		if (th->psh)
			printk("PSH ");
		if (th->rst)
			printk("RST ");
		if (th->syn)
			printk("SYN ");
		if (th->fin)
			printk("FIN ");
		/* Max length: 11 "URGP=65535 " */
		printk("URGP=%u ", ntohs(th->urg_ptr));

		if ((logflags & IPT_LOG_TCPOPT)
		    && th->doff * 4 > sizeof(struct tcphdr)) {
			unsigned char _opt[4 * 15 - sizeof(struct tcphdr)];
			unsigned char *op;
			unsigned int i, optsize;

			optsize = th->doff * 4 - sizeof(struct tcphdr);
			op = skb_header_pointer(skb,
						iphoff+ih->ihl*4+sizeof(_tcph),
						optsize, _opt);
			if (op == NULL) {
				printk("TRUNCATED");
				return;
			}

			/* Max length: 127 "OPT (" 15*4*2chars ") " */
			printk("OPT (");
			for (i = 0; i < optsize; i++)
				printk("%02X", op[i]);
			printk(") ");
		}
		break;
	}
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE: {
		struct udphdr _udph, *uh;

		if (ih->protocol == IPPROTO_UDP)
			/* Max length: 10 "PROTO=UDP "     */
			printk("PROTO=UDP " );
		else	/* Max length: 14 "PROTO=UDPLITE " */
			printk("PROTO=UDPLITE ");

		if (ntohs(ih->frag_off) & IP_OFFSET)
			break;

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		uh = skb_header_pointer(skb, iphoff+ih->ihl*4,
					sizeof(_udph), &_udph);
		if (uh == NULL) {
			printk("INCOMPLETE [%u bytes] ",
			       skb->len - iphoff - ih->ihl*4);
			break;
		}

		/* Max length: 20 "SPT=65535 DPT=65535 " */
		printk("SPT=%u DPT=%u LEN=%u ",
		       ntohs(uh->source), ntohs(uh->dest),
		       ntohs(uh->len));
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr _icmph, *ich;
		static const size_t required_len[NR_ICMP_TYPES+1]
			= { [ICMP_ECHOREPLY] = 4,
			    [ICMP_DEST_UNREACH]
			    = 8 + sizeof(struct iphdr),
			    [ICMP_SOURCE_QUENCH]
			    = 8 + sizeof(struct iphdr),
			    [ICMP_REDIRECT]
			    = 8 + sizeof(struct iphdr),
			    [ICMP_ECHO] = 4,
			    [ICMP_TIME_EXCEEDED]
			    = 8 + sizeof(struct iphdr),
			    [ICMP_PARAMETERPROB]
			    = 8 + sizeof(struct iphdr),
			    [ICMP_TIMESTAMP] = 20,
			    [ICMP_TIMESTAMPREPLY] = 20,
			    [ICMP_ADDRESS] = 12,
			    [ICMP_ADDRESSREPLY] = 12 };

		/* Max length: 11 "PROTO=ICMP " */
		printk("PROTO=ICMP ");

		if (ntohs(ih->frag_off) & IP_OFFSET)
			break;

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		ich = skb_header_pointer(skb, iphoff + ih->ihl * 4,
					 sizeof(_icmph), &_icmph);
		if (ich == NULL) {
			printk("INCOMPLETE [%u bytes] ",
			       skb->len - iphoff - ih->ihl*4);
			break;
		}

		/* Max length: 18 "TYPE=255 CODE=255 " */
		printk("TYPE=%u CODE=%u ", ich->type, ich->code);

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		if (ich->type <= NR_ICMP_TYPES
		    && required_len[ich->type]
		    && skb->len-iphoff-ih->ihl*4 < required_len[ich->type]) {
			printk("INCOMPLETE [%u bytes] ",
			       skb->len - iphoff - ih->ihl*4);
			break;
		}

		switch (ich->type) {
		case ICMP_ECHOREPLY:
		case ICMP_ECHO:
			/* Max length: 19 "ID=65535 SEQ=65535 " */
			printk("ID=%u SEQ=%u ",
			       ntohs(ich->un.echo.id),
			       ntohs(ich->un.echo.sequence));
			break;

		case ICMP_PARAMETERPROB:
			/* Max length: 14 "PARAMETER=255 " */
			printk("PARAMETER=%u ",
			       ntohl(ich->un.gateway) >> 24);
			break;
		case ICMP_REDIRECT:
			/* Max length: 24 "GATEWAY=255.255.255.255 " */
			printk("GATEWAY=%u.%u.%u.%u ",
			       NIPQUAD(ich->un.gateway));
			/* Fall through */
		case ICMP_DEST_UNREACH:
		case ICMP_SOURCE_QUENCH:
		case ICMP_TIME_EXCEEDED:
			/* Max length: 3+maxlen */
			if (!iphoff) { /* Only recurse once. */
				printk("[");
				dump_packet(info, skb,
					    iphoff + ih->ihl*4+sizeof(_icmph));
				printk("] ");
			}

			/* Max length: 10 "MTU=65535 " */
			if (ich->type == ICMP_DEST_UNREACH
			    && ich->code == ICMP_FRAG_NEEDED)
				printk("MTU=%u ", ntohs(ich->un.frag.mtu));
		}
		break;
	}
	/* Max Length */
	case IPPROTO_AH: {
		struct ip_auth_hdr _ahdr, *ah;

		if (ntohs(ih->frag_off) & IP_OFFSET)
			break;

		/* Max length: 9 "PROTO=AH " */
		printk("PROTO=AH ");

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		ah = skb_header_pointer(skb, iphoff+ih->ihl*4,
					sizeof(_ahdr), &_ahdr);
		if (ah == NULL) {
			printk("INCOMPLETE [%u bytes] ",
			       skb->len - iphoff - ih->ihl*4);
			break;
		}

		/* Length: 15 "SPI=0xF1234567 " */
		printk("SPI=0x%x ", ntohl(ah->spi));
		break;
	}
	case IPPROTO_ESP: {
		struct ip_esp_hdr _esph, *eh;

		/* Max length: 10 "PROTO=ESP " */
		printk("PROTO=ESP ");

		if (ntohs(ih->frag_off) & IP_OFFSET)
			break;

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		eh = skb_header_pointer(skb, iphoff+ih->ihl*4,
					sizeof(_esph), &_esph);
		if (eh == NULL) {
			printk("INCOMPLETE [%u bytes] ",
			       skb->len - iphoff - ih->ihl*4);
			break;
		}

		/* Length: 15 "SPI=0xF1234567 " */
		printk("SPI=0x%x ", ntohl(eh->spi));
		break;
	}
	/* Max length: 10 "PROTO 255 " */
	default:
		printk("PROTO=%u ", ih->protocol);
	}

	/* Max length: 15 "UID=4294967295 " */
	if ((logflags & IPT_LOG_UID) && !iphoff && skb->sk) {
		read_lock_bh(&skb->sk->sk_callback_lock);
		if (skb->sk->sk_socket && skb->sk->sk_socket->file)
			printk("UID=%u ", skb->sk->sk_socket->file->f_uid);
		read_unlock_bh(&skb->sk->sk_callback_lock);
	}

	/* Proto    Max log string length */
	/* IP:      40+46+6+11+127 = 230 */
	/* TCP:     10+max(25,20+30+13+9+32+11+127) = 252 */
	/* UDP:     10+max(25,20) = 35 */
	/* UDPLITE: 14+max(25,20) = 39 */
	/* ICMP:    11+max(25, 18+25+max(19,14,24+3+n+10,3+n+10)) = 91+n */
	/* ESP:     10+max(25)+15 = 50 */
	/* AH:      9+max(25)+15 = 49 */
	/* unknown: 10 */

	/* (ICMP allows recursion one level deep) */
	/* maxlen =  IP + ICMP +  IP + max(TCP,UDP,ICMP,unknown) */
	/* maxlen = 230+   91  + 230 + 252 = 803 */
}

static void
log_packet(unsigned int pf,
	       unsigned int hooknum,
	       const struct sk_buff *skb,
	       const struct net_device *in,
	       const struct net_device *out,
	       const struct nf_loginfo *loginfo,
	       const char *prefix)
{
	if (!loginfo)
		loginfo = &default_loginfo;

	
       write_lock_bh(&trigger_lock);
	printk("<%d>%sIN=%s OUT=%s ", loginfo->u.log.level,
	       prefix,
	       in ? in->name : "",
	       out ? out->name : "");
#ifdef CONFIG_BRIDGE_NETFILTER
	if (skb->nf_bridge) {
		struct net_device *physindev = skb->nf_bridge->physindev;
		struct net_device *physoutdev = skb->nf_bridge->physoutdev;

		if (physindev && in != physindev)
			printk("PHYSIN=%s ", physindev->name);
		if (physoutdev && out != physoutdev)
			printk("PHYSOUT=%s ", physoutdev->name);
	}
#endif

	if (in && !out) {
		/* MAC logging for input chain only. */
		printk("MAC=");
		if (skb->dev && skb->dev->hard_header_len
		    && skb->mac_header != skb->network_header) {
			int i;
			const unsigned char *p = skb_mac_header(skb);
			for (i = 0; i < skb->dev->hard_header_len; i++,p++)
				printk("%02x%c", *p,
				       i==skb->dev->hard_header_len - 1
				       ? ' ':':');
		} else
			printk(" ");
	}

	dump_packet(loginfo, skb, 0);
	printk("\n");
       write_unlock_bh(&trigger_lock);
}
/*=====================================end by Taide */
static void trigger_refresh(struct ipt_trigger *trig, unsigned long extra_jiffies)
{
    DEBUGP("%s: \n", __FUNCTION__);
    NF_CT_ASSERT(trig);
    write_lock_bh(&trigger_lock);

    /* Need del_timer for race avoidance (may already be dying). */
    if (del_timer(&trig->timeout)) {
	trig->timeout.expires = jiffies + extra_jiffies;
	add_timer(&trig->timeout);
    }

    write_unlock_bh(&trigger_lock);
}

static void __del_trigger(struct ipt_trigger *trig)
{
    DEBUGP("%s: \n", __FUNCTION__);
    NF_CT_ASSERT(trig);
    ASSERT_WRITE_LOCK(&trigger_lock);

     /* delete from 'trigger_list' */
    list_del(&trig->list);
    kfree(trig);
}

static void trigger_timeout(unsigned long ul_trig)
{
    struct ipt_trigger *trig= (void *) ul_trig;

    DEBUGP("trigger list %p timed out\n", trig);
    write_lock_bh(&trigger_lock);
    __del_trigger(trig);
    write_unlock_bh(&trigger_lock);
}

static unsigned int
add_new_trigger(struct ipt_trigger *trig)
{
    struct ipt_trigger *new;

    DEBUGP("!!!!!!!!!!!! %s !!!!!!!!!!!\n", __FUNCTION__);
    write_lock_bh(&trigger_lock);
    new = (struct ipt_trigger *)
	kmalloc(sizeof(struct ipt_trigger), GFP_ATOMIC);

    if (!new) {
	write_unlock_bh(&trigger_lock);
	DEBUGP("%s: OOM allocating trigger list\n", __FUNCTION__);
	return -ENOMEM;
    }

    memset(new, 0, sizeof(*trig));
    INIT_LIST_HEAD(&new->list);
    memcpy(new, trig, sizeof(*trig));
    /* add to global table of trigger */
    list_add(&new->list, &trigger_list);
    /* add and start timer if required */
    init_timer(&new->timeout);
    new->timeout.data = (unsigned long)new;
    new->timeout.function = trigger_timeout;
    new->timeout.expires = jiffies + (TRIGGER_TIMEOUT * HZ);
    add_timer(&new->timeout);
	    
    write_unlock_bh(&trigger_lock);

    return 0;
}

static inline int trigger_out_matched(const struct ipt_trigger *i,
	const u_int16_t proto, const u_int16_t dport)
{
    DEBUGP("%s: i=%p, proto= %d, dport=%d.\n", __FUNCTION__, i, proto, dport);
    DEBUGP("%s: Got one, mproto= %d, mport[0..1]=%d, %d.\n", __FUNCTION__, 
	    i->mproto, i->ports.mport[0], i->ports.mport[1]);

    return ((i->mproto == proto) && (i->ports.mport[0] <= dport) 
	    && (i->ports.mport[1] >= dport));
}

static unsigned int
trigger_out(struct sk_buff **pskb,
		unsigned int hooknum,
		const struct net_device *in,
		const struct net_device *out,
		const void *targinfo)
{
    const struct ipt_trigger_info *info = targinfo;
    struct ipt_trigger trig, *found;
    const struct iphdr *iph = ip_hdr(*pskb);
    struct tcphdr *tcph = (void *)iph + iph->ihl*4;	/* Might be TCP, UDP */

    DEBUGP("############# %s ############\n", __FUNCTION__);
    /* Check if the trigger range has already existed in 'trigger_list'. */
    found = LIST_FIND(&trigger_list, trigger_out_matched, struct ipt_trigger *, iph->protocol, ntohs(tcph->dest));

    if (found) {
	/* Yeah, it exists. We need to update(delay) the destroying timer. */
	trigger_refresh(found, TRIGGER_TIMEOUT * HZ);
	/* In order to allow multiple hosts use the same port range, we update
	   the 'saddr' after previous trigger has a reply connection. */
	if (found->reply)
	    found->srcip = iph->saddr;
    }
    else {
	/* Create new trigger */
	memset(&trig, 0, sizeof(trig));
	trig.srcip = iph->saddr;
	trig.mproto = iph->protocol;
	trig.rproto = info->proto;
	memcpy(&trig.ports, &info->ports, sizeof(struct ipt_trigger_ports));
	add_new_trigger(&trig);	/* Add the new 'trig' to list 'trigger_list'. */
    }

    return IPT_CONTINUE;	/* We don't block any packet. */
}

static inline int trigger_in_matched(const struct ipt_trigger *i,
	const u_int16_t proto, const u_int16_t dport)
{
    u_int16_t rproto = i->rproto;

    DEBUGP("%s: i=%p, proto= %d, dport=%d.\n", __FUNCTION__, i, proto, dport);
    DEBUGP("%s: Got one, rproto= %d, rport[0..1]=%d, %d.\n", __FUNCTION__, i->rproto, i->ports.rport[0], i->ports.rport[1]); 

    if (!rproto)
	rproto = proto;

    return ((rproto == proto) && (i->ports.rport[0] <= dport) 
	    && (i->ports.rport[1] >= dport));
}

static unsigned int
trigger_in(struct sk_buff **pskb,
		unsigned int hooknum,
		const struct net_device *in,
		const struct net_device *out,
		const void *targinfo)
{
    struct ipt_trigger *found;
    //const struct iphdr *iph = (*pskb)->nh.iph;
    const struct iphdr *iph = ip_hdr(*pskb);
    struct tcphdr *tcph = (void *)iph + iph->ihl*4;	/* Might be TCP, UDP */

	DEBUGP("2############# %s ############\n", __FUNCTION__);
    /* Check if the trigger-ed range has already existed in 'trigger_list'. */
    found = LIST_FIND(&trigger_list, trigger_in_matched,
	    struct ipt_trigger *, iph->protocol, ntohs(tcph->dest));
    if (found) {
	DEBUGP("############# %s ############\n", __FUNCTION__);
	/* Yeah, it exists. We need to update(delay) the destroying timer. */
	trigger_refresh(found, TRIGGER_TIMEOUT * HZ);
	/*Taide add to  show trigger packet in incoming log 2010_8_10  begin*/
	log_packet(0, hooknum,*pskb,	in,out,NULL,	"TRIGGER ");
	/*--------------------------------------------end by Taide*/
	return NF_ACCEPT;	/* Accept it, or the imcoming packet could be 
				   dropped in the FORWARD chain */
    }
 
    return IPT_CONTINUE;	/* Our job is the interception. */
}

static unsigned int
trigger_dnat(struct sk_buff **pskb,
		unsigned int hooknum,
		const struct net_device *in,
		const struct net_device *out,
		const void *targinfo)
{
    struct ipt_trigger *found;
    //const struct iphdr *iph = (*pskb)->nh.iph;
    const struct iphdr *iph = ip_hdr(*pskb);
    struct tcphdr *tcph = (void *)iph + iph->ihl*4;	/* Might be TCP, UDP */
    struct nf_conn *ct;
    enum ip_conntrack_info ctinfo;
    struct nf_nat_range newrange;

    DEBUGP("1############# %s ############\n", __FUNCTION__);
    NF_CT_ASSERT(hooknum == NF_IP_PRE_ROUTING);
    /* Check if the trigger-ed range has already existed in 'trigger_list'. */
    found = LIST_FIND(&trigger_list, trigger_in_matched,
	    struct ipt_trigger *, iph->protocol, ntohs(tcph->dest));

    if (!found || !found->srcip)
	return IPT_CONTINUE;	/* We don't block any packet. */

    DEBUGP("############# %s ############\n", __FUNCTION__);
    found->reply = 1;	/* Confirm there has been a reply connection. */
    ct = nf_ct_get(*pskb, &ctinfo);
    NF_CT_ASSERT(ct && (ctinfo == IP_CT_NEW));

    DEBUGP("%s: got ", __FUNCTION__);
    DUMP_TUPLE(&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);

    /* Alter the destination of imcoming packet. */
    newrange = ((struct nf_nat_range)
	    { IP_NAT_RANGE_MAP_IPS,
	             found->srcip, found->srcip,
	             { 0 }, { 0 }
	           });
#ifdef DEL_IP_CONNTRACK_ENTRY
	ct->its = IPT_TRIGGER_STATUS_DNAT;
#endif

    /* Hand modified range to generic setup. */
    return nf_nat_setup_info(ct, &newrange, hooknum);
}

static unsigned int
trigger_target(struct sk_buff **pskb,
		const struct net_device *in,
		const struct net_device *out,
		unsigned int hooknum,
		const struct xt_target *target,
		const void *targinfo)
{
	const struct ipt_trigger_info *info = targinfo;
	const struct iphdr *iph = ip_hdr(*pskb);

    DEBUGP("%s: type = %s\n", __FUNCTION__, 
	    (info->type == IPT_TRIGGER_DNAT) ? "dnat" :
	    (info->type == IPT_TRIGGER_IN) ? "in" : "out");

    /* The Port-trigger only supports TCP and UDP. */
	if ((iph->protocol != IPPROTO_TCP) && (iph->protocol != IPPROTO_UDP))
		return IPT_CONTINUE;

	if (info->type == IPT_TRIGGER_OUT)
		return trigger_out(pskb, hooknum, in, out, targinfo);
	else if (info->type == IPT_TRIGGER_IN)
		return trigger_in(pskb, hooknum, in, out, targinfo);
	else if (info->type == IPT_TRIGGER_DNAT)
		return trigger_dnat(pskb, hooknum, in, out, targinfo);

    return IPT_CONTINUE;
}

static int
trigger_check(const char *tablename,
	       const void *e,
	       const struct xt_target *target,
	       void *targinfo,
	       unsigned int hook_mask)
{
	const struct ipt_trigger_info *info = targinfo;
	struct list_head *cur_item, *tmp_item;

	if ((strcmp(tablename, "mangle") == 0)) {
		DEBUGP("trigger_check: bad table `%s'.\n", tablename);
		return 0;
	}
/*
	if (targinfosize != IPT_ALIGN(sizeof(*info))) {
		DEBUGP("trigger_check: size %u.\n", targinfosize);
		return 0;
	}
*/
	if (hook_mask & ~((1 << NF_IP_PRE_ROUTING) | (1 << NF_IP_FORWARD))) {
		DEBUGP("trigger_check: bad hooks %x.\n", hook_mask);
		return 0;
	}
	if (info->proto) {
	    if (info->proto != IPPROTO_TCP && info->proto != IPPROTO_UDP) {
		DEBUGP("trigger_check: bad proto %d.\n", info->proto);
		return 0;
	    }
	}
	if (info->type == IPT_TRIGGER_OUT) {
	    if (!info->ports.mport[0] || !info->ports.rport[0]) {
		DEBUGP("trigger_check: Try 'iptbles -j TRIGGER -h' for help.\n");
		return 0;
	    }
	}

	/* Empty the 'trigger_list' */
	list_for_each_safe(cur_item, tmp_item, &trigger_list) {
	    struct ipt_trigger *trig = (void *)cur_item;

	    DEBUGP("%s: list_for_each_safe(): %p.\n", __FUNCTION__, trig);
	    del_timer(&trig->timeout);
	    __del_trigger(trig);
	}

	return 1;
}
static struct xt_target ipt_trigger = {
	.name		= "TRIGGER",
	.family		= AF_INET,
	.target		= trigger_target,
	.targetsize	= sizeof(struct ipt_trigger_info),
//	.table		= "nat",
	.hooks		= (1 << NF_IP_PRE_ROUTING) | (1 << NF_IP_FORWARD),
	.checkentry	= trigger_check,
	.me		= THIS_MODULE,
};

static int __init init(void)
{
	return xt_register_target(&ipt_trigger);
}

static void __exit fini(void)
{
	xt_unregister_target(&ipt_trigger);
}

module_init(init);
module_exit(fini);
