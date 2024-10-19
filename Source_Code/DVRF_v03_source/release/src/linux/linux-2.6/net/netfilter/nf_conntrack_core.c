/* Connection state tracking for netfilter.  This is separated from,
   but required by, the NAT layer; it can also be used by an iptables
   extension. */

/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2006 Netfilter Core Team <coreteam@netfilter.org>
 * (C) 2003,2004 USAGI/WIDE Project <http://www.linux-ipv6.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/stddef.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/err.h>
#include <linux/percpu.h>
#include <linux/moduleparam.h>
#include <linux/notifier.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/mm.h>
#ifdef CONFIG_BCM_NAT
#include <net/ip.h>
#endif

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_core.h>

#define NF_CONNTRACK_VERSION	"0.5.0"

#ifdef HNDCTF
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/route.h>
#include <typedefs.h>
#include <osl.h>
#include <ctf/hndctf.h>

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>

#define IPVERSION_IS_4(ipver)		((ipver) == 4)
#else
#define IPVERSION_IS_4(ipver)		1
#endif /* CONFIG_IPV6 */
#define NFC_CTF_ENABLED	(1 << 31)
#endif /* HNDCTF */

#define DEBUGP(format, args...)

DEFINE_RWLOCK(nf_conntrack_lock);
EXPORT_SYMBOL_GPL(nf_conntrack_lock);

/* nf_conntrack_standalone needs this */
atomic_t nf_conntrack_count = ATOMIC_INIT(0);
EXPORT_SYMBOL_GPL(nf_conntrack_count);

void (*nf_conntrack_destroyed)(struct nf_conn *conntrack);
EXPORT_SYMBOL_GPL(nf_conntrack_destroyed);

unsigned int nf_conntrack_htable_size __read_mostly;
EXPORT_SYMBOL_GPL(nf_conntrack_htable_size);

int nf_conntrack_max __read_mostly;
EXPORT_SYMBOL_GPL(nf_conntrack_max);

struct list_head *nf_conntrack_hash __read_mostly;
EXPORT_SYMBOL_GPL(nf_conntrack_hash);

struct nf_conn nf_conntrack_untracked __read_mostly;
EXPORT_SYMBOL_GPL(nf_conntrack_untracked);

unsigned int nf_ct_log_invalid __read_mostly;
LIST_HEAD(unconfirmed);
static int nf_conntrack_vmalloc __read_mostly;

static unsigned int nf_conntrack_next_id;

DEFINE_PER_CPU(struct ip_conntrack_stat, nf_conntrack_stat);
EXPORT_PER_CPU_SYMBOL(nf_conntrack_stat);

#if defined(CONFIG_BCM_NAT) || defined(HNDCTF)
//Zhijian add for fastnat and hndctf 2010-07-27	
//#define CTF_QOS_MARK_ONLY
#define MTU_CONTROL
#define REFRESH_CT_TIMER
#ifdef REFRESH_CT_TIMER
extern unsigned int nf_ct_tcp_timeout_established;
extern unsigned int nf_ct_udp_timeout_stream;
#endif

#define IP_MASK_MAX 256
typedef struct _ip_mask
{
	u32			ip;
	u32			mask;
}ip_mask_t;
static ip_mask_t lan_ip_masks[IP_MASK_MAX];
static unsigned int ip_mask_num = 0;

typedef struct ctf_qos
{
	struct ctf_qos * next;
	ctf_conn_tuple_t	tuple;
	int tos;
	__u32 priority;
	__u32 mark;
#if !defined(HNDCTF)
	uint32			live;	
#endif
#ifdef MTU_CONTROL
	uint32			mtu;
#endif
#ifdef REFRESH_CT_TIMER
	struct ip_conntrack *ct;
#endif
	unsigned char smac[ETH_ALEN];
}ctf_qos_t;

static spinlock_t qtable_lock = SPIN_LOCK_UNLOCKED;

#define QOS_TABLE_SZ	1025
static ctf_qos_t * qos_table[QOS_TABLE_SZ];
static struct kmem_cache *qos_record_cache;

static void qos_table_dump_entry(const char * comment, ctf_qos_t * qos_entry)
{
	if(qos_entry != NULL)
	{
		printk("%s qos entry(0x%p): %s %08x:%u->%08x:%u tos:%u priority:%u mark:%u next:0x%p\n",
			(comment == NULL) ? "" : comment,
			qos_entry, (qos_entry->tuple.proto == IPPROTO_TCP) ? "tcp" : "udp",
			ntohl(qos_entry->tuple.sip[0]), ntohs(qos_entry->tuple.sp),
			ntohl(qos_entry->tuple.dip[0]), ntohs(qos_entry->tuple.dp),
			qos_entry->tos, qos_entry->priority, qos_entry->mark,
			qos_entry->next);
	}
	else if(comment != NULL)
	{
		printk("%s qos entry(0x%p): \n", comment, NULL);
	}
}

static void qos_table_dump(const char * comment)
{
	uint32 hash;
	ctf_qos_t * qos_entry ;
	
	printk("===========================>>\n");
	if(comment != NULL)
	{
		printk("%s\n", comment);
	}
	spin_lock_bh(&qtable_lock);
	for(hash = 0; hash < QOS_TABLE_SZ; hash ++)
	{
		qos_entry = qos_table[hash];
		while(qos_entry != NULL)
		{
			qos_table_dump_entry(NULL, qos_entry);
			qos_entry = qos_entry->next;
		}
	}
	spin_unlock_bh(&qtable_lock);
	printk("<<===========================\n");
}

static inline void qos_init(void *p, struct kmem_cache *cache, 
				  unsigned long flags)
{
	ctf_qos_t *qos_entry = p;

	memset(qos_entry, 0, sizeof(ctf_qos_t));
#if !defined(HNDCTF)
	qos_entry->live = 1;	
#endif
}

static void qos_table_init(void)
{
	memset(qos_table, 0, sizeof(qos_table));
	qos_record_cache = kmem_cache_create("qos_record_cache",
					      sizeof(ctf_qos_t),
					      0,
					      SLAB_HWCACHE_ALIGN,
					      qos_init, NULL);
	if (!qos_record_cache)
		panic("cannot create qos record cache");
}

static ctf_qos_t * qos_table_get_entry(void)
{
	ctf_qos_t * qos_entry ;
	qos_entry = kmem_cache_alloc(qos_record_cache, GFP_ATOMIC);
	return qos_entry;
}

static void qos_table_free_entry(ctf_qos_t * qos_entry)
{
	if(qos_entry != NULL)
	{
		kmem_cache_free(qos_record_cache, qos_entry);
	}
}

static ctf_qos_t * qos_table_lkup(uint32 sip, uint32 dip, uint8 proto, uint16 sp, uint16 dp)
{
	uint32 hash;
	ctf_qos_t * qos_entry ;

	hash = (sip + dip + sp + dp + proto) % QOS_TABLE_SZ;
	spin_lock_bh(&qtable_lock);
	qos_entry = qos_table[hash];
	while(qos_entry != NULL)
	{
		if(qos_entry->tuple.sip[0] == sip
			&& qos_entry->tuple.dip[0] == dip
			&& qos_entry->tuple.proto == proto
			&& qos_entry->tuple.sp == sp
			&& qos_entry->tuple.dp == dp)
		{
			break;
		}
		qos_entry = qos_entry->next;
	}
	spin_unlock_bh(&qtable_lock);
	return qos_entry;
}

static void qos_table_insert(ctf_qos_t * qos_entry)
{
	uint32 hash;

	if(qos_entry != NULL)
	{
		hash = (qos_entry->tuple.sip[0] + qos_entry->tuple.dip[0] + qos_entry->tuple.sp + qos_entry->tuple.dp + qos_entry->tuple.proto) % QOS_TABLE_SZ;
		spin_lock_bh(&qtable_lock);
		qos_entry->next = qos_table[hash];
		qos_table[hash] = qos_entry;
		spin_unlock_bh(&qtable_lock);
	}
}

static void qos_table_add(ctf_conn_tuple_t * tuple, int tos, __u32 priority, __u32 mark, __u8 * smac
#ifdef REFRESH_CT_TIMER
	 , struct nf_conn *ct
#endif
#ifdef MTU_CONTROL
	 , uint32 mtu
#endif
	)
{
	ctf_qos_t * qos_entry = NULL;
	
	if(tuple == NULL)
	{
		return;
	}
	qos_entry = qos_table_lkup(tuple->sip, tuple->dip, tuple->proto, tuple->sp, tuple->dp);
	
	if(qos_entry != NULL)
	{
		qos_entry->priority = priority;
		qos_entry->mark = mark;
		qos_entry->tos = tos;
#ifdef REFRESH_CT_TIMER
		qos_entry->ct = ct;
#endif
#ifdef MTU_CONTROL
		 qos_entry->mtu = (mtu == 0) ? ETH_DATA_LEN : mtu;
#endif
		if(smac != NULL)
		{
			memcpy(qos_entry->smac, smac, ETH_ALEN);
		}
	}
	else
	{
		qos_entry = qos_table_get_entry();
		if(qos_entry != NULL)
		{
			memcpy(&qos_entry->tuple, tuple, sizeof(qos_entry->tuple));
			qos_entry->priority = priority;
			qos_entry->mark = mark;
			qos_entry->tos = tos;
#ifdef REFRESH_CT_TIMER
			qos_entry->ct = ct;
#endif
#ifdef MTU_CONTROL
			 qos_entry->mtu = (mtu == 0) ? ETH_DATA_LEN : mtu;
#endif
			if(smac != NULL)
			{
				memcpy(qos_entry->smac, smac, ETH_ALEN);
			}
			qos_table_insert(qos_entry);
		}
	}
#ifdef DEBUG
	printk("qos_table_add: %s %08x:%u->%08x:%u tos:%u priority:%u  mark:%u\n",
		(tuple->proto == IPPROTO_TCP) ? "tcp" : "udp",
		ntohl(tuple->sip), ntohs(tuple->sp), ntohl(tuple->dip), ntohs(tuple->dp), tos, priority, mark);
	qos_table_dump_entry("qos_table_add", qos_entry);
	qos_table_dump(NULL);
#endif
}

static ctf_qos_t * qos_table_get(uint32 sip, uint32 dip, uint8 proto, uint16 sp, uint16 dp)
{
	return qos_table_lkup(sip, dip, proto, sp, dp);
}

static void qos_table_delete(uint32 sip, uint32 dip, uint8 proto, uint16 sp, uint16 dp)
{
	uint32 hash;
	ctf_qos_t * prev ;
	ctf_qos_t * qos_entry ;

	hash = (sip + dip + sp + dp + proto) % QOS_TABLE_SZ;
	spin_lock_bh(&qtable_lock);
	prev = qos_table[hash];
	qos_entry = qos_table[hash];
	while(qos_entry != NULL)
	{
		if(qos_entry->tuple.sip[0] == sip
			&& qos_entry->tuple.dip[0] == dip
			&& qos_entry->tuple.proto == proto
			&& qos_entry->tuple.sp == sp
			&& qos_entry->tuple.dp == dp)
		{
			if(qos_entry == qos_table[hash])
			{
				qos_table[hash] = qos_entry->next;
			}
			else
			{
				prev->next = qos_entry->next;
			}
			break;
		}
		prev = qos_entry;
		qos_entry = qos_entry->next;
	}
	spin_unlock_bh(&qtable_lock);
#ifndef DEBUG
	qos_table_free_entry(qos_entry);
#else
	printk("qos_table_delete: %s %08x:%u->%08x:%u\n",
		(proto == IPPROTO_TCP) ? "tcp" : "udp", ntohl(sip), ntohs(sp), ntohl(dip), ntohs(dp));
	qos_table_dump_entry("qos_table_delete", qos_entry);
	qos_table_free_entry(qos_entry);
	qos_table_dump(NULL);
#endif
}


static void qos_table_delete_all()
{
	uint32 hash;
	ctf_qos_t * qos_entry ;
	ctf_qos_t * next ;

	spin_lock_bh(&qtable_lock);
	for(hash = 0; hash < QOS_TABLE_SZ; hash ++)
	{
		qos_entry = qos_table[hash];
		while(qos_entry != NULL)
		{
			next = qos_entry->next;
#ifndef DEBUG
			qos_table_free_entry(qos_entry);
#else
			qos_table_dump_entry("qos_table_delete", qos_entry);
			qos_table_free_entry(qos_entry);
#endif
			qos_entry = next;
		}
	}
	memset(qos_table, 0, sizeof(qos_table));
	spin_unlock_bh(&qtable_lock);
}

static void qos_table_delete_ip_range(uint32 begin, uint32 end)
{
	uint32 hash;
	ctf_qos_t * prev ;
	ctf_qos_t * next ;
	ctf_qos_t * qos_entry ;
	uint32 sip;
	//uint32 dip;

	spin_lock_bh(&qtable_lock);
	for(hash = 0; hash < QOS_TABLE_SZ; hash ++)
	{
		qos_entry = qos_table[hash];
		while(qos_entry != NULL)
		{
			next = qos_entry->next;
			sip = ntohl(qos_entry->tuple.sip[0]);
			//dip = ntohl(qos_entry->tuple.dip[0]);
			if((sip >= begin && sip <= end)/* || (dip >= begin && dip <= end)*/)
			{
				if(qos_entry == qos_table[hash])
				{
					qos_table[hash] = next;
				}
				else
				{
					prev->next = next;
				}
#ifndef DEBUG
				qos_table_free_entry(qos_entry);
#else
				qos_table_dump_entry("qos_table_delete", qos_entry);
				qos_table_free_entry(qos_entry);
#endif
			}
			else
			{
				prev = qos_entry;
			}
			qos_entry = next;
		}
	}
	spin_unlock_bh(&qtable_lock);

#ifdef DEBUG
	qos_table_dump(NULL);
#endif
}

static void qos_table_delete_port_range(u_int16_t begin, u_int16_t end)
{
	uint32 hash;
	ctf_qos_t * prev ;
	ctf_qos_t * next ;
	ctf_qos_t * qos_entry ;
	u_int16_t sp;
	u_int16_t dp;

	spin_lock_bh(&qtable_lock);
	for(hash = 0; hash < QOS_TABLE_SZ; hash ++)
	{
		qos_entry = qos_table[hash];
		while(qos_entry != NULL)
		{
			next = qos_entry->next;
			sp = ntohs(qos_entry->tuple.sp);
			dp = ntohs(qos_entry->tuple.dp);
			if(/*(sp >= begin && sp <= end) || */(dp >= begin && dp <= end))
			{
				if(qos_entry == qos_table[hash])
				{
					qos_table[hash] = next;
				}
				else
				{
					prev->next = next;
				}
#ifndef DEBUG
				qos_table_free_entry(qos_entry);
#else
				qos_table_dump_entry("qos_table_delete", qos_entry);
				qos_table_free_entry(qos_entry);
#endif
			}
			else
			{
				prev = qos_entry;
			}
			qos_entry = next;
		}
	}
	spin_unlock_bh(&qtable_lock);

#ifdef DEBUG
	qos_table_dump(NULL);
#endif
}

static void qos_table_delete_mac(unsigned char * mac)
{
	uint32 hash;
	ctf_qos_t * prev ;
	ctf_qos_t * next ;
	ctf_qos_t * qos_entry ;

	if(mac == NULL)
	{
		return;
	}
	spin_lock_bh(&qtable_lock);
	for(hash = 0; hash < QOS_TABLE_SZ; hash ++)
	{
		qos_entry = qos_table[hash];
		while(qos_entry != NULL)
		{
			next = qos_entry->next;
			if(!memcmp(qos_entry->smac, mac, ETH_ALEN))
			{
				if(qos_entry == qos_table[hash])
				{
					qos_table[hash] = next;
				}
				else
				{
					prev->next = next;
				}
#ifndef DEBUG
				qos_table_free_entry(qos_entry);
#else
				qos_table_dump_entry("qos_table_delete", qos_entry);
				qos_table_free_entry(qos_entry);
#endif
			}
			else
			{
				prev = qos_entry;
			}
			qos_entry = next;
		}
	}
	spin_unlock_bh(&qtable_lock);

#ifdef DEBUG
	qos_table_dump(NULL);
#endif
}

/* IPV4 and IPV6 common */
#define IP_VER_OFFSET		0x0	/* offset to version field */
#define IP_VER_MASK		0xf0	/* version mask */
#define IP_VER_SHIFT		4	/* version shift */
#define IP_VER_4		4	/* version number for IPV4 */
#define IP_VER_6		6	/* version number for IPV6 */

#define IP_VER(ip_body) \
	((((unsigned char *)(ip_body))[IP_VER_OFFSET] & IP_VER_MASK) >> IP_VER_SHIFT)

int set_qos_info(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	ctf_qos_t * qos_entry;
         u_int16_t diffs[2];
#ifdef HNDCTF
	int i;
#endif

	iph = ip_hdr(skb);
	if(iph == NULL)
	{
		return -1;
	}
	
	if(IP_VER(iph) != IP_VER_4)
	{
		return -1;
	}
	
#ifdef HNDCTF
	if(ip_mask_num == 0)
	{
		return 0;
	}
	for(i = 0; i < ip_mask_num; i ++)
	{
		if(((iph->saddr & lan_ip_masks[i].mask) == (lan_ip_masks[i].ip & lan_ip_masks[i].mask)) 
			&& ((iph->saddr & lan_ip_masks[i].mask) == (iph->daddr & lan_ip_masks[i].mask)))
		{
			//LAN forward
			return 0;
		}
	}
#endif
	
	/* Gather fragments. */
	if (iph->frag_off & htons(IP_OFFSET))
	{
		return -1;
	}

	if (iph->protocol != IPPROTO_UDP
	    && iph->protocol != IPPROTO_TCP)
	{
		return -1;
	}

	tcph = ((struct tcphdr *)(((__u8 *)iph) + (iph->ihl << 2)));

	qos_entry = qos_table_get(iph->saddr, iph->daddr, iph->protocol, tcph->source, tcph->dest);
	if(qos_entry == NULL)
	{
		return -1;
	}
		
#ifdef MTU_CONTROL
	if(qos_entry->mtu != ETH_DATA_LEN)
	{
		if (iph->protocol == IPPROTO_TCP)
		{
			//if(skb->tail - skb->network_header > qos_entry->mtu)
			{
				//return 1;
			}
		}
		else if (iph->protocol == IPPROTO_UDP)
		{
			if((skb->len - (skb->network_header - skb->data)) > qos_entry->mtu)
			{
				return -1;
			}
		}
	}
#endif
		 
#ifdef REFRESH_CT_TIMER
    if(qos_entry->ct != NULL)
    {
        if (iph->protocol == IPPROTO_TCP)
        {
            nf_ct_refresh(qos_entry->ct, skb, nf_ct_tcp_timeout_established);
        }
        else if (iph->protocol == IPPROTO_UDP)
        {
            nf_ct_refresh(qos_entry->ct, skb, nf_ct_udp_timeout_stream);
        }
    }
#endif
 
#ifndef CTF_QOS_MARK_ONLY
	 if(iph->tos != qos_entry->tos)
	 {
	         diffs[0] = htons(iph->tos) ^ 0xFFFF;
	         iph->tos = qos_entry->tos;
	         diffs[1] = htons(iph->tos);
	         iph->check = csum_fold(csum_partial((char *)diffs,
	                                             sizeof(diffs),
	                                             iph->check^0xFFFF));
	  }
#endif	  
	  skb->priority = qos_entry->priority;
	  skb->mark = qos_entry->mark;
	return 0;	
}

EXPORT_SYMBOL(set_qos_info);

//Zhijian add for fast nat or hndctf 2010-07-06
static u_int16_t slow_nat_ports[SLOW_NAT_PROTO_MAX][256] = {
	{(u_int16_t)__constant_htons(80),(u_int16_t)__constant_htons(443),0,},
	{(u_int16_t)__constant_htons(53),0,}
};

bool is_slow_nat_port(SLOW_NAT_PROTO proto, u_int16_t port)
{
	int i;
	switch(proto)
	{
		case SLOW_NAT_PROTO_TCP:
		case SLOW_NAT_PROTO_UDP:
			for(i = 0; slow_nat_ports[proto][i] != 0; i ++)
			{
				if(slow_nat_ports[proto][i] == port)
				{
					return TRUE;
				}
			}
			break;
	}
	return FALSE;
}

#ifdef DEBUG
//Zhijian add for hndctf debug 2010-09-03	
void print_pkt_info(struct nf_conn *ct,
	    enum ip_conntrack_info ctinfo,
	    unsigned int hooknum,
	    struct sk_buff *skb)
{
	struct nf_conntrack_tuple *orig, *repl;
	struct iphdr *iph;
	struct tcphdr *th;


	printk("_________________PKT_________________\n");

	orig = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	repl = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;
	printk("[TUP] %d %x:%u->%x:%u\n",
	       orig->dst.protonum, htonl(orig->src.u3.ip), htons(orig->src.u.tcp.port), 
	       htonl(orig->dst.u3.ip), htons(orig->dst.u.tcp.port));
	printk("[TUP] %d %x:%u->%x:%u\n",
	       repl->dst.protonum, htonl(repl->dst.u3.ip), htons(repl->dst.u.tcp.port),
	       htonl(repl->src.u3.ip), htons(repl->src.u.tcp.port));
	iph = ip_hdr(skb);
	th = (struct tcphdr *)((unsigned char *)iph + (iph->ihl * 4));
	printk("[SKB] %d %x:%u->%x:%u\n",
	       iph->protocol, htonl(iph->saddr), htons(th->source),
	       htonl(iph->daddr), htons(th->dest));
	printk("[FLG] slow_nat: %d\n", ct->slow_nat);
	printk("____________________________________\n");
}
#endif /* DEBUG */
#endif /* CONFIG_BCM_NAT || HNDCTF */

#ifdef HNDCTF
//Zhijian add for hndctf 2010-08-26
u_int32_t filter_loopback_ip = 0;

int ip_conntrack_vlan_fast_path = 0;
//Zhijian add for hndctf 2010-07-27	

#define DEF_IPC_ENTRY_MAX	4000
u_int32_t ipc_entry_max = DEF_IPC_ENTRY_MAX;

//Zhijian add for new ctf api 2010-11-02	
static inline int ipc_entry_is_full()
{
	return (ctf_ipc_count_get(kcih) >= ipc_entry_max);
}

int32 ipc_entry_cnt_get(void)
{
	return ctf_ipc_count_get(kcih);
}

bool
ip_conntrack_is_ipc_allowed(struct sk_buff *skb, u_int32_t hooknum)
{
	struct net_device *dev;

	if (!CTF_ENAB(kcih))
		return FALSE;

	// (2011-09-27) sync E4200's IPv6 CTF code
	if(ipc_entry_is_full()) {
		printk("%s: ipc_entry_is_full\n", __FUNCTION__);
		return FALSE;
	}

	if (hooknum == NF_IP_PRE_ROUTING || hooknum == NF_IP_POST_ROUTING) {
		dev = skb->dev;
		if (dev->priv_flags & IFF_802_1Q_VLAN)
			dev = VLAN_DEV_INFO(dev)->real_dev;

		/* Add ipc entry if packet is received on ctf enabled interface
		 * and the packet is not a defrag'd one.
		 */
		if (ctf_isenabled(kcih, dev) && (skb->len <= dev->mtu))
			skb->nfcache |= NFC_CTF_ENABLED;
	}

	/* Add the cache entries only if the device has registered and
	 * enabled ctf.
	 */
	if (skb->nfcache & NFC_CTF_ENABLED)
		return TRUE;

	return FALSE;
}

static inline int ip_skb_dst_mtu(struct sk_buff *skb)
{
	struct inet_sock *inet = skb->sk ? inet_sk(skb->sk) : NULL;

	return (inet && inet->pmtudisc == IP_PMTUDISC_PROBE) ?
	       skb->dst->dev->mtu : dst_mtu(skb->dst);
}

void
ip_conntrack_ipct_add(struct sk_buff *skb, u_int32_t hooknum,
                      struct nf_conn *ct, enum ip_conntrack_info ci,
                      struct nf_conntrack_tuple *manip)
{
	ctf_ipc_t ipc_entry;
	struct hh_cache *hh;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct rtable *rt;
	struct nf_conn_help *help;
	enum ip_conntrack_dir dir;
	uint8 ipver, protocol;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	struct ipv6hdr *ip6h = NULL;
#endif /* CONFIG_IPV6 */

	if ((skb == NULL) || (ct == NULL))
		return;

	/* Check CTF enabled */
	if (!ip_conntrack_is_ipc_allowed(skb, hooknum))
		return;

	/* We only add cache entires for non-helper connections and at
	 * pre or post routing hooks.
	 */
	help = nfct_help(ct);
	if ((help && help->helper) || (ct->ctf_flags & CTF_FLAGS_EXCLUDED) ||
	    ((hooknum != NF_IP_PRE_ROUTING) && (hooknum != NF_IP_POST_ROUTING)))
		return;

	iph = ip_hdr(skb);
	ipver = iph->version;
	
	/* Support both IPv4 and IPv6 */
	if (ipver == 4) {
		protocol = iph->protocol;
	}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (ipver == 6) {
		ip6h = (struct ipv6hdr *)iph;
		protocol = ip6h->nexthdr;
	}
#endif /* CONFIG_IPV6 */
	else
		return;

	/* Only TCP and UDP are supported */
	if (protocol == IPPROTO_TCP) {
		/* Add ipc entries for connections in established state only */
		if ((ci != IP_CT_ESTABLISHED) && (ci != (IP_CT_ESTABLISHED+IP_CT_IS_REPLY)))
			return;

    if (ct->proto.tcp.state >= TCP_CONNTRACK_FIN_WAIT &&
    	ct->proto.tcp.state <= TCP_CONNTRACK_TIME_WAIT)
			return;
	}
	else if (protocol != IPPROTO_UDP)
		return;

	dir = CTINFO2DIR(ci);
	if (ct->ctf_flags & (1 << dir))
		return;

	/* Do route lookup for alias address if we are doing DNAT in this
	 * direction.
	 */
	if (skb->dst == NULL) {
		/* Find the destination interface */
		if (IPVERSION_IS_4(ipver)) {
			u_int32_t daddr;

			if ((manip != NULL) && (HOOK2MANIP(hooknum) == IP_NAT_MANIP_DST))
				daddr = manip->dst.u3.ip;
			else
				daddr = iph->daddr;
			ip_route_input(skb, daddr, iph->saddr, iph->tos, skb->dev);
		}
		else
			ip6_route_input(skb);
	}

	/* Ensure the packet belongs to a forwarding connection and it is
	 * destined to an unicast address.
	 */
	rt = (struct rtable *)skb->dst;
	if ((rt == NULL) ||
	    (IPVERSION_IS_4(ipver) ? 
	    	((rt->u.dst.input != ip_forward) || (rt->rt_type != RTN_UNICAST)) :
	    	((rt->u.dst.input != ip6_forward) || !(ipv6_addr_type(&ip6h->daddr) & IPV6_ADDR_UNICAST))) ||
	    (rt->u.dst.neighbour == NULL) ||
	    ((rt->u.dst.neighbour->nud_state &
	     (NUD_PERMANENT|NUD_REACHABLE|NUD_STALE|NUD_DELAY|NUD_PROBE)) == 0))
		return;

	memset(&ipc_entry, 0, sizeof(ipc_entry));

	/* Init the neighboring sender address */
	memcpy(ipc_entry.sa.octet, eth_hdr(skb)->h_source, ETH_ALEN);

	/* If the packet is received on a bridge device then save
	 * the bridge cache entry pointer in the ip cache entry.
	 * This will be referenced in the data path to update the
	 * live counter of brc entry whenever a received packet
	 * matches corresponding ipc entry matches.
	 */
	if ((skb->dev != NULL) && ctf_isbridge(kcih, skb->dev))
		ipc_entry.brcp = ctf_brc_lkup(kcih, eth_hdr(skb)->h_source);

	hh = skb->dst->hh;
	if (hh != NULL) {
		eth = (struct ethhdr *)(((unsigned char *)hh->hh_data) + 2);
		memcpy(ipc_entry.dhost.octet, eth->h_dest, ETH_ALEN);
		memcpy(ipc_entry.shost.octet, eth->h_source, ETH_ALEN);
	} else {
		memcpy(ipc_entry.dhost.octet, rt->u.dst.neighbour->ha, ETH_ALEN);
		memcpy(ipc_entry.shost.octet, skb->dst->dev->dev_addr, ETH_ALEN);
	}

	/* Add ctf ipc entry for this direction */
	if (IPVERSION_IS_4(ipver)) {
		tcph = ((struct tcphdr *)(((__u8 *)iph) + (iph->ihl << 2)));
		ipc_entry.tuple.sip[0] = iph->saddr;
		ipc_entry.tuple.dip[0] = iph->daddr;
	}	else {
		tcph = (struct tcphdr *)&ip6h[1];
		memcpy(ipc_entry.tuple.sip, &ip6h->saddr, sizeof(ipc_entry.tuple.sip));
		memcpy(ipc_entry.tuple.dip, &ip6h->daddr, sizeof(ipc_entry.tuple.dip));
	}
	ipc_entry.tuple.proto = protocol;
	ipc_entry.tuple.sp = tcph->source;
	ipc_entry.tuple.dp = tcph->dest;

	ipc_entry.next = NULL;

	/* For vlan interfaces fill the vlan id and the tag/untag actions */
	if (ip_conntrack_vlan_fast_path && (skb->dst->dev->priv_flags & IFF_802_1Q_VLAN)) {
		ipc_entry.txif = (void *)(VLAN_DEV_INFO(skb->dst->dev)->real_dev);
		ipc_entry.vid = VLAN_DEV_INFO(skb->dst->dev)->vlan_id;
		ipc_entry.action = ((VLAN_DEV_INFO(skb->dst->dev)->flags & 1) ?
		                    CTF_ACTION_TAG : CTF_ACTION_UNTAG);
	} else {
		ipc_entry.txif = skb->dst->dev;
		ipc_entry.action = CTF_ACTION_UNTAG;
	}

	/* Update the manip ip and port */
	if (manip != NULL) {
		if (HOOK2MANIP(hooknum) == IP_NAT_MANIP_SRC) {
			ipc_entry.nat.ip = manip->src.u3.ip;
			ipc_entry.nat.port = manip->src.u.tcp.port;
			ipc_entry.action |= CTF_ACTION_SNAT;
		} else {
			ipc_entry.nat.ip = manip->dst.u3.ip;
			ipc_entry.nat.port = manip->dst.u.tcp.port;
			ipc_entry.action |= CTF_ACTION_DNAT;
		}
	}

	/* Do bridge cache lookup to determine outgoing interface
	 * and any vlan tagging actions if needed.
	 */
	if (ctf_isbridge(kcih, ipc_entry.txif)) {
		ctf_brc_t *brcp;

		brcp = ctf_brc_lkup(kcih, ipc_entry.dhost.octet);

		if (brcp == NULL)
			return;
		else {
			ipc_entry.action |= brcp->action;
			ipc_entry.txif = brcp->txifp;
			ipc_entry.vid = brcp->vid;
		}
	}

#if defined(DEBUG)
	if (IPVERSION_IS_4(ipver))
		printk("%s: Adding ipc entry for [%d]%u.%u.%u.%u:%u - %u.%u.%u.%u:%u\n", __FUNCTION__,
			ipc_entry.tuple.proto, 
			NIPQUAD(ipc_entry.tuple.sip[0]), ntohs(ipc_entry.tuple.sp), 
			NIPQUAD(ipc_entry.tuple.dip[0]), ntohs(ipc_entry.tuple.dp));
	else
		printk("\n%s: Adding ipc entry for [%d]\n"
			"%08x.%08x.%08x.%08x:%u => %08x.%08x.%08x.%08x:%u\n",
			__FUNCTION__, ipc_entry.tuple.proto,
			ntohl(ipc_entry.tuple.sip[0]), ntohl(ipc_entry.tuple.sip[1]),
			ntohl(ipc_entry.tuple.sip[2]), ntohl(ipc_entry.tuple.sip[3]),
			ntohs(ipc_entry.tuple.sp),
			ntohl(ipc_entry.tuple.dip[0]), ntohl(ipc_entry.tuple.dip[1]),
			ntohl(ipc_entry.tuple.dip[2]), ntohl(ipc_entry.tuple.dip[3]),
			ntohs(ipc_entry.tuple.dp));
	printk("sa %02x:%02x:%02x:%02x:%02x:%02x\n",
			ipc_entry.shost.octet[0], ipc_entry.shost.octet[1],
			ipc_entry.shost.octet[2], ipc_entry.shost.octet[3],
			ipc_entry.shost.octet[4], ipc_entry.shost.octet[5]);
	printk("da %02x:%02x:%02x:%02x:%02x:%02x\n",
			ipc_entry.dhost.octet[0], ipc_entry.dhost.octet[1],
			ipc_entry.dhost.octet[2], ipc_entry.dhost.octet[3],
			ipc_entry.dhost.octet[4], ipc_entry.dhost.octet[5]);
	printk("[%d] vid: %d action %x\n", hooknum, ipc_entry.vid, ipc_entry.action);
	if (manip != NULL)
		printk("manip_ip: %u.%u.%u.%u manip_port %u\n",
			NIPQUAD(ipc_entry.nat.ip), ntohs(ipc_entry.nat.port));
	printk("txif: %s\n", ((struct net_device *)ipc_entry.txif)->name);
#endif

	ctf_ipc_add(kcih, &ipc_entry);

	// (2011-09-27) Zhijian add for hndctf 2010-07-27
	if (IPVERSION_IS_4(ipver))
	{
		qos_table_add(
		    &ipc_entry.tuple
		    , iph->tos
		    , skb->priority
		    , skb->mark
		    , ipc_entry.sa.octet
#ifdef REFRESH_CT_TIMER
		    , ct
#endif
#ifdef MTU_CONTROL
		    , ip_skb_dst_mtu(skb)
#endif
		);
	}

	/* Update the attributes flag to indicate a CTF conn */
	ct->ctf_flags |= (CTF_FLAGS_CACHED | (1 << dir));

}

int
ip_conntrack_ipct_delete(struct nf_conn *ct, int ct_timeout)
{
	ctf_ipc_t *ipct;
	struct nf_conntrack_tuple *orig, *repl;

	if (!CTF_ENAB(kcih))
		return (0);

	orig = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;

	if ((orig->dst.protonum != IPPROTO_TCP) && (orig->dst.protonum != IPPROTO_UDP))
		return (0);

	repl = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;

	/* If the refresh counter of ipc entry is non zero, it indicates
	 * that the packet transfer is active and we should not delete
	 * the conntrack entry.
	 */
	if (ct_timeout) {
		ipct = ctf_ipc_lkup(kcih, &orig->src.u3.ip, &orig->dst.u3.ip,
		                    orig->dst.protonum, orig->src.u.tcp.port,
		                    orig->dst.u.tcp.port);

		/* Postpone the deletion of ct entry if there are frames
		 * flowing in this direction.
		 */
		if ((ipct != NULL) && (ipct->live > 0)) {
			ipct->live = 0;
			//2011-09-22 fix issue CD-router item 99: Verify NAT TCP session timeout for established session (Jemmy)
			ct->timeout.expires = /*jiffies +*/ ct->expire_jiffies;
			add_timer(&ct->timeout);
			return (-1);
		}

		ipct = ctf_ipc_lkup(kcih, &repl->src.u3.ip, &repl->dst.u3.ip,
		                    repl->dst.protonum, repl->src.u.tcp.port,
		                    repl->dst.u.tcp.port);

		if ((ipct != NULL) && (ipct->live > 0)) {
			ipct->live = 0;
			//2011-09-22 fix issue CD-router item 99: Verify NAT TCP session timeout for established session (Jemmy)
			ct->timeout.expires = /*jiffies +*/ ct->expire_jiffies;
			add_timer(&ct->timeout);
			return (-1);
		}
	}

	/* If there are no packets over this connection for timeout period
	 * delete the entries.
	 */
	ctf_ipc_delete(kcih, &orig->src.u3.ip, &orig->dst.u3.ip, orig->dst.protonum,
	               orig->src.u.tcp.port, orig->dst.u.tcp.port);

	ctf_ipc_delete(kcih, &repl->src.u3.ip, &repl->dst.u3.ip, repl->dst.protonum,
	               repl->src.u.tcp.port, repl->dst.u.tcp.port);

	// (2011-09-27) Zhijian add for hndctf 2010-07-29
	qos_table_delete(orig->src.u3.ip, orig->dst.u3.ip, orig->dst.protonum,
		orig->src.u.tcp.port, orig->dst.u.tcp.port);

	qos_table_delete(repl->src.u3.ip, repl->dst.u3.ip, repl->dst.protonum,
		repl->src.u.tcp.port, repl->dst.u.tcp.port);
#ifdef DEBUG
	printk("%s: Deleting the tuple %x %x %d %d %d\n",
	       __FUNCTION__, orig->src.u3.ip, orig->dst.u3.ip, orig->dst.protonum,
	       orig->src.u.tcp.port, orig->dst.u.tcp.port);
	printk("%s: Deleting the tuple %x %x %d %d %d\n",
	       __FUNCTION__, repl->dst.u3.ip, repl->src.u3.ip, repl->dst.protonum,
	       repl->dst.u.tcp.port, repl->src.u.tcp.port);
#endif

	return (0);
}

//Zhijian add for hndctf 2010-08-26
//#define TIME_FILTER_WORKAROUND_DEL_ALL
#ifdef TIME_FILTER_WORKAROUND_DEL_ALL
void ctf_ipc_delete_all(void)
{
	int i;
	struct list_head *head, *temp_head;
	struct nf_conntrack_tuple_hash *tuple_hash;
	struct nf_conn  *ct = NULL;
#if 1 //Zhijian add for hndctf debug 2010-09-03	
	struct nf_conntrack_tuple *orig, *repl;


	printk("ctf_ipc_delete_all\n");
#endif
	read_lock_bh(&nf_conntrack_lock);
	for (i = 0; i < nf_conntrack_htable_size; i++) 
	{
		head = &nf_conntrack_hash[i];
		if(head == NULL)
		{
			continue;
		}
		temp_head = head;
		while(1) 
		{	
			temp_head = temp_head->next;				
			if(temp_head == head) 
			{			
				head = NULL;			
				temp_head = NULL;
				break;			
			}
			tuple_hash = (struct nf_conntrack_tuple_hash *)temp_head;
			ct = (struct nf_conn *)nf_ct_tuplehash_to_ctrack(tuple_hash);
 			if(ct == NULL)
			{
				continue;
			}
#if 1 //Zhijian add for hndctf debug 2010-09-03	
			orig = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
			repl = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;
			printk("[DEL] %d %x:%u->%x:%u\n",
			       orig->dst.protonum, htonl(orig->src.u3.ip), htons(orig->src.u.tcp.port), 
			       htonl(orig->dst.u3.ip), htons(orig->dst.u.tcp.port));
			printk("[DEL] %d %x:%u->%x:%u\n",
			       repl->dst.protonum, htonl(repl->dst.u3.ip), htons(repl->dst.u.tcp.port),
			       htonl(repl->src.u3.ip), htons(repl->src.u.tcp.port));
#endif
			ip_conntrack_ipct_delete(ct, 0);
		}					
	}
	read_unlock_bh(&nf_conntrack_lock);
}


#else
//Zhijian add for new ctf api 2010-11-02	
void ctf_ipc_delete_all(void)
{
	ctf_ipc_t ipcm;

	printk("<1>ctf_ipc_delete_all\n");
	memset(&ipcm, 0, sizeof(ipcm));
	ctf_ipc_delete_multi(kcih, &ipcm, &ipcm);
	qos_table_delete_all();
}

#define IS_HEX(c) (((c) >= '0' && (c) <= '9') || ((c) >= 'A' && (c) <= 'F') || ((c) >= 'a' && (c) <= 'f'))
#define IS_COMMA(c) ((c) == ':')
#define IS_SPACE(c) ((c) == ' ' || (c) == '\t')
#define IS_VALID_MAC(c) (IS_HEX((c)) || IS_COMMA((c)))
#define HEX_VAL(c) (((c) >= '0' && (c) <= '9') ? ((c) - '0') : (((c) >= 'A' && (c) <= 'F') ? ((c) - 'A' + 10) : (((c) >= 'a' && (c) <= 'f') ? ((c) - 'a' + 10) : -1)))
static int ParseMacAddr(const char * buffer, unsigned char * mac)
{
	int i;
	int j;
	int n;
	int val;
	
	if(buffer == NULL || mac == NULL)
	{
		return 0;
	}
	//printk("<1>ParseMacAddr [%s]\n", buffer);
	while(IS_SPACE(*buffer))
	{
		buffer ++;
	}
	if(buffer[0] == '\0' || IS_COMMA(buffer[0]) || !IS_HEX(buffer[0]))
	{
		return 0;
	}
	i = 0;
	j = 0;
	n = 0;
	while(*buffer)
	{
		if(IS_HEX(*buffer))
		{
			if(j >= ETH_ALEN || n > 1)
			{
				return 0;
			}
			val = HEX_VAL(*buffer);
			if(val < 0)
			{
				return 0;
			}
			if(n == 0)
			{
				mac[j] = (unsigned char)((val & 0x0F) << 4);
				n ++;
			}
			else
			{
				mac[j] |= (unsigned char)(val & 0x0F);
				n ++;
				j ++;
			}
		}
		else if(IS_COMMA(*buffer))
		{
			if(i >= ETH_ALEN || n == 0)
			{
				return 0;
			}
			i ++;
			n = 0;
		}
		else if(IS_SPACE(*buffer))
		{
			if(i != (ETH_ALEN - 1) || n == 0)
			{
				return 0;
			}
			break;
		}
		else
		{
			printk("<1>Parse mac addr error: unkown char [%s]\n", buffer);
			return 0;
		}
		buffer ++;
	}
	i ++;
	return i;
}

void ctf_ipc_delete_by_ip_range(uint32 begin, uint32 end)
{
	ctf_ipc_t ipcm;
	ctf_ipc_t ipcm_end;
	
	if(begin == 0 && end == 0)
	{
		return;
	}
	memset(&ipcm, 0, sizeof(ipcm));
	//printk("<1>try delete: source ip range [%08x - %08x]\n", begin, end);
	if(begin == end)
	{
		ipcm.tuple.sip[0] = htonl(begin);
		ipcm.nat.ip = 0;
		ctf_ipc_delete_multi(kcih, &ipcm, &ipcm);
		ipcm.nat.ip = ipcm.tuple.sip[0];
		ipcm.tuple.sip[0] = 0;
		ctf_ipc_delete_multi(kcih, &ipcm, &ipcm);
	}
	else
	{
		memset(&ipcm_end, 0, sizeof(ipcm_end));
		ipcm.tuple.sip[0] = htonl(begin);
		ipcm.nat.ip = 0;
		ipcm_end.tuple.sip[0] = htonl(end);
		ipcm_end.nat.ip = 0;
		ctf_ipc_delete_range(kcih, &ipcm, &ipcm_end);
		ipcm.nat.ip = ipcm.tuple.sip[0];
		ipcm.tuple.sip[0] = 0;
		ipcm_end.nat.ip = ipcm_end.tuple.sip[0];
		ipcm_end.tuple.sip[0] = 0;
		ctf_ipc_delete_range(kcih, &ipcm, &ipcm_end);
	}
	qos_table_delete_ip_range(begin, end);
}

void ctf_ipc_delete_by_mac(const char * mac)
{
	ctf_ipc_t ipcm;
	
	memset(&ipcm, 0, sizeof(ipcm));
	if(ParseMacAddr(mac, ipcm.sa.octet) == ETH_ALEN)
	{
		//printk("<1>try delete: source mac [%02x:%02x:%02x:%02x:%02x:%02x]\n",
		//	ipcm.sa.octet[0], ipcm.sa.octet[1], ipcm.sa.octet[2], ipcm.sa.octet[3], ipcm.sa.octet[4], ipcm.sa.octet[5]);
		ctf_ipc_delete_multi(kcih, &ipcm, &ipcm);
		qos_table_delete_mac(ipcm.sa.octet);
	}
}
#endif /* TIME_FILTER_WORKAROUND_DEL_ALL */

void ctf_ipc_delete_by_port_range(u_int16_t begin, u_int16_t end)
{
	ctf_ipc_t ipcm;
	ctf_ipc_t ipcm_end;
	
	if(begin == 0 && end == 0)
	{
		return;
	}
	memset(&ipcm, 0, sizeof(ipcm));
	if(begin == end)
	{
		ipcm.tuple.dp = htons(begin);
		ipcm.nat.port = 0;
		ctf_ipc_delete_multi(kcih, &ipcm, &ipcm);
		ipcm.nat.port = ipcm.tuple.dp;
		ipcm.tuple.dp = 0;
		ctf_ipc_delete_multi(kcih, &ipcm, &ipcm);
	}
	else
	{
		memset(&ipcm_end, 0, sizeof(ipcm_end));
		ipcm.tuple.dp = htons(begin);
		ipcm.nat.port = 0;
		ipcm_end.tuple.dp = htons(end);
		ipcm_end.nat.port = 0;
		ctf_ipc_delete_range(kcih, &ipcm, &ipcm_end);
		ipcm.nat.port = ipcm.tuple.dp;
		ipcm.tuple.dp = 0;
		ipcm_end.nat.port = ipcm_end.tuple.dp;
		ipcm_end.tuple.dp = 0;
		ctf_ipc_delete_range(kcih, &ipcm, &ipcm_end);
	}
	qos_table_delete_port_range(begin, end);
}

#include <linux/inetdevice.h>
#define LOOP_BACK_IP __constant_htonl(0x7F000001)
#define LOOP_BACK_MASK __constant_htonl(0xFF000000)

#if 1 //Zhijian add for hndctf debug 2010-09-03	
static void print_ip_masks(void)
{
	int i = 0;

	printk("wan ip %08x\n", ntohl(filter_loopback_ip));
	for(i = 0; i < ip_mask_num; i++)
	{
		printk("lan_interface[%d]: ip %08x  mask %08x\n", i, ntohl(lan_ip_masks[i].ip), ntohl(lan_ip_masks[i].mask));
	}
}
#endif

static void get_lan_ip_masks(u32 wanip)
{
	struct net_device *dev;
	struct in_device *indev;

	read_lock(&dev_base_lock);
	ip_mask_num = 0;
	for_each_netdev(dev)
	{
		if(ip_mask_num >= IP_MASK_MAX)
		{
			break;
		}
		indev = in_dev_get(dev);
		if(indev != NULL)
		{
			if(indev->ifa_list != NULL)
			{
				if(indev->ifa_list->ifa_local != 0)
				{
					if(!(((indev->ifa_list->ifa_local & LOOP_BACK_MASK) == (LOOP_BACK_IP & LOOP_BACK_MASK))
						|| (indev->ifa_list->ifa_local == wanip)))
					{
						lan_ip_masks[ip_mask_num].ip = indev->ifa_list->ifa_local;
						lan_ip_masks[ip_mask_num].mask = indev->ifa_list->ifa_mask;
						ip_mask_num ++;
					}
				}
			}
			in_dev_put(indev);
		}
	}
	read_unlock(&dev_base_lock);
#if 1
	print_ip_masks();
#endif
}

int is_lan_ip(u_int32_t ip)
{
	int i = 0;

	for(i = 0; i < ip_mask_num; i++)
	{
		if((ip & lan_ip_masks[i].mask) == (lan_ip_masks[i].ip & lan_ip_masks[i].mask))
		{
			//printk("is_lan_ip[%d]: ip %08x  mask %08x\n", i, ntohl(lan_ip_masks[i].ip), ntohl(lan_ip_masks[i].mask));
			return 1;
		}
	}

	return 0;
}

void set_filter_loopback_ip(u_int32_t ip)
{
	filter_loopback_ip = ip;
	get_lan_ip_masks(filter_loopback_ip);
}

int ctf_bypass = 0;
EXPORT_SYMBOL(ctf_bypass);
void ctf_forward_enable(int enable)
{
	ctf_bypass = enable ? 0 : 1;
	printk("ctf_bypass = %d\n", ctf_bypass);	
}

#if 1 //Zhijian add for hndctf debug 2010-09-03
#define	NAME_SZ	8		/* 8 char names */

#define BRC_SZ	32
#define IPC_SZ	128
#define bcm_bprintf(b, arg ...) printk("<4>" arg)

typedef spinlock_t ctf_lock_t;

typedef struct ctf_dev	ctf_dev_t;

typedef struct ctf_dev_list {
	ctf_dev_t	*head;		/* Pointer to head */
	ctf_lock_t	*lock;		/* Lock for devices list */
} ctf_dev_list_t;

typedef struct ctf_info {
	ctf_t		ctf;		/* Public structure */
	osl_t		*osh;		/* OS handle */
	ctf_brc_t	**brc;		/* Bridge cache table */
	ctf_lock_t	*brc_lock;	/* Lock for bridge cache */
	ctf_ipc_t	**ipc;		/* IP connection cache table */
	ctf_lock_t	*ipc_lock;	/* Lock for ip conn cache */
	ctf_dev_list_t	*dev_list;	/* List of CTF enabled devices */
	uint32		*msg_level;	/* Message level pointer */
	uint8		name[NAME_SZ];	/* Callers name for diag msgs */
} ctf_info_t;

/* Device specific information */
struct ctf_dev {
	ctf_dev_t	*next;		/* Pointer to next entry */
	void		*dev;		/* Device identifier/pointer */
	bool		enabled;	/* CTF enable/disable status */
	bool		is_br;		/* True if device is bridge */
};


#define	CTF_BRC_LOCK(ci)	spin_lock_bh(((ctf_info_t *)(ci))->brc_lock)
#define	CTF_IPC_LOCK(ci)	spin_lock_bh(((ctf_info_t *)(ci))->ipc_lock)
#define	CTF_BRC_UNLOCK(ci)	spin_unlock_bh(((ctf_info_t *)(ci))->brc_lock)
#define	CTF_IPC_UNLOCK(ci)	spin_unlock_bh(((ctf_info_t *)(ci))->ipc_lock)
#define	CTF_DEV_LIST_LOCK(ci)	spin_lock_bh(((ctf_info_t *)(ci))->dev_list->lock)
#define	CTF_DEV_LIST_UNLOCK(ci)	spin_unlock_bh(((ctf_info_t *)(ci))->dev_list->lock)

#define DEV_IFNAME(dev)		(((struct net_device *)dev)->name)

#define	CTF_OSH(ci)	((ctf_info_t *)(ci))->osh
#define	CTF_MSGLVL(ci)	((ctf_info_t *)(ci))->msg_level
#define	CTF_BRCP(ci)	((ctf_info_t *)(ci))->brc
#define	CTF_IPCP(ci)	((ctf_info_t *)(ci))->ipc
#define	CTF_DEV_LIST_HEAD(ci)	((ctf_info_t *)(ci))->dev_list->head

#define NTOH32	ntohl
#define NTOH16	ntohs

static void _ctf_dump(ctf_t *ci, struct bcmstrbuf *b)
{
	int32 i;
	ctf_ipc_t *ipcp;
	ctf_brc_t *brcp;
	char eabuf[ETHER_ADDR_STR_LEN];
#ifdef CTFPOOL
	osl_t *osh;
#endif /* CTFPOOL */
	uint32 total;

	ASSERT((ci != NULL) && (b != NULL));

	if(ci == NULL)
	{
		printk("%s: ERROR CTF module not found,  kcih = NULL\n", __FUNCTION__);
		return;
	}

	bcm_bprintf(b, "IP connection cache:\n");
	bcm_bprintf(b, "Proto\tSrcIP\t\tSrcPort\t\tDestIP\t\tDstPort\t\tLive\t\tNatInfo\n");

	CTF_IPC_LOCK(ci);
	for (i = 0, total = 0; i < IPC_SZ; i++) {
		ipcp = CTF_IPCP(ci)[i];
		while (ipcp != NULL) {
			bcm_bprintf(b, "%s\t\t%08x\t% 5u\t\t%08x\t% 5u\t\t%u\t\t%08x:%u\n",
			            ((ipcp->tuple.proto == 6) ? "tcp" : "udp"),
			            NTOH32(ipcp->tuple.sip[0]), NTOH16(ipcp->tuple.sp), 
			            NTOH32(ipcp->tuple.dip[0]), NTOH16(ipcp->tuple.dp),
			            ipcp->live,
			            NTOH32(ipcp->nat.ip), NTOH16(ipcp->nat.port));
			total ++;
			ipcp = ipcp->next;
		}
	}
	CTF_IPC_UNLOCK(ci);
	bcm_bprintf(b, "Total %u IP connections\n", total);

	bcm_bprintf(b, "\nBridge cache:\n");
	bcm_bprintf(b, "MacAddr\t\t\tInterface\tLive\n");

	CTF_BRC_LOCK(ci);
	for (i = 0; i < BRC_SZ; i++) {
		brcp = CTF_BRCP(ci)[i];
		while (brcp != NULL) {
			bcm_bprintf(b, "%s\t\t%s\t\t%d\n",
			            bcm_ether_ntoa(&brcp->dhost, eabuf),
			            DEV_IFNAME(brcp->txifp),
			            brcp->live);
			brcp = brcp->next;
		}
	}
	CTF_BRC_UNLOCK(ci);

#ifdef CTFPOOL
	osh = CTF_OSH(ci);
	if (osh != NULL) {
		bcm_bprintf(b, "\nFast pool stats:\n");
		osl_ctfpool_stats(osh, b);
		bcm_bprintf(b, "\n");
	}
#endif /* CTFPOOL */
	qos_table_dump(NULL);
	print_ip_masks();
}

void CtfDump(void)
{
	//ctf_dump(kcih, NULL);
	_ctf_dump(kcih, NULL);
}
#endif
#endif /* HNDCTF */

#ifdef CONFIG_BCM_NAT
#define	BCM_FASTNAT_DENY	1
extern int ipv4_conntrack_fastnat;
extern struct nf_conntrack_l3proto nf_conntrack_l3proto_ipv4;

typedef int (*bcmNatBindHook)(struct nf_conn *ct,enum ip_conntrack_info ctinfo,
	    						struct sk_buff **pskb, struct nf_conntrack_l4proto *l4proto);
static bcmNatBindHook bcm_nat_bind_hook = NULL;
int bcm_nat_bind_hook_func(bcmNatBindHook hook_func) {
	bcm_nat_bind_hook = hook_func;
	return 1;
};

typedef int (*bcmNatHitHook)(struct sk_buff *skb);
bcmNatHitHook bcm_nat_hit_hook = NULL;
int bcm_nat_hit_hook_func(bcmNatHitHook hook_func) {
	bcm_nat_hit_hook = hook_func;
	return 1;
};
#endif /* CONFIG_BCM_NAT */

/*
 * This scheme offers various size of "struct nf_conn" dependent on
 * features(helper, nat, ...)
 */

#define NF_CT_FEATURES_NAMELEN	256
static struct {
	/* name of slab cache. printed in /proc/slabinfo */
	char *name;

	/* size of slab cache */
	size_t size;

	/* slab cache pointer */
	struct kmem_cache *cachep;

	/* allocated slab cache + modules which uses this slab cache */
	int use;

} nf_ct_cache[NF_CT_F_NUM];

/* protect members of nf_ct_cache except of "use" */
DEFINE_RWLOCK(nf_ct_cache_lock);

/* This avoids calling kmem_cache_create() with same name simultaneously */
static DEFINE_MUTEX(nf_ct_cache_mutex);

static int nf_conntrack_hash_rnd_initted;
static unsigned int nf_conntrack_hash_rnd;

static u_int32_t __hash_conntrack(const struct nf_conntrack_tuple *tuple,
				  unsigned int size, unsigned int rnd)
{
#ifdef CONFIG_BCM_NAT
	if (tuple->src.l3num == PF_INET && tuple->dst.protonum == PF_INET) {
		/* ntohl because more differences in low bits. */
		/* To ensure that halves of the same connection don't hash
		   clash, we add the source per-proto again. */
		return (ntohl(tuple->src.u3.ip + tuple->dst.u3.ip
			     + tuple->src.u.all + tuple->dst.u.all
			     + tuple->dst.protonum)
			+ ntohs(tuple->src.u.all))
			% nf_conntrack_htable_size;
	} else
#endif
	{
		unsigned int a, b;
	
		a = jhash2(tuple->src.u3.all, ARRAY_SIZE(tuple->src.u3.all),
			   (tuple->src.l3num << 16) | tuple->dst.protonum);
		b = jhash2(tuple->dst.u3.all, ARRAY_SIZE(tuple->dst.u3.all),
			   (tuple->src.u.all << 16) | tuple->dst.u.all);
	
		return jhash_2words(a, b, rnd) % size;
	}
}

static inline u_int32_t hash_conntrack(const struct nf_conntrack_tuple *tuple)
{
	return __hash_conntrack(tuple, nf_conntrack_htable_size,
				nf_conntrack_hash_rnd);
}

int nf_conntrack_register_cache(u_int32_t features, const char *name,
				size_t size)
{
	int ret = 0;
	char *cache_name;
	struct kmem_cache *cachep;

	DEBUGP("nf_conntrack_register_cache: features=0x%x, name=%s, size=%d\n",
	       features, name, size);

	if (features < NF_CT_F_BASIC || features >= NF_CT_F_NUM) {
		DEBUGP("nf_conntrack_register_cache: invalid features.: 0x%x\n",
			features);
		return -EINVAL;
	}

	mutex_lock(&nf_ct_cache_mutex);

	write_lock_bh(&nf_ct_cache_lock);
	/* e.g: multiple helpers are loaded */
	if (nf_ct_cache[features].use > 0) {
		DEBUGP("nf_conntrack_register_cache: already resisterd.\n");
		if ((!strncmp(nf_ct_cache[features].name, name,
			      NF_CT_FEATURES_NAMELEN))
		    && nf_ct_cache[features].size == size) {
			DEBUGP("nf_conntrack_register_cache: reusing.\n");
			nf_ct_cache[features].use++;
			ret = 0;
		} else
			ret = -EBUSY;

		write_unlock_bh(&nf_ct_cache_lock);
		mutex_unlock(&nf_ct_cache_mutex);
		return ret;
	}
	write_unlock_bh(&nf_ct_cache_lock);

	/*
	 * The memory space for name of slab cache must be alive until
	 * cache is destroyed.
	 */
	cache_name = kmalloc(sizeof(char)*NF_CT_FEATURES_NAMELEN, GFP_ATOMIC);
	if (cache_name == NULL) {
		DEBUGP("nf_conntrack_register_cache: can't alloc cache_name\n");
		ret = -ENOMEM;
		goto out_up_mutex;
	}

	if (strlcpy(cache_name, name, NF_CT_FEATURES_NAMELEN)
						>= NF_CT_FEATURES_NAMELEN) {
		printk("nf_conntrack_register_cache: name too long\n");
		ret = -EINVAL;
		goto out_free_name;
	}

	cachep = kmem_cache_create(cache_name, size, 0, 0,
				   NULL, NULL);
	if (!cachep) {
		printk("nf_conntrack_register_cache: Can't create slab cache "
		       "for the features = 0x%x\n", features);
		ret = -ENOMEM;
		goto out_free_name;
	}

	write_lock_bh(&nf_ct_cache_lock);
	nf_ct_cache[features].use = 1;
	nf_ct_cache[features].size = size;
	nf_ct_cache[features].cachep = cachep;
	nf_ct_cache[features].name = cache_name;
	write_unlock_bh(&nf_ct_cache_lock);

	goto out_up_mutex;

out_free_name:
	kfree(cache_name);
out_up_mutex:
	mutex_unlock(&nf_ct_cache_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(nf_conntrack_register_cache);

void nf_conntrack_unregister_cache(u_int32_t features)
{
	struct kmem_cache *cachep;
	char *name;

	/*
	 * This assures that kmem_cache_create() isn't called before destroying
	 * slab cache.
	 */
	DEBUGP("nf_conntrack_unregister_cache: 0x%04x\n", features);
	mutex_lock(&nf_ct_cache_mutex);

	write_lock_bh(&nf_ct_cache_lock);
	if (--nf_ct_cache[features].use > 0) {
		write_unlock_bh(&nf_ct_cache_lock);
		mutex_unlock(&nf_ct_cache_mutex);
		return;
	}
	cachep = nf_ct_cache[features].cachep;
	name = nf_ct_cache[features].name;
	nf_ct_cache[features].cachep = NULL;
	nf_ct_cache[features].name = NULL;
	nf_ct_cache[features].size = 0;
	write_unlock_bh(&nf_ct_cache_lock);

	synchronize_net();

	kmem_cache_destroy(cachep);
	kfree(name);

	mutex_unlock(&nf_ct_cache_mutex);
}
EXPORT_SYMBOL_GPL(nf_conntrack_unregister_cache);

int
nf_ct_get_tuple(const struct sk_buff *skb,
		unsigned int nhoff,
		unsigned int dataoff,
		u_int16_t l3num,
		u_int8_t protonum,
		struct nf_conntrack_tuple *tuple,
		const struct nf_conntrack_l3proto *l3proto,
		const struct nf_conntrack_l4proto *l4proto)
{
	NF_CT_TUPLE_U_BLANK(tuple);

	tuple->src.l3num = l3num;
	if (l3proto->pkt_to_tuple(skb, nhoff, tuple) == 0)
		return 0;

	tuple->dst.protonum = protonum;
	tuple->dst.dir = IP_CT_DIR_ORIGINAL;

	return l4proto->pkt_to_tuple(skb, dataoff, tuple);
}
EXPORT_SYMBOL_GPL(nf_ct_get_tuple);

#ifdef CONFIG_BCM_NAT
static int
ipv4_ct_get_tuple(const struct sk_buff *skb,
		unsigned int nhoff,
		unsigned int dataoff,
		u_int8_t protonum,
		struct nf_conntrack_tuple *tuple,
		const struct nf_conntrack_l4proto *l4proto)
{
	const struct iphdr *iph = ip_hdr(skb);

	tuple->src.u.all = tuple->dst.u.all = 0;
	tuple->src.u3.all[0]
	= tuple->src.u3.all[1]
	= tuple->src.u3.all[2]
	= tuple->src.u3.all[3]
	= 0;
	tuple->dst.u3.all[0]
	= tuple->dst.u3.all[1]
	= tuple->dst.u3.all[2]
	= tuple->dst.u3.all[3]
	= 0;
	
	tuple->src.l3num = PF_INET;
	tuple->src.u3.ip = iph->saddr;
	tuple->dst.u3.ip = iph->daddr;
	tuple->dst.protonum = protonum;
	tuple->dst.dir = IP_CT_DIR_ORIGINAL;

	return l4proto->pkt_to_tuple(skb, dataoff, tuple);
}
#endif /* CONFIG_BCM_NAT */

int
nf_ct_invert_tuple(struct nf_conntrack_tuple *inverse,
		   const struct nf_conntrack_tuple *orig,
		   const struct nf_conntrack_l3proto *l3proto,
		   const struct nf_conntrack_l4proto *l4proto)
{
#ifdef CONFIG_BCM_NAT
	if (inverse->src.l3num == PF_INET && inverse->dst.protonum == PF_INET){
		inverse->src.u.all = inverse->dst.u.all = 0;
		inverse->src.u3.all[0]
		= inverse->src.u3.all[1]
		= inverse->src.u3.all[2]
		= inverse->src.u3.all[3]
		= 0;
		inverse->dst.u3.all[0]
		= inverse->dst.u3.all[1]
		= inverse->dst.u3.all[2]
		= inverse->dst.u3.all[3]
		= 0;
		inverse->src.u3.ip = orig->dst.u3.ip;
		inverse->dst.u3.ip = orig->src.u3.ip;
	} else
#endif
	{
		NF_CT_TUPLE_U_BLANK(inverse);

		if (l3proto->invert_tuple(inverse, orig) == 0)
			return 0;
	}
	inverse->src.l3num = orig->src.l3num;
	inverse->dst.dir = !orig->dst.dir;

	inverse->dst.protonum = orig->dst.protonum;
	return l4proto->invert_tuple(inverse, orig);
}
EXPORT_SYMBOL_GPL(nf_ct_invert_tuple);

static void
clean_from_lists(struct nf_conn *ct)
{
	DEBUGP("clean_from_lists(%p)\n", ct);
	list_del(&ct->tuplehash[IP_CT_DIR_ORIGINAL].list);
	list_del(&ct->tuplehash[IP_CT_DIR_REPLY].list);

	/* Destroy all pending expectations */
	nf_ct_remove_expectations(ct);
}

static void
destroy_conntrack(struct nf_conntrack *nfct)
{
	struct nf_conn *ct = (struct nf_conn *)nfct;
	struct nf_conntrack_l4proto *l4proto;
	typeof(nf_conntrack_destroyed) destroyed;

	DEBUGP("destroy_conntrack(%p)\n", ct);
	NF_CT_ASSERT(atomic_read(&nfct->use) == 0);
	NF_CT_ASSERT(!timer_pending(&ct->timeout));

#ifdef HNDCTF
	ip_conntrack_ipct_delete(ct, 0);
#endif /* HNDCTF*/

	nf_conntrack_event(IPCT_DESTROY, ct);
	set_bit(IPS_DYING_BIT, &ct->status);

	/* To make sure we don't get any weird locking issues here:
	 * destroy_conntrack() MUST NOT be called with a write lock
	 * to nf_conntrack_lock!!! -HW */
	rcu_read_lock();
	l4proto = __nf_ct_l4proto_find(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.l3num,
				       ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.protonum);
	if (l4proto && l4proto->destroy)
		l4proto->destroy(ct);

	destroyed = rcu_dereference(nf_conntrack_destroyed);
	if (destroyed)
		destroyed(ct);

	rcu_read_unlock();

	write_lock_bh(&nf_conntrack_lock);
	/* Expectations will have been removed in clean_from_lists,
	 * except TFTP can create an expectation on the first packet,
	 * before connection is in the list, so we need to clean here,
	 * too. */
	nf_ct_remove_expectations(ct);

	#if defined(CONFIG_NETFILTER_XT_MATCH_LAYER7) || defined(CONFIG_NETFILTER_XT_MATCH_LAYER7_MODULE)
	if(ct->layer7.app_proto)
		kfree(ct->layer7.app_proto);
	if(ct->layer7.app_data)
	kfree(ct->layer7.app_data);
	#endif


	/* We overload first tuple to link into unconfirmed list. */
	if (!nf_ct_is_confirmed(ct)) {
		BUG_ON(list_empty(&ct->tuplehash[IP_CT_DIR_ORIGINAL].list));
		list_del(&ct->tuplehash[IP_CT_DIR_ORIGINAL].list);
	}

	NF_CT_STAT_INC(delete);
	write_unlock_bh(&nf_conntrack_lock);

	if (ct->master)
		nf_ct_put(ct->master);

	DEBUGP("destroy_conntrack: returning ct=%p to slab\n", ct);
	nf_conntrack_free(ct);
}

static void death_by_timeout(unsigned long ul_conntrack)
{
	struct nf_conn *ct = (void *)ul_conntrack;
	struct nf_conn_help *help = nfct_help(ct);
	struct nf_conntrack_helper *helper;

#ifdef HNDCTF
	/* If negative error is returned it means the entry hasn't
	 * timed out yet.
	 */
	if (ip_conntrack_ipct_delete(ct, jiffies >= ct->timeout.expires ? 1 : 0) != 0)
		return;
#endif /* HNDCTF */

	if (help) {
		rcu_read_lock();
		helper = rcu_dereference(help->helper);
		if (helper && helper->destroy)
			helper->destroy(ct);
		rcu_read_unlock();
	}

	write_lock_bh(&nf_conntrack_lock);
	/* Inside lock so preempt is disabled on module removal path.
	 * Otherwise we can get spurious warnings. */
	NF_CT_STAT_INC(delete_list);
	clean_from_lists(ct);
	write_unlock_bh(&nf_conntrack_lock);
	nf_ct_put(ct);
}

struct nf_conntrack_tuple_hash *
__nf_conntrack_find(const struct nf_conntrack_tuple *tuple,
		    const struct nf_conn *ignored_conntrack)
{
	struct nf_conntrack_tuple_hash *h;
	unsigned int hash = hash_conntrack(tuple);

	list_for_each_entry(h, &nf_conntrack_hash[hash], list) {
		if (nf_ct_tuplehash_to_ctrack(h) != ignored_conntrack &&
		    nf_ct_tuple_equal(tuple, &h->tuple)) {
			NF_CT_STAT_INC(found);
			return h;
		}
		NF_CT_STAT_INC(searched);
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(__nf_conntrack_find);

/* Find a connection corresponding to a tuple. */
struct nf_conntrack_tuple_hash *
nf_conntrack_find_get(const struct nf_conntrack_tuple *tuple,
		      const struct nf_conn *ignored_conntrack)
{
	struct nf_conntrack_tuple_hash *h;

	read_lock_bh(&nf_conntrack_lock);
	h = __nf_conntrack_find(tuple, ignored_conntrack);
	if (h)
		atomic_inc(&nf_ct_tuplehash_to_ctrack(h)->ct_general.use);
	read_unlock_bh(&nf_conntrack_lock);

	return h;
}
EXPORT_SYMBOL_GPL(nf_conntrack_find_get);

static void __nf_conntrack_hash_insert(struct nf_conn *ct,
				       unsigned int hash,
				       unsigned int repl_hash)
{
	ct->id = ++nf_conntrack_next_id;
	list_add(&ct->tuplehash[IP_CT_DIR_ORIGINAL].list,
		 &nf_conntrack_hash[hash]);
	list_add(&ct->tuplehash[IP_CT_DIR_REPLY].list,
		 &nf_conntrack_hash[repl_hash]);
}

void nf_conntrack_hash_insert(struct nf_conn *ct)
{
	unsigned int hash, repl_hash;

	hash = hash_conntrack(&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
	repl_hash = hash_conntrack(&ct->tuplehash[IP_CT_DIR_REPLY].tuple);

	write_lock_bh(&nf_conntrack_lock);
	__nf_conntrack_hash_insert(ct, hash, repl_hash);
	write_unlock_bh(&nf_conntrack_lock);
}
EXPORT_SYMBOL_GPL(nf_conntrack_hash_insert);

/* Confirm a connection given skb; places it in hash table */
int
__nf_conntrack_confirm(struct sk_buff **pskb)
{
	unsigned int hash, repl_hash;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;
	struct nf_conn_help *help;
	enum ip_conntrack_info ctinfo;

	ct = nf_ct_get(*pskb, &ctinfo);

	/* ipt_REJECT uses nf_conntrack_attach to attach related
	   ICMP/TCP RST packets in other direction.  Actual packet
	   which created connection will be IP_CT_NEW or for an
	   expected connection, IP_CT_RELATED. */
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL)
		return NF_ACCEPT;

	hash = hash_conntrack(&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
	repl_hash = hash_conntrack(&ct->tuplehash[IP_CT_DIR_REPLY].tuple);

	/* We're not in hash table, and we refuse to set up related
	   connections for unconfirmed conns.  But packet copies and
	   REJECT will give spurious warnings here. */
	/* NF_CT_ASSERT(atomic_read(&ct->ct_general.use) == 1); */

	/* No external references means noone else could have
	   confirmed us. */
	NF_CT_ASSERT(!nf_ct_is_confirmed(ct));
	DEBUGP("Confirming conntrack %p\n", ct);

	write_lock_bh(&nf_conntrack_lock);

	/* See if there's one in the list already, including reverse:
	   NAT could have grabbed it without realizing, since we're
	   not in the hash.  If there is, we lost race. */
	list_for_each_entry(h, &nf_conntrack_hash[hash], list)
		if (nf_ct_tuple_equal(&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple,
				      &h->tuple))
			goto out;
	list_for_each_entry(h, &nf_conntrack_hash[repl_hash], list)
		if (nf_ct_tuple_equal(&ct->tuplehash[IP_CT_DIR_REPLY].tuple,
					  &h->tuple))
			goto out;

	/* Remove from unconfirmed list */
	list_del(&ct->tuplehash[IP_CT_DIR_ORIGINAL].list);

	__nf_conntrack_hash_insert(ct, hash, repl_hash);
	/* Timer relative to confirmation time, not original
	   setting time, otherwise we'd get timer wrap in
	   weird delay cases. */
	ct->timeout.expires += jiffies;
	add_timer(&ct->timeout);
	atomic_inc(&ct->ct_general.use);
	set_bit(IPS_CONFIRMED_BIT, &ct->status);
	NF_CT_STAT_INC(insert);
	write_unlock_bh(&nf_conntrack_lock);
	help = nfct_help(ct);
	if (help && help->helper)
		nf_conntrack_event_cache(IPCT_HELPER, *pskb);
#ifdef CONFIG_NF_NAT_NEEDED
	if (test_bit(IPS_SRC_NAT_DONE_BIT, &ct->status) ||
	    test_bit(IPS_DST_NAT_DONE_BIT, &ct->status))
		nf_conntrack_event_cache(IPCT_NATINFO, *pskb);
#endif
	nf_conntrack_event_cache(master_ct(ct) ?
				 IPCT_RELATED : IPCT_NEW, *pskb);
	return NF_ACCEPT;

out:
	NF_CT_STAT_INC(insert_failed);
	write_unlock_bh(&nf_conntrack_lock);
	return NF_DROP;
}
EXPORT_SYMBOL_GPL(__nf_conntrack_confirm);

/* Returns true if a connection correspondings to the tuple (required
   for NAT). */
int
nf_conntrack_tuple_taken(const struct nf_conntrack_tuple *tuple,
			 const struct nf_conn *ignored_conntrack)
{
	struct nf_conntrack_tuple_hash *h;

	read_lock_bh(&nf_conntrack_lock);
	h = __nf_conntrack_find(tuple, ignored_conntrack);
	read_unlock_bh(&nf_conntrack_lock);

	return h != NULL;
}
EXPORT_SYMBOL_GPL(nf_conntrack_tuple_taken);

/* There's a small race here where we may free a just-assured
   connection.  Too bad: we're in trouble anyway. */
static int early_drop(struct list_head *chain)
{
	/* Traverse backwards: gives us oldest, which is roughly LRU */
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct = NULL, *tmp;
	int dropped = 0;

	read_lock_bh(&nf_conntrack_lock);
	list_for_each_entry_reverse(h, chain, list) {
		tmp = nf_ct_tuplehash_to_ctrack(h);
		if (!test_bit(IPS_ASSURED_BIT, &tmp->status)) {
			ct = tmp;
			atomic_inc(&ct->ct_general.use);
			break;
		}
	}
	read_unlock_bh(&nf_conntrack_lock);

	if (!ct)
		return dropped;

#ifdef HNDCTF
	ip_conntrack_ipct_delete(ct, 0);
#endif /* HNDCTF */

	if (del_timer(&ct->timeout)) {
		death_by_timeout((unsigned long)ct);
		dropped = 1;
		NF_CT_STAT_INC_ATOMIC(early_drop);
	}
	nf_ct_put(ct);
	return dropped;
}

static struct nf_conn *
__nf_conntrack_alloc(const struct nf_conntrack_tuple *orig,
		     const struct nf_conntrack_tuple *repl,
		     const struct nf_conntrack_l3proto *l3proto,
		     u_int32_t features)
{
	struct nf_conn *conntrack = NULL;
	struct nf_conntrack_helper *helper;

	if (unlikely(!nf_conntrack_hash_rnd_initted)) {
		get_random_bytes(&nf_conntrack_hash_rnd, 4);
		nf_conntrack_hash_rnd_initted = 1;
	}

	/* We don't want any race condition at early drop stage */
	atomic_inc(&nf_conntrack_count);

	if (nf_conntrack_max
	    && atomic_read(&nf_conntrack_count) > nf_conntrack_max) {
		unsigned int hash = hash_conntrack(orig);
		/* Try dropping from this hash chain. */
		if (!early_drop(&nf_conntrack_hash[hash])) {
			atomic_dec(&nf_conntrack_count);
			if (net_ratelimit())
				printk(KERN_WARNING
				       "nf_conntrack: table full, dropping"
				       " packet.\n");
			return ERR_PTR(-ENOMEM);
		}
	}

	/*  find features needed by this conntrack. */
	features |= l3proto->get_features(orig);

	read_lock_bh(&nf_conntrack_lock);
	helper = __nf_ct_helper_find(repl);
	/* NAT might want to assign a helper later */
	if (helper || features & NF_CT_F_NAT)
		features |= NF_CT_F_HELP;
	read_unlock_bh(&nf_conntrack_lock);

	DEBUGP("nf_conntrack_alloc: features=0x%x\n", features);

	read_lock_bh(&nf_ct_cache_lock);

	if (unlikely(!nf_ct_cache[features].use)) {
		DEBUGP("nf_conntrack_alloc: not supported features = 0x%x\n",
			features);
		goto out;
	}

	conntrack = kmem_cache_alloc(nf_ct_cache[features].cachep, GFP_ATOMIC);
	if (conntrack == NULL) {
		DEBUGP("nf_conntrack_alloc: Can't alloc conntrack from cache\n");
		goto out;
	}

	memset(conntrack, 0, nf_ct_cache[features].size);
	conntrack->features = features;
	atomic_set(&conntrack->ct_general.use, 1);
	conntrack->tuplehash[IP_CT_DIR_ORIGINAL].tuple = *orig;
	conntrack->tuplehash[IP_CT_DIR_REPLY].tuple = *repl;
	/* Don't set timer yet: wait for confirmation */
	setup_timer(&conntrack->timeout, death_by_timeout,
		    (unsigned long)conntrack);
	read_unlock_bh(&nf_ct_cache_lock);

	return conntrack;
out:
	read_unlock_bh(&nf_ct_cache_lock);
	atomic_dec(&nf_conntrack_count);
	return conntrack;
}

struct nf_conn *nf_conntrack_alloc(const struct nf_conntrack_tuple *orig,
				   const struct nf_conntrack_tuple *repl)
{
	struct nf_conntrack_l3proto *l3proto;
	struct nf_conn *ct;

	rcu_read_lock();
	l3proto = __nf_ct_l3proto_find(orig->src.l3num);
	ct = __nf_conntrack_alloc(orig, repl, l3proto, 0);
	rcu_read_unlock();

	return ct;
}
EXPORT_SYMBOL_GPL(nf_conntrack_alloc);

void nf_conntrack_free(struct nf_conn *conntrack)
{
	u_int32_t features = conntrack->features;
	NF_CT_ASSERT(features >= NF_CT_F_BASIC && features < NF_CT_F_NUM);
	DEBUGP("nf_conntrack_free: features = 0x%x, conntrack=%p\n", features,
	       conntrack);
	kmem_cache_free(nf_ct_cache[features].cachep, conntrack);
	atomic_dec(&nf_conntrack_count);
}
EXPORT_SYMBOL_GPL(nf_conntrack_free);

void del_selected_conntrack(struct nf_conntrack_tuple_hash *h)
{
	struct nf_conn *ct;
	unsigned long extra_jiffies = 1 * HZ;

	DEBUGP("%s: \n", __FUNCTION__);
	if (h)
	{		
		ct = nf_ct_tuplehash_to_ctrack(h);
		NF_CT_ASSERT(ct->timeout.data == (unsigned long)ct);		

		/* If not in hash table, timer will not be active yet */
		if (!nf_ct_is_confirmed(ct)) {
			ct->timeout.expires = extra_jiffies;		
		}
		else
		{		
			if (del_timer(&ct->timeout))
			{
				ct->timeout.expires = jiffies + extra_jiffies;
				add_timer(&ct->timeout);
			}		
		}
		
	}
}

/* Allocate a new conntrack: we return -ENOMEM if classification
   failed due to stress.  Otherwise it really is unclassifiable. */
static struct nf_conntrack_tuple_hash *
init_conntrack(const struct nf_conntrack_tuple *tuple,
	       struct nf_conntrack_l3proto *l3proto,
	       struct nf_conntrack_l4proto *l4proto,
	       struct sk_buff *skb,
	       unsigned int dataoff)
{
	struct nf_conn *conntrack;
	struct nf_conn_help *help;
	struct nf_conntrack_tuple repl_tuple;
	struct nf_conntrack_expect *exp;
	u_int32_t features = 0;

	if (!nf_ct_invert_tuple(&repl_tuple, tuple, l3proto, l4proto)) {
		DEBUGP("Can't invert tuple.\n");
		return NULL;
	}

	read_lock_bh(&nf_conntrack_lock);
	exp = __nf_conntrack_expect_find(tuple);
	if (exp && exp->helper)
		features = NF_CT_F_HELP;
	read_unlock_bh(&nf_conntrack_lock);

	conntrack = __nf_conntrack_alloc(tuple, &repl_tuple, l3proto, features);
	if (conntrack == NULL || IS_ERR(conntrack)) {
		DEBUGP("Can't allocate conntrack.\n");
		return (struct nf_conntrack_tuple_hash *)conntrack;
	}

	if (!l4proto->new(conntrack, skb, dataoff)) {
		nf_conntrack_free(conntrack);
		DEBUGP("init conntrack: can't track with proto module\n");
		return NULL;
	}

	write_lock_bh(&nf_conntrack_lock);
	exp = find_expectation(tuple);

	help = nfct_help(conntrack);
	if (exp) {
		DEBUGP("conntrack: expectation arrives ct=%p exp=%p\n",
			conntrack, exp);
		/* Welcome, Mr. Bond.  We've been expecting you... */
		__set_bit(IPS_EXPECTED_BIT, &conntrack->status);
		conntrack->master = exp->master;
		if (exp->helper)
			rcu_assign_pointer(help->helper, exp->helper);
#ifdef CONFIG_NF_CONNTRACK_MARK
		conntrack->mark = exp->master->mark;
#endif
#ifdef CONFIG_NF_CONNTRACK_SECMARK
		conntrack->secmark = exp->master->secmark;
#endif
		nf_conntrack_get(&conntrack->master->ct_general);
		NF_CT_STAT_INC(expect_new);
	} else {
		if (help) {
			/* not in hash table yet, so not strictly necessary */
			rcu_assign_pointer(help->helper,
					   __nf_ct_helper_find(&repl_tuple));
		}
		NF_CT_STAT_INC(new);
	}

	/* Overload tuple linked list to put us in unconfirmed list. */
	list_add(&conntrack->tuplehash[IP_CT_DIR_ORIGINAL].list, &unconfirmed);

	write_unlock_bh(&nf_conntrack_lock);

	if (exp) {
		if (exp->expectfn)
			exp->expectfn(conntrack, exp);
		nf_conntrack_expect_put(exp);
	}

	return &conntrack->tuplehash[IP_CT_DIR_ORIGINAL];
}

/* On success, returns conntrack ptr, sets skb->nfct and ctinfo */
static inline struct nf_conn *
resolve_normal_ct(struct sk_buff *skb,
		  unsigned int dataoff,
		  u_int16_t l3num,
		  u_int8_t protonum,
		  struct nf_conntrack_l3proto *l3proto,
		  struct nf_conntrack_l4proto *l4proto,
		  int *set_reply,
		  enum ip_conntrack_info *ctinfo)
{
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;

	if (!nf_ct_get_tuple(skb, skb_network_offset(skb),
			     dataoff, l3num, protonum, &tuple, l3proto,
			     l4proto)) {
		DEBUGP("resolve_normal_ct: Can't get tuple\n");
		return NULL;
	}

	/* look for tuple match */
	h = nf_conntrack_find_get(&tuple, NULL);
	if (!h) {
		h = init_conntrack(&tuple, l3proto, l4proto, skb, dataoff);
		if (!h)
			return NULL;
		if (IS_ERR(h))
			return (void *)h;
	}
	ct = nf_ct_tuplehash_to_ctrack(h);

	/* It exists; we have (non-exclusive) reference. */
	if (NF_CT_DIRECTION(h) == IP_CT_DIR_REPLY) {
		*ctinfo = IP_CT_ESTABLISHED + IP_CT_IS_REPLY;
		/* Please set reply bit if this packet OK */
		*set_reply = 1;
	} else {
		/* Once we've had two way comms, always ESTABLISHED. */
		if (test_bit(IPS_SEEN_REPLY_BIT, &ct->status)) {
			DEBUGP("nf_conntrack_in: normal packet for %p\n", ct);
			*ctinfo = IP_CT_ESTABLISHED;
		} else if (test_bit(IPS_EXPECTED_BIT, &ct->status)) {
			DEBUGP("nf_conntrack_in: related packet for %p\n", ct);
			*ctinfo = IP_CT_RELATED;
		} else {
			DEBUGP("nf_conntrack_in: new packet for %p\n", ct);
			*ctinfo = IP_CT_NEW;
		}
		*set_reply = 0;
	}
	skb->nfct = &ct->ct_general;
	skb->nfctinfo = *ctinfo;
	return ct;
}

#ifdef CONFIG_BCM_NAT
static inline struct nf_conn *
ipv4_resolve_normal_ct(struct sk_buff *skb,
		  unsigned int dataoff,
		  u_int8_t protonum,
		  struct nf_conntrack_l4proto *l4proto,
		  int *set_reply,
		  enum ip_conntrack_info *ctinfo)
{
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;

	if (!ipv4_ct_get_tuple(skb, skb_network_offset(skb),
			     dataoff, protonum, &tuple, l4proto)) {
		DEBUGP("resolve_normal_ct: Can't get tuple\n");
		return NULL;
	}
	/* look for tuple match */
	h = nf_conntrack_find_get(&tuple, NULL);
	if (!h) {
		h = init_conntrack(&tuple, &nf_conntrack_l3proto_ipv4, l4proto, skb, dataoff);
		if (!h)
			return NULL;
		if (IS_ERR(h))
			return (void *)h;
	}
	ct = nf_ct_tuplehash_to_ctrack(h);

	/* It exists; we have (non-exclusive) reference. */
	if (NF_CT_DIRECTION(h) == IP_CT_DIR_REPLY) {
		*ctinfo = IP_CT_ESTABLISHED + IP_CT_IS_REPLY;
		/* Please set reply bit if this packet OK */
		*set_reply = 1;
	} else {
		/* Once we've had two way comms, always ESTABLISHED. */
		if (test_bit(IPS_SEEN_REPLY_BIT, &ct->status)) {
			DEBUGP("nf_conntrack_in: normal packet for %p\n", ct);
			*ctinfo = IP_CT_ESTABLISHED;
		} else if (test_bit(IPS_EXPECTED_BIT, &ct->status)) {
			DEBUGP("nf_conntrack_in: related packet for %p\n", ct);
			*ctinfo = IP_CT_RELATED;
		} else {
			DEBUGP("nf_conntrack_in: new packet for %p\n", ct);
			*ctinfo = IP_CT_NEW;
		}
		*set_reply = 0;
	}
	skb->nfct = &ct->ct_general;
	skb->nfctinfo = *ctinfo;
	return ct;
}
#endif /* CONFIG_BCM_NAT */

#if defined(CONFIG_BCM_NAT) || defined(HNDCTF)
//Zhijian add for fast nat or hndctf  2010-07-06
void force_slow_nat(struct sk_buff *pskb)
{
	struct nf_conn  *ct = NULL;
	if(pskb->nfct != NULL)
	{
		ct = (struct nf_conn *)pskb->nfct;
		if(!ct->slow_nat)
		{
			ct->slow_nat = 1;
		}
	}
}

#endif

unsigned int
nf_conntrack_in(int pf, unsigned int hooknum, struct sk_buff **pskb)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct nf_conntrack_l3proto *l3proto;
	struct nf_conntrack_l4proto *l4proto;
	unsigned int dataoff;
	u_int8_t protonum;
	int set_reply = 0;
	int ret;

	/* Previously seen (loopback or untracked)?  Ignore. */
	if ((*pskb)->nfct) {
		NF_CT_STAT_INC_ATOMIC(ignore);
		return NF_ACCEPT;
	}

	/* rcu_read_lock()ed by nf_hook_slow */
	l3proto = __nf_ct_l3proto_find((u_int16_t)pf);

	if ((ret = l3proto->prepare(pskb, hooknum, &dataoff, &protonum)) <= 0) {
		DEBUGP("not prepared to track yet or error occured\n");
		return -ret;
	}

	l4proto = __nf_ct_l4proto_find((u_int16_t)pf, protonum);

	/* It may be an special packet, error, unclean...
	 * inverse of the return code tells to the netfilter
	 * core what to do with the packet. */
	if (l4proto->error != NULL &&
	    (ret = l4proto->error(*pskb, dataoff, &ctinfo, pf, hooknum)) <= 0) {
		NF_CT_STAT_INC_ATOMIC(error);
		NF_CT_STAT_INC_ATOMIC(invalid);
		return -ret;
	}

	ct = resolve_normal_ct(*pskb, dataoff, pf, protonum, l3proto, l4proto,
			       &set_reply, &ctinfo);
	if (!ct) {
		/* Not valid part of a connection */
		NF_CT_STAT_INC_ATOMIC(invalid);
		return NF_ACCEPT;
	}

	if (IS_ERR(ct)) {
		/* Too stressed to deal. */
		NF_CT_STAT_INC_ATOMIC(drop);
		return NF_DROP;
	}

	NF_CT_ASSERT((*pskb)->nfct);

	ret = l4proto->packet(ct, *pskb, dataoff, ctinfo, pf, hooknum);
	if (ret < 0) {
		/* Invalid: inverse of the return code tells
		 * the netfilter core what to do */
		DEBUGP("nf_conntrack_in: Can't track with proto module\n");
		nf_conntrack_put((*pskb)->nfct);
		(*pskb)->nfct = NULL;
		NF_CT_STAT_INC_ATOMIC(invalid);
		return -ret;
	}

	if (set_reply && !test_and_set_bit(IPS_SEEN_REPLY_BIT, &ct->status))
		nf_conntrack_event_cache(IPCT_STATUS, *pskb);

	return ret;
}
EXPORT_SYMBOL_GPL(nf_conntrack_in);

#ifdef CONFIG_BCM_NAT
extern struct sk_buff * nf_ct_ipv4_gather_frags(struct sk_buff *skb, u_int32_t user);

unsigned int
ipv4_nf_conntrack_in(int pf, unsigned int hooknum, struct sk_buff **pskb)
{
	struct nf_conn *ct;
	struct nf_conn_nat *nat;
	enum ip_conntrack_info ctinfo;
	struct nf_conntrack_l3proto *l3proto;
	struct nf_conntrack_l4proto *l4proto;
	unsigned int dataoff;
	u_int8_t protonum;
	int set_reply = 0;
	int ret;
	struct nf_conn_help *help;

	/* Previously seen (loopback or untracked)?  Ignore. */
	if ((*pskb)->nfct) {
		NF_CT_STAT_INC_ATOMIC(ignore);
		return NF_ACCEPT;
	}

	/* rcu_read_lock()ed by nf_hook_slow */
	l3proto = &nf_conntrack_l3proto_ipv4;
	dataoff = skb_network_offset(*pskb) + ip_hdrlen(*pskb);
	protonum = ip_hdr(*pskb)->protocol;

	/* Gather fragments. */
	if (ip_hdr(*pskb)->frag_off & htons(IP_MF | IP_OFFSET)) {
		*pskb = nf_ct_ipv4_gather_frags(*pskb,
						hooknum == NF_IP_PRE_ROUTING ?
						IP_DEFRAG_CONNTRACK_IN :
						IP_DEFRAG_CONNTRACK_OUT);
		if (!*pskb)
			return NF_STOLEN;
	}
	
	l4proto = __nf_ct_l4proto_find((u_int16_t)pf, protonum);

	/* It may be an special packet, error, unclean...
	 * inverse of the return code tells to the netfilter
	 * core what to do with the packet. */

	if (l4proto->error != NULL &&
	    (ret = l4proto->error(*pskb, dataoff, &ctinfo, pf, hooknum)) <= 0) {
		NF_CT_STAT_INC_ATOMIC(error);
		NF_CT_STAT_INC_ATOMIC(invalid);
		return -ret;
	}
	ct = ipv4_resolve_normal_ct(*pskb, dataoff, protonum, l4proto,
			       &set_reply, &ctinfo);
	if (!ct) {
		/* Not valid part of a connection */
		NF_CT_STAT_INC_ATOMIC(invalid);
		return NF_ACCEPT;
	}

	if (IS_ERR(ct)) {
		/* Too stressed to deal. */
		NF_CT_STAT_INC_ATOMIC(drop);
		return NF_DROP;
	}

	NF_CT_ASSERT((*pskb)->nfct);

	ret = l4proto->packet(ct, *pskb, dataoff, ctinfo, pf, hooknum);
	if (ret < 0) {
		/* Invalid: inverse of the return code tells
		 * the netfilter core what to do */
		DEBUGP("nf_conntrack_in: Can't track with proto module\n");
		nf_conntrack_put((*pskb)->nfct);
		(*pskb)->nfct = NULL;
		NF_CT_STAT_INC_ATOMIC(invalid);
		return -ret;
	}

	help = nfct_help(ct);
	nat = nfct_nat(ct);
	if (ipv4_conntrack_fastnat && bcm_nat_bind_hook
		&& !(nat->info.nat_type & BCM_FASTNAT_DENY)
		&& !help->helper
		&& (ctinfo == IP_CT_ESTABLISHED || ctinfo == IP_CT_IS_REPLY)
		&& (hooknum == NF_IP_PRE_ROUTING) && 
		(protonum == IPPROTO_TCP || protonum == IPPROTO_UDP)) {

		struct nf_conntrack_tuple *t1, *t2;
		t1 = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
		t2 = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;
		if (!(t1->dst.u3.ip == t2->src.u3.ip &&
			t1->src.u3.ip == t2->dst.u3.ip &&
			t1->dst.u.all == t2->src.u.all &&
			t1->src.u.all == t2->dst.u.all)) {
			ret = bcm_nat_bind_hook(ct, ctinfo, pskb, l4proto);
		}
	}
	if (set_reply && !test_and_set_bit(IPS_SEEN_REPLY_BIT, &ct->status)) {
		if (hooknum == NF_IP_LOCAL_OUT)
			nat->info.nat_type |= BCM_FASTNAT_DENY;

		nf_conntrack_event_cache(IPCT_STATUS, *pskb);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(ipv4_nf_conntrack_in);
#endif /* CONFIG_BCM_NAT */

int nf_ct_invert_tuplepr(struct nf_conntrack_tuple *inverse,
			 const struct nf_conntrack_tuple *orig)
{
	int ret;

	rcu_read_lock();
	ret = nf_ct_invert_tuple(inverse, orig,
				 __nf_ct_l3proto_find(orig->src.l3num),
				 __nf_ct_l4proto_find(orig->src.l3num,
						      orig->dst.protonum));
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(nf_ct_invert_tuplepr);

/* Alter reply tuple (maybe alter helper).  This is for NAT, and is
   implicitly racy: see __nf_conntrack_confirm */
void nf_conntrack_alter_reply(struct nf_conn *ct,
			      const struct nf_conntrack_tuple *newreply)
{
	struct nf_conn_help *help = nfct_help(ct);

	write_lock_bh(&nf_conntrack_lock);
	/* Should be unconfirmed, so not in hash table yet */
	NF_CT_ASSERT(!nf_ct_is_confirmed(ct));

	DEBUGP("Altering reply tuple of %p to ", ct);
	NF_CT_DUMP_TUPLE(newreply);

	ct->tuplehash[IP_CT_DIR_REPLY].tuple = *newreply;
	if (!ct->master && help && help->expecting == 0) {
		struct nf_conntrack_helper *helper;
		helper = __nf_ct_helper_find(newreply);
		if (helper)
			memset(&help->help, 0, sizeof(help->help));
		/* not in hash table yet, so not strictly necessary */
		rcu_assign_pointer(help->helper, helper);
	}

	write_unlock_bh(&nf_conntrack_lock);
}
EXPORT_SYMBOL_GPL(nf_conntrack_alter_reply);

/* Refresh conntrack for this many jiffies and do accounting if do_acct is 1 */
void __nf_ct_refresh_acct(struct nf_conn *ct,
			  enum ip_conntrack_info ctinfo,
			  const struct sk_buff *skb,
			  unsigned long extra_jiffies,
			  int do_acct)
{
	int event = 0;

	NF_CT_ASSERT(ct->timeout.data == (unsigned long)ct);
	NF_CT_ASSERT(skb);

	write_lock_bh(&nf_conntrack_lock);

	/* Only update if this is not a fixed timeout */
	if (test_bit(IPS_FIXED_TIMEOUT_BIT, &ct->status)) {
		write_unlock_bh(&nf_conntrack_lock);
		return;
	}

	/* If not in hash table, timer will not be active yet */
	if (!nf_ct_is_confirmed(ct)) {
#ifdef HNDCTF
		ct->expire_jiffies = extra_jiffies;
#endif /* HNDCTF */
		ct->timeout.expires = extra_jiffies;
		event = IPCT_REFRESH;
	} else {
		unsigned long newtime = jiffies + extra_jiffies;

		/* Only update the timeout if the new timeout is at least
		   HZ jiffies from the old timeout. Need del_timer for race
		   avoidance (may already be dying). */
		if (newtime - ct->timeout.expires >= HZ
		    && del_timer(&ct->timeout)) {
#ifdef HNDCTF
			//ct->expire_jiffies = newtime;
			ct->expire_jiffies = extra_jiffies;
#endif /* HNDCTF */
			ct->timeout.expires = newtime;
			add_timer(&ct->timeout);
			event = IPCT_REFRESH;
		}
	}

#ifdef CONFIG_NF_CT_ACCT
	if (do_acct) {
		ct->counters[CTINFO2DIR(ctinfo)].packets++;
		ct->counters[CTINFO2DIR(ctinfo)].bytes +=
			skb->len - skb_network_offset(skb);

		if ((ct->counters[CTINFO2DIR(ctinfo)].packets & 0x80000000)
		    || (ct->counters[CTINFO2DIR(ctinfo)].bytes & 0x80000000))
			event |= IPCT_COUNTER_FILLING;
	}
#endif

	write_unlock_bh(&nf_conntrack_lock);

	/* must be unlocked when calling event cache */
	if (event)
		nf_conntrack_event_cache(event, skb);
}
EXPORT_SYMBOL_GPL(__nf_ct_refresh_acct);

#if defined(CONFIG_NF_CT_NETLINK) || defined(CONFIG_NF_CT_NETLINK_MODULE)

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/mutex.h>


/* Generic function for tcp/udp/sctp/dccp and alike. This needs to be
 * in ip_conntrack_core, since we don't want the protocols to autoload
 * or depend on ctnetlink */
int nf_ct_port_tuple_to_nfattr(struct sk_buff *skb,
			       const struct nf_conntrack_tuple *tuple)
{
	NFA_PUT(skb, CTA_PROTO_SRC_PORT, sizeof(u_int16_t),
		&tuple->src.u.tcp.port);
	NFA_PUT(skb, CTA_PROTO_DST_PORT, sizeof(u_int16_t),
		&tuple->dst.u.tcp.port);
	return 0;

nfattr_failure:
	return -1;
}
EXPORT_SYMBOL_GPL(nf_ct_port_tuple_to_nfattr);

static const size_t cta_min_proto[CTA_PROTO_MAX] = {
	[CTA_PROTO_SRC_PORT-1]  = sizeof(u_int16_t),
	[CTA_PROTO_DST_PORT-1]  = sizeof(u_int16_t)
};

int nf_ct_port_nfattr_to_tuple(struct nfattr *tb[],
			       struct nf_conntrack_tuple *t)
{
	if (!tb[CTA_PROTO_SRC_PORT-1] || !tb[CTA_PROTO_DST_PORT-1])
		return -EINVAL;

	if (nfattr_bad_size(tb, CTA_PROTO_MAX, cta_min_proto))
		return -EINVAL;

	t->src.u.tcp.port = *(__be16 *)NFA_DATA(tb[CTA_PROTO_SRC_PORT-1]);
	t->dst.u.tcp.port = *(__be16 *)NFA_DATA(tb[CTA_PROTO_DST_PORT-1]);

	return 0;
}
EXPORT_SYMBOL_GPL(nf_ct_port_nfattr_to_tuple);
#endif

/* Used by ipt_REJECT and ip6t_REJECT. */
void __nf_conntrack_attach(struct sk_buff *nskb, struct sk_buff *skb)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;

	/* This ICMP is in reverse direction to the packet which caused it */
	ct = nf_ct_get(skb, &ctinfo);
	if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL)
		ctinfo = IP_CT_RELATED + IP_CT_IS_REPLY;
	else
		ctinfo = IP_CT_RELATED;

	/* Attach to new skbuff, and increment count */
	nskb->nfct = &ct->ct_general;
	nskb->nfctinfo = ctinfo;
	nf_conntrack_get(nskb->nfct);
}
EXPORT_SYMBOL_GPL(__nf_conntrack_attach);

static inline int
do_iter(const struct nf_conntrack_tuple_hash *i,
	int (*iter)(struct nf_conn *i, void *data),
	void *data)
{
	return iter(nf_ct_tuplehash_to_ctrack(i), data);
}

/* Bring out ya dead! */
static struct nf_conn *
get_next_corpse(int (*iter)(struct nf_conn *i, void *data),
		void *data, unsigned int *bucket)
{
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;

	write_lock_bh(&nf_conntrack_lock);
	for (; *bucket < nf_conntrack_htable_size; (*bucket)++) {
		list_for_each_entry(h, &nf_conntrack_hash[*bucket], list) {
			ct = nf_ct_tuplehash_to_ctrack(h);
			if (iter(ct, data))
				goto found;
		}
	}
	list_for_each_entry(h, &unconfirmed, list) {
		ct = nf_ct_tuplehash_to_ctrack(h);
		if (iter(ct, data))
			set_bit(IPS_DYING_BIT, &ct->status);
	}
	write_unlock_bh(&nf_conntrack_lock);
	return NULL;
found:
	atomic_inc(&ct->ct_general.use);
	write_unlock_bh(&nf_conntrack_lock);
	return ct;
}

void
nf_ct_iterate_cleanup(int (*iter)(struct nf_conn *i, void *data), void *data)
{
	struct nf_conn *ct;
	unsigned int bucket = 0;

	while ((ct = get_next_corpse(iter, data, &bucket)) != NULL) {
#ifdef HNDCTF
		ip_conntrack_ipct_delete(ct, 0);
#endif /* HNDCTF */
		/* Time to push up daises... */
		if (del_timer(&ct->timeout))
			death_by_timeout((unsigned long)ct);
		/* ... else the timer will get him soon. */

		nf_ct_put(ct);
	}
}

EXPORT_SYMBOL_GPL(nf_ct_iterate_cleanup);

/* 
 * remove the expect conntrack channel based on the control channel. 
 * Lai 2010.04.02 add.
 */
void nf_ct_expect_conntrack_clean(struct nf_conn *ct)
{
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *sibling;
	int i;
	unsigned long extra_jiffies = 1 * HZ;

	read_lock_bh(&nf_conntrack_lock);
	for(i = 0; i < nf_conntrack_htable_size; i++)
	{
		list_for_each_entry(h, &nf_conntrack_hash[i], list)
		{
			sibling = nf_ct_tuplehash_to_ctrack(h);

			if(sibling->master && (sibling->master == ct) && (sibling != ct))
			{
				/* found out the expect channel here. */
				if(del_timer(&sibling->timeout))
				{
					/* Just setting timeout, don't put ct away. */
					sibling->timeout.expires = jiffies + extra_jiffies;
					add_timer(&sibling->timeout);
				}
			}
		}
	}
	read_unlock_bh(&nf_conntrack_lock);
}

static int kill_all(struct nf_conn *i, void *data)
{
	return 1;
}

static void free_conntrack_hash(struct list_head *hash, int vmalloced, int size)
{
	if (vmalloced)
		vfree(hash);
	else
		free_pages((unsigned long)hash,
			   get_order(sizeof(struct list_head) * size));
}

void nf_conntrack_flush(void)
{
	nf_ct_iterate_cleanup(kill_all, NULL);
}
EXPORT_SYMBOL_GPL(nf_conntrack_flush);

/* Mishearing the voices in his head, our hero wonders how he's
   supposed to kill the mall. */
void nf_conntrack_cleanup(void)
{
	int i;

	rcu_assign_pointer(ip_ct_attach, NULL);

	/* This makes sure all current packets have passed through
	   netfilter framework.  Roll on, two-stage module
	   delete... */
	synchronize_net();

	nf_ct_event_cache_flush();
 i_see_dead_people:
	nf_conntrack_flush();
	if (atomic_read(&nf_conntrack_count) != 0) {
		schedule();
		goto i_see_dead_people;
	}
	/* wait until all references to nf_conntrack_untracked are dropped */
	while (atomic_read(&nf_conntrack_untracked.ct_general.use) > 1)
		schedule();

	rcu_assign_pointer(nf_ct_destroy, NULL);

	for (i = 0; i < NF_CT_F_NUM; i++) {
		if (nf_ct_cache[i].use == 0)
			continue;

		NF_CT_ASSERT(nf_ct_cache[i].use == 1);
		nf_ct_cache[i].use = 1;
		nf_conntrack_unregister_cache(i);
	}
	kmem_cache_destroy(nf_conntrack_expect_cachep);
	free_conntrack_hash(nf_conntrack_hash, nf_conntrack_vmalloc,
			    nf_conntrack_htable_size);

	nf_conntrack_proto_fini();
}

static struct list_head *alloc_hashtable(int size, int *vmalloced)
{
	struct list_head *hash;
	unsigned int i;

	*vmalloced = 0;
	hash = (void*)__get_free_pages(GFP_KERNEL,
				       get_order(sizeof(struct list_head)
						 * size));
	if (!hash) {
		*vmalloced = 1;
		printk(KERN_WARNING "nf_conntrack: falling back to vmalloc.\n");
		hash = vmalloc(sizeof(struct list_head) * size);
	}

	if (hash)
		for (i = 0; i < size; i++)
			INIT_LIST_HEAD(&hash[i]);

	return hash;
}

int set_hashsize(const char *val, struct kernel_param *kp)
{
	int i, bucket, hashsize, vmalloced;
	int old_vmalloced, old_size;
	int rnd;
	struct list_head *hash, *old_hash;
	struct nf_conntrack_tuple_hash *h;

	/* On boot, we can set this without any fancy locking. */
	if (!nf_conntrack_htable_size)
		return param_set_uint(val, kp);

	hashsize = simple_strtol(val, NULL, 0);
	if (!hashsize)
		return -EINVAL;

	hash = alloc_hashtable(hashsize, &vmalloced);
	if (!hash)
		return -ENOMEM;

	/* We have to rehahs for the new table anyway, so we also can
	 * use a newrandom seed */
	get_random_bytes(&rnd, 4);

	write_lock_bh(&nf_conntrack_lock);
	for (i = 0; i < nf_conntrack_htable_size; i++) {
		while (!list_empty(&nf_conntrack_hash[i])) {
			h = list_entry(nf_conntrack_hash[i].next,
				       struct nf_conntrack_tuple_hash, list);
			list_del(&h->list);
			bucket = __hash_conntrack(&h->tuple, hashsize, rnd);
			list_add_tail(&h->list, &hash[bucket]);
		}
	}
	old_size = nf_conntrack_htable_size;
	old_vmalloced = nf_conntrack_vmalloc;
	old_hash = nf_conntrack_hash;

	nf_conntrack_htable_size = hashsize;
	nf_conntrack_vmalloc = vmalloced;
	nf_conntrack_hash = hash;
	nf_conntrack_hash_rnd = rnd;
	write_unlock_bh(&nf_conntrack_lock);

	free_conntrack_hash(old_hash, old_vmalloced, old_size);
	return 0;
}

module_param_call(hashsize, set_hashsize, param_get_uint,
		  &nf_conntrack_htable_size, 0600);

int __init nf_conntrack_init(void)
{
	int ret;

	/* Idea from tcp.c: use 1/16384 of memory.  On i386: 32MB
	 * machine has 256 buckets.  >= 1GB machines have 8192 buckets. */
	if (!nf_conntrack_htable_size) {
		nf_conntrack_htable_size
			= (((num_physpages << PAGE_SHIFT) / 16384)
			   / sizeof(struct list_head));
		if (num_physpages > (1024 * 1024 * 1024 / PAGE_SIZE))
			nf_conntrack_htable_size = 8192;
		if (nf_conntrack_htable_size < 16)
			nf_conntrack_htable_size = 16;
	}
	nf_conntrack_max = 8 * nf_conntrack_htable_size;

	printk("nf_conntrack version %s (%u buckets, %d max)\n",
	       NF_CONNTRACK_VERSION, nf_conntrack_htable_size,
	       nf_conntrack_max);

	nf_conntrack_hash = alloc_hashtable(nf_conntrack_htable_size,
					    &nf_conntrack_vmalloc);
	if (!nf_conntrack_hash) {
		printk(KERN_ERR "Unable to create nf_conntrack_hash\n");
		goto err_out;
	}

	ret = nf_conntrack_register_cache(NF_CT_F_BASIC, "nf_conntrack:basic",
					  sizeof(struct nf_conn));
	if (ret < 0) {
		printk(KERN_ERR "Unable to create nf_conn slab cache\n");
		goto err_free_hash;
	}

	nf_conntrack_expect_cachep = kmem_cache_create("nf_conntrack_expect",
					sizeof(struct nf_conntrack_expect),
					0, 0, NULL, NULL);
	if (!nf_conntrack_expect_cachep) {
		printk(KERN_ERR "Unable to create nf_expect slab cache\n");
		goto err_free_conntrack_slab;
	}

	ret = nf_conntrack_proto_init();
	if (ret < 0)
		goto out_free_expect_slab;

	/* For use by REJECT target */
	rcu_assign_pointer(ip_ct_attach, __nf_conntrack_attach);
	rcu_assign_pointer(nf_ct_destroy, destroy_conntrack);

	/* Set up fake conntrack:
	    - to never be deleted, not in any hashes */
	atomic_set(&nf_conntrack_untracked.ct_general.use, 1);
	/*  - and look it like as a confirmed connection */
	set_bit(IPS_CONFIRMED_BIT, &nf_conntrack_untracked.status);

#if defined(CONFIG_BCM_NAT) || defined(HNDCTF)
//Zhijian add for fastnat and hndctf 2010-07-27 
	qos_table_init();
#endif	

	return ret;

out_free_expect_slab:
	kmem_cache_destroy(nf_conntrack_expect_cachep);
err_free_conntrack_slab:
	nf_conntrack_unregister_cache(NF_CT_F_BASIC);
err_free_hash:
	free_conntrack_hash(nf_conntrack_hash, nf_conntrack_vmalloc,
			    nf_conntrack_htable_size);
err_out:
	return -ENOMEM;
}
