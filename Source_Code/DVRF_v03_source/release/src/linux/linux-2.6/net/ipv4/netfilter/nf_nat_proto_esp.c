/*
 * ip_nat_proto_esp.c - Version 0.1
 *
 * NAT protocol helper module for ESP.
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>

#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_rule.h>
#include <net/netfilter/nf_nat_protocol.h>
#include <linux/netfilter/nf_conntrack_proto_esp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Harald Welte <laforge@gnumonks.org>");
MODULE_DESCRIPTION("Netfilter NAT protocol helper module for ESP");

#if 0
#define DEBUGP(format, args...) printk(KERN_DEBUG __FILE__ ":" __FUNCTION__": " format, ## args)
#define DUMP_TUPLE_ESP(x) printk("%u.%u.%u.%u:0x%x -> %u.%u.%u.%u:0x%x\n", \
			NIPQUAD((x)->src.u3.ip), ntohl((x)->src.u.esp.spi), \
			NIPQUAD((x)->dst.u3.ip), ntohl((x)->dst.u.esp.spi))
#else
#define DUMP_TUPLE_ESP(x)
#define DEBUGP(x, args...)
#endif

/* is key in given range between min and max */
static int
esp_in_range(const struct nf_conntrack_tuple *tuple,
	     enum nf_nat_manip_type maniptype,
	     const union nf_conntrack_man_proto *min,
	     const union nf_conntrack_man_proto *max)
{
	unsigned int spi;
	DEBUGP("esp_in_range entry.\n");
	return 0;	
	if (maniptype == IP_NAT_MANIP_SRC)
		spi = tuple->src.u.esp.spi;
	else
		spi = tuple->dst.u.esp.spi;
	
	DUMP_TUPLE_ESP(tuple);

	return (ntohl(spi) >= ntohl(min->esp.spi) &&
		 ntohl(spi) <= ntohl(max->esp.spi));

}

/* generate unique tuple ... */
static int 
esp_unique_tuple(struct nf_conntrack_tuple *tuple,
		 const struct nf_nat_range *range,
		 enum nf_nat_manip_type maniptype,
		 const struct nf_conn *conntrack)
{
	u_int32_t min, i, range_size;
	u_int32_t key = 0;
	u_int32_t *spi = NULL;
	DEBUGP("esp_unique_tuple entry.\n");
	return 1;
	DUMP_TUPLE_ESP(tuple);

	if (maniptype == IP_NAT_MANIP_SRC)
		spi = &tuple->src.u.esp.spi;
	else
		spi = &tuple->dst.u.esp.spi;
	
	/*range is to do fast search*/
	if (! (range->flags & IP_NAT_RANGE_PROTO_SPECIFIED))
	{
			DEBUGP("NATing ESP (ct = %p)\n",conntrack);
			min = 1;
			range_size = 0xffffffff;
	} 
	else
	{
		min = ntohl(range->min.esp.spi);
		range_size = ntohl(range->max.esp.spi) - min + 1;
	}

	DEBUGP("min = %u, range_size = %u\n", min, range_size); 

	for (i = 0; i < range_size; i++, key++) {
		*spi = htonl(min + key % range_size);
		if (!nf_nat_used_tuple(tuple, conntrack))
			return 1;
	}

	DEBUGP("%p: no NAT mapping\n", conntrack);

	return 0;
}

/* manipulate a ESP packet according to maniptype */
static int 
esp_manip_pkt(struct sk_buff **pskb,
		unsigned int iphdroff,
	      const struct nf_conntrack_tuple *tuple,
	      enum nf_nat_manip_type maniptype)
{
	//struct iphdr *iph = (struct iphdr *)((*pskb)->data + iphdroff);
	struct iphdr *iph = ip_hdr(*pskb);	
	struct esp_hdr *esph = (struct esp_hdr *)((u_int32_t *)iph+iph->ihl);
	u_int32_t *old_ip;
	u_int32_t *old_spi =NULL;
	u_int32_t sip = 0, dip =0,ret = 0;
       DEBUGP("\n@@@@ %s @@@@\n", __FUNCTION__);	

	
	DEBUGP("dir =[%d] manip [%u.%u.%u.%u] spi[%x].\n "
			"ip_header sip[%u.%u.%u.%u]dip[%u.%u.%u.%u].\n"
			"spi[0x%x] seq[%u].\n",
			maniptype,NIPQUAD(tuple->src.u3.ip),ntohl(tuple->src.u.esp.spi),
			NIPQUAD(iph->saddr),NIPQUAD(iph->daddr),ntohl(esph->spi),ntohl(esph->seq));

	/*keep data to tuple struct*/
	if (maniptype == IP_NAT_MANIP_SRC)
	{
		/* Get rid of dst  ip / spi */
		 old_ip = &iph->daddr; //here orignal ip header
		 old_spi =&esph->spi;
		ret = NF_ACCEPT;
	}
	else 
	{
		ret = esp_packet_in(iph,&sip,&dip);
		if (ret == NF_ACCEPT)
		{
			DEBUGP("found !! sip[%u.%u.%u.%u]dip[%u.%u.%u.%u]\n",
				NIPQUAD(sip),NIPQUAD(dip));
		 	old_ip = &dip; //here orignal ip header
		 	old_spi = &esph->spi;
		}
		else
		{
			DEBUGP("Not found !! sip[%u.%u.%u.%u]dip[%u.%u.%u.%u]\n",
				NIPQUAD(sip),NIPQUAD(dip));
			/* Get rid of dst  ip / spi */
		 	old_ip = &iph->daddr; //here orignal ip header
		 	old_spi = &esph->spi;
		}
	}
	return ret;
}

static struct nf_nat_protocol esp __read_mostly = {
   .name = "ESP",
   .protonum = IPPROTO_ESP,
   .me = THIS_MODULE,
   .manip_pkt = esp_manip_pkt,
   .in_range = esp_in_range,
   .unique_tuple = esp_unique_tuple,
};

int __init nf_nat_proto_esp_init(void)
{
	printk("edward =======nf_nat_proto_esp_init \n");
   return nf_nat_protocol_register(&esp);
}

void __exit nf_nat_proto_esp_fini(void)
{
   nf_nat_protocol_unregister(&esp);
}

module_init(nf_nat_proto_esp_init);
module_exit(nf_nat_proto_esp_fini);

