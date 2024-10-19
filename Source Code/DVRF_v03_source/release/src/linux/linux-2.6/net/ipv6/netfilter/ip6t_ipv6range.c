/* ipv6range match - matches IPv6 packets based
   on whether they contain certain ranges */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ipv6.h>
#include <linux/types.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter_ipv6/ip6t_ipv6range.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("IPv6 range match");
MODULE_AUTHOR("Leo Lin<leo.lin@cybertan.com.tw>");

#define DEBUGP printk

static int
ipv6range_match(const struct sk_buff *skb,
		 const struct net_device *in,
		 const struct net_device *out,
		 const struct xt_match *match,
		 const void *matchinfo,
		 int offset,
		 unsigned int protoff,
		 int *hotdrop)
{
	const struct ip6t_ipv6range_info *info = matchinfo;
	const struct ipv6hdr *iph = ipv6_hdr(skb);

	if (info->flags & IPV6RANGE_SRC) {
		if ((memcmp(&iph->saddr, &info->src.min_ip, sizeof(struct in6_addr)) < 0
			  || memcmp(&iph->saddr, &info->src.max_ip, sizeof(struct in6_addr)) > 0)
			 ^ !!(info->flags & IPV6RANGE_SRC_INV)) {
			DEBUGP("src IP " NIP6_FMT " NOT in range %s" NIP6_FMT "-" NIP6_FMT"\n", NIP6(iph->saddr), info->flags & IPV6RANGE_SRC_INV ? "(INV) " : "", NIP6(info->src.min_ip), NIP6(info->src.max_ip));
			return 0;
		}
	}
	if (info->flags & IPV6RANGE_DST) {
		if ((memcmp(&iph->daddr, &info->dst.min_ip, sizeof(struct in6_addr) < 0)
			  || memcmp(&iph->daddr, &info->dst.max_ip, sizeof(struct in6_addr)) > 0)
			 ^ !!(info->flags & IPV6RANGE_DST_INV)) {
			DEBUGP("dst IP "NIP6_FMT " NOT in range %s" NIP6_FMT "-" NIP6_FMT "\n", NIP6(iph->daddr), info->flags & IPV6RANGE_DST_INV ? "(INV) " : "", NIP6(info->dst.min_ip), NIP6(info->dst.max_ip));
			return 0;
		}
	}
	return 1;
}

static struct xt_match ip6t_ipv6range_match = {
	.name		= "ipv6range",
	.family		= AF_INET6,
	.match		= &ipv6range_match,
	.matchsize	= sizeof(struct ip6t_ipv6range_info),
	.checkentry	= NULL,
	.destroy	= NULL,
	.me		= THIS_MODULE,
};

static int __init ipv6range_init(void)
{
	return xt_register_match(&ip6t_ipv6range_match);
}

static void __exit ipv6range_exit(void)
{
	xt_unregister_match(&ip6t_ipv6range_match);
}

module_init(ipv6range_init);
module_exit(ipv6range_exit);
