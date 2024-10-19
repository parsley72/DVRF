#ifndef _IP6T_IPV6RANGE_H
#define _IP6T_IPV6RANGE_H

#define IPV6RANGE_SRC		0x01	/* Match source IPv6 address */
#define IPV6RANGE_DST		0x02	/* Match destination IPv6 address */
#define IPV6RANGE_SRC_INV	0x10	/* Negate the condition */
#define IPV6RANGE_DST_INV	0x20	/* Negate the condition */

struct ip6t_ipv6range {
	/* Inclusive: network order. */
	struct in6_addr min_ip, max_ip;
};

struct ip6t_ipv6range_info
{
	struct ip6t_ipv6range src;
	struct ip6t_ipv6range dst;

	/* Flags from above */
	u_int8_t flags;
};


#endif /* _IP6T_IPV6RANGE_H */
