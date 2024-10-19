#ifndef _IP6T_REJECT_H
#define _IP6T_REJECT_H

enum ip6t_reject_with {
	IP6T_ICMP6_NO_ROUTE,
	IP6T_ICMP6_ADM_PROHIBITED,
	IP6T_ICMP6_NOT_NEIGHBOUR,
	IP6T_ICMP6_ADDR_UNREACH,
	IP6T_ICMP6_PORT_UNREACH,
	IP6T_ICMP6_ECHOREPLY,
	IP6T_TCP_RESET,
	/*
	 * 2010-12-09 ruby add to "Router IPv6 Requirements" L-15
	 * ICMPv6 : Source address failed ingress/egress policy (code 5)
	 */
	IP6T_ICMP6_SOURCE_ADDR_FAILED,
	IP6T_HTTP_REDIRECT
};

struct ip6t_reject_info {
	u_int32_t	with;	/* reject type */
};

#endif /*_IP6T_REJECT_H*/
