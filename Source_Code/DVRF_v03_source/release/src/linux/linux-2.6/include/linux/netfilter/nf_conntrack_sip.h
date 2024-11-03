#ifndef __NF_CONNTRACK_SIP_H__
#define __NF_CONNTRACK_SIP_H__
#ifdef __KERNEL__

#define SIP_PORT	5060
#define SIP_TIMEOUT	3600

#define __SIP_HDR(__name, __cname, __search, __match)                   \
{                                                                       \
	.name           = (__name),                                     \
	.len            = sizeof(__name) - 1,                           \
	.cname          = (__cname),                                    \
	.clen           = (__cname) ? sizeof(__cname) - 1 : 0,          \
	.search         = (__search),                                   \
	.slen           = (__search) ? sizeof(__search) - 1 : 0,        \
	.match_len      = (__match),                                    \
}

#define SDP_HDR(__name, __search, __match) \
	__SIP_HDR(__name, NULL, __search, __match)

enum sip_header_pos {
	POS_REG_REQ_URI,
	POS_REQ_URI,
	POS_FROM,
	POS_TO,
	POS_VIA,
	POS_CONTACT,
	POS_CONTENT,
	POS_CALL_ID,
	POS_MEDIA,
	POS_OWNER_IP4,
	POS_CONNECTION_IP4,
	POS_OWNER_IP6,
	POS_CONNECTION_IP6,
	POS_SDP_HEADER,
};

enum sdp_header_types {
	SDP_HDR_UNSPEC,
	SDP_HDR_VERSION,
	SDP_HDR_OWNER_IP4,
	SDP_HDR_CONNECTION_IP4,
	SDP_HDR_OWNER_IP6,
	SDP_HDR_CONNECTION_IP6,
	SDP_HDR_MEDIA,
};

enum sip_expectation_classes {
	SIP_EXPECT_SIGNALLING,
	SIP_EXPECT_AUDIO,
	SIP_EXPECT_VIDEO,
	SIP_EXPECT_APPLICATION,
	SIP_EXPECT_DATA,
	SIP_EXPECT_CONTROL,
	__SIP_EXPECT_MAX
};


 struct sdp_media_type {
         const char                      *name;
         unsigned int                    len;
         enum sip_expectation_classes    class;
 };
 
 #define SDP_MEDIA_TYPE(__name, __class)                                 \
 {                                                                       \
         .name   = (__name),                                             \
         .len    = sizeof(__name) - 1,                                   \
         .class  = (__class),                                            \
 }

extern unsigned int (*nf_nat_sip_hook)(struct sk_buff **pskb,
				       enum ip_conntrack_info ctinfo,
				       struct nf_conn *ct,
				       const char **dptr);
#if 0
extern unsigned int (*nf_nat_sdp_hook)(struct sk_buff **pskb,
				       enum ip_conntrack_info ctinfo,
				       struct nf_conntrack_expect *exp,
				       const char *dptr);
extern unsigned int (*nf_nat_sdp_hook)(struct sk_buff **pskb,
						enum ip_conntrack_info ctinfo,
						struct nf_conntrack_expect *rtp_exp,
						struct nf_conntrack_expect *rtcp_exp,
						const char *dptr);
#endif

extern unsigned int (*nf_nat_sdp_addr_hook)(struct sk_buff **skb,
					const char **dptr,
					unsigned int dataoff,
					unsigned int *datalen,
					enum sdp_header_types type,
					enum sdp_header_types term,
					const union nf_conntrack_address *addr);
extern unsigned int (*nf_nat_sdp_port_hook)(struct sk_buff **skb,
					const char **dptr,
					unsigned int *datalen,
					unsigned int matchoff,
					unsigned int matchlen,
					u_int16_t port);
extern unsigned int (*nf_nat_sdp_session_hook)(struct sk_buff **skb,
					const char **dptr,
					unsigned int dataoff,
					unsigned int *datalen,
					const union nf_conntrack_address *addr);
extern unsigned int (*nf_nat_sdp_media_hook)(struct sk_buff **skb,
					const char **dptr,
					unsigned int *datalen,
					struct nf_conntrack_expect *rtp_exp,
					struct nf_conntrack_expect *rtcp_exp,
					unsigned int mediaoff,
					unsigned int medialen,
					union nf_conntrack_address *rtp_addr);

extern int ct_sip_get_info(struct nf_conn *ct, const char *dptr, size_t dlen,
			   unsigned int *matchoff, unsigned int *matchlen,
			   enum sip_header_pos pos);
extern int ct_sip_lnlen(const char *line, const char *limit);
extern const char *ct_sip_search(const char *needle, const char *haystack,
				 size_t needle_len, size_t haystack_len,
				 int case_sensitive);
extern int ct_sip_get_sdp_header(const struct nf_conn *ct, const char *dptr,
                          unsigned int dataoff, unsigned int dlen,
                          enum sdp_header_types type,
                          enum sdp_header_types term,
                          unsigned int *matchoff, unsigned int *matchlen);
#endif /* __KERNEL__ */
#endif /* __NF_CONNTRACK_SIP_H__ */
