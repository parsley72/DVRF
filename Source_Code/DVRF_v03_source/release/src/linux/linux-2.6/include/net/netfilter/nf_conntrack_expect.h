/*
 * connection tracking expectations.
 */

#ifndef _NF_CONNTRACK_EXPECT_H
#define _NF_CONNTRACK_EXPECT_H
#include <net/netfilter/nf_conntrack.h>

extern struct list_head nf_conntrack_expect_list;
extern struct kmem_cache *nf_conntrack_expect_cachep;
extern const struct file_operations exp_file_ops;

struct nf_conntrack_expect
{
	/* Internal linked list (global expectation list) */
	struct list_head list;

	/* We expect this tuple, with the following mask */
	struct nf_conntrack_tuple tuple, mask;

	/* Function to call after setup and insertion */
	void (*expectfn)(struct nf_conn *new,
			 struct nf_conntrack_expect *this);

	/* Helper to assign to new connection */
	struct nf_conntrack_helper *helper;

	/* The conntrack of the master connection */
	struct nf_conn *master;

	/* Timer function; deletes the expectation. */
	struct timer_list timeout;

	/* Usage count. */
	atomic_t use;

	/* Unique ID */
	unsigned int id;

	/* Flags */
	unsigned int flags;

#ifdef CONFIG_NF_NAT_NEEDED
	__be32 saved_ip;
	/* This is the original per-proto part, used to map the
	 * expected connection the way the recipient expects. */
	union nf_conntrack_man_proto saved_proto;
	/* Direction relative to the master connection. */
	enum ip_conntrack_dir dir;
#endif

	/* Add by Kelly add 2010.01.08 for SIP ALG */
	/* Maybe have an exit expectation.
	 * I add SIP Header Call-ID information into nf_conntrack_expect
	 * That can ensure correct and exit expectation.
	 * For an example:
	 * 	Caller sent INVITE without Authenticate, and SIP Proxy will response 407.
	 *	Caller will send again INVITE with Authemticate.
	 *	These SIP INVITE are the same dialog (these are the same Call-ID).
	 *	So do not need two expectation	
	 */
	unsigned int sip_call_id_hash;
};

#define NF_CT_EXPECT_PERMANENT 0x1

/* Lai 2010.04.02 add this flag for RTSP ALG. */
#define NF_CT_EXPECT_RTCP 0x2


struct nf_conntrack_expect *
__nf_conntrack_expect_find(const struct nf_conntrack_tuple *tuple);

struct nf_conntrack_expect *
nf_conntrack_expect_find_get(const struct nf_conntrack_tuple *tuple);

struct nf_conntrack_expect *
find_expectation(const struct nf_conntrack_tuple *tuple);

void nf_ct_unlink_expect(struct nf_conntrack_expect *exp);
struct nf_conntrack_expect *__nf_conntrack_expect_find_by_sip_call_id(unsigned int sip_call_id_hash);
struct nf_conntrack_expect *nf_conntrack_expect_find_by_sip_call_id(unsigned int sip_call_id_hash);
void nf_ct_remove_expectations(struct nf_conn *ct);
void nf_conntrack_unexpect_related(struct nf_conntrack_expect *exp);

/* Allocate space for an expectation: this is mandatory before calling
   nf_conntrack_expect_related.  You will have to call put afterwards. */
struct nf_conntrack_expect *nf_conntrack_expect_alloc(struct nf_conn *me);
void nf_conntrack_expect_init(struct nf_conntrack_expect *, int,
			      union nf_conntrack_address *,
			      union nf_conntrack_address *,
			      u_int8_t, __be16 *, __be16 *);
void nf_conntrack_expect_put(struct nf_conntrack_expect *exp);
int nf_conntrack_expect_related(struct nf_conntrack_expect *expect);

#endif /*_NF_CONNTRACK_EXPECT_H*/
