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

#include <asm/types.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include "defs.h"
#include "log.h"

static struct sock *nlsock = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
static DEFINE_MUTEX(semLock);
#else
static DECLARE_MUTEX(semLock);
#endif

static int (*fp_receive)(void *, int, unsigned int) = NULL;

int send_to_user(unsigned int id, void *in, int length);
int nlink_init(int (*f_callback)(void *data, int type, unsigned int length));
void nlink_fini(void);


static inline void handle_packet(struct sk_buff *skb)
{
    int status = 0;
    unsigned int skblen;
    __u32 nlmsglen = 0;
    __u16 type;
    struct nlmsghdr *nlh;

    skblen = skb->len;
    if (skblen < sizeof(struct nlmsghdr))
    {
        pk_debug("skb(%d) < nlhdr(%d)",  skblen, sizeof(struct nlmsghdr));
        return;
    }

    nlh = (struct nlmsghdr *)skb->data;
    nlmsglen = nlh->nlmsg_len;
    if (nlmsglen < sizeof(*nlh) || skblen < nlmsglen)
    {
        return;
    }

    type = nlh->nlmsg_type;

    if (fp_receive)
		status = fp_receive(NLMSG_DATA(nlh), type, skblen - NLMSG_LENGTH(0));

    return;
}

static void rcv_from_sk(struct sock *sk, int len)
{

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	do
    {
        struct sk_buff *skb;

		mutex_lock(&semLock);


        while ((skb = skb_dequeue(&sk->sk_receive_queue)) != NULL)
        {
            handle_packet(skb);
            kfree_skb(skb);
        }

		mutex_unlock(&semLock);
    }
    while (nlsock && nlsock->sk_receive_queue.qlen);
#else
	do
    {
        struct sk_buff *skb;

        if (down_trylock(&semLock))
        {
            return;
		}

        while ((skb = skb_dequeue(&sk->receive_queue)) != NULL)
        {
            handle_packet(skb);
            kfree_skb(skb);
        }

        up(&semLock);
    }
    while (nlsock && nlsock->receive_queue.qlen);
#endif

}


int send_to_user(unsigned int id, void *in, int length)
{
    struct sk_buff *skb = NULL;
    struct nlmsghdr *nlh;
    char *data;
    size_t size = 0;

    if (!in)
    {
        pk_debug("Incoming data is NULL");
		goto nlmsg_failure;
        //return -1;
    }

    size = NLMSG_SPACE(length); //size of message and size of nlmsghdr
    skb = alloc_skb(size, GFP_ATOMIC);
    if (!skb)
    {
        pk_debug("Unable to allocate skb");
		goto nlmsg_failure;
        //return -1;
    }
	
	nlh = NLMSG_PUT(skb, 0, 0, id, length);
    data = NLMSG_DATA(nlh);

    memcpy(data, in, length);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    NETLINK_CB(skb).pid = 0;
    NETLINK_CB(skb).dst_group = 1;
#else
    NETLINK_CB(skb).groups = 0;
    NETLINK_CB(skb).pid = 0;
    NETLINK_CB(skb).dst_pid = 0;
    NETLINK_CB(skb).dst_groups = 1;
#endif
    
    netlink_broadcast(nlsock, skb, 0, 1, GFP_ATOMIC);
    return 0;

nlmsg_failure:
	if (skb)
		kfree_skb(skb);

	return -1;
}

int nlink_init(int (*f_callback)(void *, int, unsigned int))
{
    if ((fp_receive = f_callback) == NULL)
    {
        pk_err("No handler interests the netlink socket");
        return -EINVAL;
    }

	
	/* tlhhh. fusion code for 2.6.22 interface. 
	 * stay multicast groups to 0
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    if ((nlsock = netlink_kernel_create(NETLINK_USERSOCK, 0, rcv_from_sk, NULL, THIS_MODULE)) == NULL)
#else
    if ((nlsock = netlink_kernel_create(NETLINK_USERSOCK, rcv_from_sk)) == NULL)
#endif
    {
        pk_err("netlink socket create failed");
        return -EINVAL;
    }

    return 0;
}

void nlink_fini(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	sock_release(nlsock->sk_socket);
#else
    sock_release(nlsock->socket);
#endif
}

