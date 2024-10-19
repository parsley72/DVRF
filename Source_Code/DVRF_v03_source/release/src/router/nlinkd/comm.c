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

#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* export memcpy, strerror */
#include <unistd.h> /* export getpid */
#include <sys/socket.h>
#include <asm/types.h> /* export __u32 */
#include <linux/netlink.h>
#include <errno.h> /* errno */
#include "nlinkd.h"

int nlink_unblk_recv(void *packet);
int nlink_recv(void *payload);
int nlink_send(void *payload, unsigned int size);
int nlink_init(void);
int nlink_fini(void);

int sockfd = 0;
#define RECV_INTERVAL	1000

int nlink_unblk_recv(void *packet)
{
	fd_set 	rfds;
	int ret_val, recvlen;
	struct timeval tv;
	
	recvlen = 0;
	FD_ZERO(&rfds);
	FD_SET(sockfd,&rfds);

	do
	{
		tv.tv_sec = 0;
		tv.tv_usec = RECV_INTERVAL;

		ret_val = select(sockfd+1, &rfds, NULL, NULL, &tv);
	} while ( (ret_val < 0) && (errno == EINTR) );

	if(ret_val<=0)
		return ret_val;	//0:timeout -1:error

	if( FD_ISSET(sockfd ,&rfds) )
	{
		if( (recvlen = nlink_recv(packet)) <  0 )
		{
			if( errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			{
				tm_dbg("Nlinkd receive from kernel is interrupted, try again");
				return 0;
			}
			if( errno == ENETDOWN || errno == ENODEV)
			{
				perror( "read failed" );
			}
			return -1;
		}

	}
	
	return recvlen;
}

int nlink_recv(void *payload)
{
    int ret = 0;
    struct sockaddr_nl nladdr;
    struct msghdr msg;
    struct iovec iov;
    struct nlmsghdr * nlhdr = NULL;

#define MAX_NL_PAYLOAD_LEN 1024
    nlhdr = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_NL_PAYLOAD_LEN));
    if (NULL == nlhdr)
    {
        perror("out of memory");
        return -1;
    }
	memset( nlhdr, 0, sizeof(struct nlmsghdr) );
    iov.iov_base = (void *)nlhdr;
    iov.iov_len = NLMSG_SPACE(MAX_NL_PAYLOAD_LEN);
#undef MAX_NL_PAYLOAD_LEN
    msg.msg_name = (void *)&(nladdr);
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ret = recvmsg(sockfd, &msg, 0);

    if (ret == -1)
    {
        perror("recvmsg");
    }

    memcpy(payload, NLMSG_DATA(nlhdr), nlhdr->nlmsg_len - NLMSG_ALIGN(sizeof(struct nlmsghdr)));

    free(nlhdr);

    return ret;
}

int nlink_send(void *payload, unsigned int size)
{
    int ret = 0;
    struct nlmsghdr * nlhdr = NULL;
    struct sockaddr_nl dest;
    struct msghdr msg;
    struct iovec iov;

    /* prepare dest structure */
    bzero(&dest, sizeof(dest));
    dest.nl_family = AF_NETLINK;
    dest.nl_pid = 0;   /* For Linux Kernel */
    dest.nl_groups = 0; /* unicast */

#define MAX_NL_MSG_LEN 1024
    nlhdr = (struct nlmsghdr *)malloc(NLMSG_SPACE(size));
#undef MAX_NL_MSG_LEN
    if (NULL == nlhdr)
    {
		perror("out of memory");
		return -1;
    }
	memset( nlhdr, 0, sizeof(struct nlmsghdr));
    nlhdr->nlmsg_pid = getpid();  /* self pid */
    nlhdr->nlmsg_flags = 0;
    
    /* Fill in the netlink message payload */
    memcpy(NLMSG_DATA(nlhdr), payload, size);
    nlhdr->nlmsg_len = NLMSG_LENGTH(size);

    iov.iov_base = (void *)nlhdr;
    iov.iov_len = nlhdr->nlmsg_len;
#if 0
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
#endif
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

again:
    ret = sendto(sockfd, nlhdr, nlhdr->nlmsg_len, 0, (struct sockaddr *)&dest, sizeof(dest));

    if (ret == -1)
    {
		if( errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
		{
			tm_dbg("Nlinkd send to kernel is interrupted, try again");
			goto again;
		}
		perror("sendto");
    }

    free(nlhdr);

    return ret;
}

int nlink_init(void)
{
	int ret = 0;

	sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);

	if (sockfd == -1)
	{
	    perror("socket");
	    return -1;
	}

	struct sockaddr_nl src_addr =
	{
	    .nl_family	= AF_NETLINK,
	    .nl_pad		= 0, /* unused */
	    .nl_pid		= getpid(), /* src pid */
	    .nl_groups	= 1  /* listen to group #1 bcast msg */
	};

	ret = bind(sockfd, (struct sockaddr*)&src_addr, sizeof(struct sockaddr_nl));

	if (ret == -1)
	{
	    perror("bing");
	    return -1;
	}

    return 0;
}

int nlink_fini(void)
{
    int ret = 0;

    ret = close(sockfd);

    if (ret == -1)
    {
        perror("close");
        return -1;
    }

    return 0;
}
