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
#include <pthread.h>
#include <errno.h>
#include <semaphore.h>
#include <signal.h>
#include <fcntl.h> /* export O_RDWR */
#include <netinet/in.h>
#include <sys/ioctl.h> /* SIOCGIFADDR */
#include <net/if.h> /* ifreq */
#include <unistd.h> /* export daemon */
#include <arpa/inet.h> /* export inet_ntoa */
#include <string.h>

#include <bcmnvram.h>
#include <cy_conf.h>
#include <code_pattern.h>
#include <utils.h>

#include "defs.h"
#include "nlinkd.h"
#include "pid.h"

//tlhhh. 2010-07-29
#include "cyParentalCTRL.h"

#define MAX_POLICY_NUMBER 14
#define MAX_PATH_LEN 2048
#define MAX_HOST_LEN 256
#define MAX_BUF_SIZE 4096

/* inet6_dev.scope defined in linux/include/net/ipv6.h */
#define SCOPE_GLOBAL			0x0
#define IPV6_ADDR_LOOPBACK		0x0010U
#define IPV6_ADDR_LINKLOCAL		0x0020U
#define IPV6_ADDR_SITELOCAL		0x0040U
#define IPV6_ADDR_SCOPE_MASK		0x00f0U

unblock_t *unblock_list[14];
static volatile int do_exit = 0;
static volatile int unblking = 0;

//tlhhh 2010-08-04. we need to protect the list operation in multi-thread environment
pthread_mutex_t mutex_pc_list;

typedef struct
{
    pthread_mutex_t f_lock;
    int is_busy;
    int number_id;
    pthread_t   id;
    char data[MAX_BUF_SIZE];
    sem_t sem;
} workthread_t;

typedef struct {
	char path[MAX_PATH_LEN];
	char host[MAX_HOST_LEN];
	char dest_ip[16];
} judge_info_t;


static int PROCESS_COUNT = 50;
static workthread_t **thread_pool = NULL;

char *strcasestr(const char *haystack, const char *needle);

//extern declaration
extern int checkLinksysWList(const char *szHost, const char *szPath);
extern int checkTMSSSPolicy( const char *host, const char *url, const char *mac );

extern int nlink_unblk_recv(void *packet);
extern int nlink_recv(void *payload);
extern int nlink_send(void *payload, unsigned int size);
extern int nlink_init(void);
extern int nlink_fini(void);

/*******************************************************************
 Are two IPs on the same subnet?
********************************************************************/
int same_net(struct in_addr ip1, struct in_addr ip2, struct in_addr mask)
{
    unsigned long net1, net2, nmask;

    nmask = ntohl(mask.s_addr);
    net1  = ntohl(ip1.s_addr);
    net2  = ntohl(ip2.s_addr);

    return((net1 & nmask) == (net2 & nmask));
}

char *url_escape(const char* szFrom)
{
	char *buff;
    const char *p = szFrom;
    
    /* we inflate input string 3x at most. */
    char *ret = (char *)malloc(strlen(szFrom)*3);
    if (ret == NULL)
    {
        perror("malloc failed");
        return NULL;
    }
    
    buff = ret;
    
    for (;*p;p++)
    {
        switch (*p)
        {
        case ';':
        case '?':
        case '/':
        case ':':
        case '#':
        case '&':
        case '=':
        case '+':
        case '$':
        case ',':
        case ' ':
        case '%':
        case '<':
        case '>':
        case '~':
            snprintf(buff, sizeof(buff), "%%%02X", (char)*p);
            buff += strlen(buff);
            break;
        default:
            *buff = *p;
            buff++;
            break;
        }
    }
    *buff = '\0'; /* end the string */
    return ret;
}

char *get_lan_ipv6_lladdr(char *nvram_value)
{
	char *lan_hwaddr = nvram_safe_get(nvram_value);
	char *pch;
	int hwaddr[6];
	int i = 0;
	char buf[64];

	memcpy(buf, lan_hwaddr, strlen(lan_hwaddr));
	buf[strlen(lan_hwaddr)] = '\0';

	pch = strtok(buf, ":");
	while (pch != NULL)
	{
		hwaddr[i++] = strtol(pch, NULL, 16);
		pch = strtok(NULL, ":");
	}

	sprintf(lan_ipv6_ipaddr, "[fec0::%02x%02x:%02xff:fe%02x:%02x%02x]",
		(hwaddr[0]^0x02), hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);

	return lan_ipv6_ipaddr;
}

char *get_lan_ipv6_ipaddr(int is_guest)
{
	char *ifname = is_guest ?nvram_safe_get("gn_lan_ifname") :nvram_safe_get("lan_ifname");
	char devname[20];
	int plen, scope, dad_status, if_idx, if_flags6, if_probes;
	char addr6p[8][5], wan_gw[8][5];
	FILE *fp = NULL;
	char cport[8];

	sprintf(cport, "%s%s", is_guest ?":" :"", is_guest ?nvram_safe_get("gn_http_port") :"");
	fp = fopen("/proc/net/if_flags6", "r");
	if (fp != NULL)
	{
		while (fscanf(fp, "%4s%4s%4s%4s%4s%4s%4s%4s %02x %02x %02x %02x %02x %08x %20s %4s%4s%4s%4s%4s%4s%4s%4s\n",
			addr6p[0],addr6p[1],addr6p[2],addr6p[3],
			addr6p[4],addr6p[5],addr6p[6],addr6p[7],
			&if_idx,
			&plen,
			&scope,
			&dad_status,
			&if_probes,
			&if_flags6,
			devname,
			wan_gw[0],wan_gw[1],wan_gw[2],wan_gw[3],
			wan_gw[4],wan_gw[5],wan_gw[6],wan_gw[7]) != EOF)
		{
			if (strcmp(devname, ifname) == 0)
			{
				if ((scope & IPV6_ADDR_SCOPE_MASK) == SCOPE_GLOBAL) {
					sprintf(lan_ipv6_ipaddr, "[%4s:%4s:%4s:%4s:%4s:%4s:%4s:%4s]%s",
					addr6p[0], addr6p[1], addr6p[2], addr6p[3],
					addr6p[4], addr6p[5], addr6p[6], addr6p[7], cport);
					return lan_ipv6_ipaddr;
				}
			}
		}
	}
	if(is_guest)
		return get_lan_ipv6_lladdr("wl0.1_hwaddr");

	return get_lan_ipv6_lladdr("lan_hwaddr");
}

/*  According to http_info, this function check if need to block. 
*	return value:
*	@if need to block: return 1, and fill the blkpage with blocking url;
*	@if do _not_ need block: return 0;
*	@if any error happened: return -1.
*/
int should_block(http_message_t *http_info, char blkpage[], unsigned long srcip, struct in6_addr tmp_addr6, int family)
{
	int do_block = 1;	//default block. tlhhh
	int is_guestnetwork = 0;
	
	//check if from guest network
	if (family == AF_INET6) {
		char gn_addr6[64];
		struct in6_addr src_addr6;

		inet_pton(AF_INET6, nvram_safe_get("gn_lan_ipv6_prefix"), (void *)&src_addr6);
		is_guestnetwork = ((tmp_addr6.s6_addr32[0] == src_addr6.s6_addr32[0]) && (tmp_addr6.s6_addr32[1] == src_addr6.s6_addr32[1]));
	}
	else {
	struct in_addr src_addr;
	struct in_addr gn_addr;
	struct in_addr gn_mask;
	
	src_addr.s_addr = srcip;
	gn_addr.s_addr = inet_addr(nvram_safe_get("gn_lan_ipaddr"));
	gn_mask.s_addr = inet_addr(nvram_safe_get("gn_lan_netmask"));
	if( same_net( src_addr, gn_addr, gn_mask) )
		is_guestnetwork = 1;
	}

	tm_dbg("is_guest=%d, action=%d, host=%s, path=%s, mac=%s", is_guestnetwork, http_info->action, http_info->host, http_info->path, http_info->pszMAC);

    /* Output URL Filter message */
    switch (http_info->action)
    {
#ifdef TMSS_URL_FILTERING
		case HTTP_MSG_ACTION_WTP_BLOCK:
			//http_info->policy_num = 0;	//policy_num already be set.
			http_info->blk_idx = 3;		//WTP
			break;
        case HTTP_MSG_ACTION_PC_BLOCK:
			http_info->blk_idx = 2;		//PC (Category or BlackList)
            break;
#endif //TMSS_URL_FILTERING

		case HTTP_MSG_ACTION_UNKNOWN:
		case HTTP_MSG_ACTION_RELAY:
		case HTTP_MSG_ACTION_LICENSE_EXPIRED:
		//case HTTP_MSG_ACTION_WHITELIST:
			/* IR-B0011870, add white list checking. */
			/* 2009.10.29
			 * IR-B0013306  update whitelist rev1.5 by Elijah.Tsai
			 * [P.S.] Only *.linksys/cisco/purenetworks/networkmagic.com won't be blocked by schedule */
			if( !((http_info->host != NULL) && (http_info->path != NULL) && (http_info->pszMAC != NULL)) )	
			{
				do_block = 0;
				break;
			}

			//PARENTAL CTRL added here!
			if ( nvram_match("hnd_filter_enabled", "1") )
			{
				int policy_number = 0;

				policy_number = ParetanlCTRL(http_info, srcip >> 24, is_guestnetwork);

				if(policy_number)
				{
					http_info->blk_idx = (policy_number & 0x0000FF00) >> 8;
					http_info->policy_num = (policy_number & 0x000000FF);
				}
				else
					do_block = 0;

			}
			else
			{
				do_block = 0;
			}
			break;

		case HTTP_MSG_ACTION_BLOCK: //wangfei sync patch from RC4-RC8
		default:
			// IR-B0013570 iPhone needs 2 attempts.
			if ( http_info->host && http_info->path
				 && strstr(http_info->host, "www.apple.com")
				 && strstr(http_info->path, "library/test/success.html") )
			 return -1;            // finish this connection and don't send forbidden page back.

			sprintf(blkpage, HTTP_HND_FORBIDDEN_HEADER);
			blkpage[MAX_URL_LENGTH-1] = '\0';
			return 1;
    }

	if( do_block )
	{
		snprintf(blkpage, MAX_URL_LENGTH, HTTP_HND_REDIRECT_URL,
			(family == AF_INET ?
			   (is_guestnetwork ? nvram_safe_get("gn_lan_ipaddr") : nvram_safe_get("lan_ipaddr")) :
			   get_lan_ipv6_ipaddr(is_guestnetwork)),
			http_info->host, http_info->path,
			http_info->policy_num, // FIXME: policy number
			http_info->pszMAC,
			http_info->blk_idx);

		blkpage[MAX_URL_LENGTH-1] = '\0';
	}
	
    http_info->action = HTTP_MSG_ACTION_UNKNOWN;
    return do_block;
}


/* tlhhh 2010-11-1. 
 * match:	return 1 
 * unmatch: return 0 
 */
static int wp_match_url(const char *host)
{
	int i;
    const char *sp = host; 
	const char *ep = host + strlen(host);
    struct list_info_t
    {
        const char keyword[256];    //256
        int  len;

    } whitelist[] = {
        {"cisco.com", strlen("cisco.com")},
        {"linksys.com", strlen("linksys.com")},
        {"linksysbycisco.com", strlen("linksysbycisco.com")}, /* 2011-08-10, resolve E3200-131*/
        {"webex.com", strlen("webex.com")},
        {"purenetworks.com", strlen("purenetworks.com")},
        {"networkmagic.com", strlen("networkmagic.com")},
    };

    if( host == NULL )
        return 0;

    for (i=0; i< sizeof(whitelist)/sizeof(whitelist[0]); i++ )
    {
        int offset = 0;

		sp = strcasestr(host, whitelist[i].keyword);

        if( sp && (whitelist[i].len == ((char *)ep - (char *)sp)) )
        {
            offset = (int)(sp - host);

			ASSERT(offset<0, " pointer offset error \n");
            if (  offset == 0 || (offset > 0 && host[offset-1] == '.') )
                return 1;
        }
        continue;
    }

    return 0;


}

int wp_should_block( http_message_t *http_info, char blkpage[], int family )
{
	if ( wp_match_url( http_info->host ) )
	{
		return 0;	//pass
	}

	snprintf(blkpage, MAX_URL_LENGTH, HTTP_WP_REDIRECT_URL,
			(family == AF_INET ?
			   nvram_safe_get("lan_ipaddr") :
			   get_lan_ipv6_ipaddr(0)),
			http_info->host, http_info->path);

	blkpage[MAX_URL_LENGTH-1] = '\0';

	return 1;
}

char *mac2str( unsigned char mac[] )
{
	static char str [6*3];

// 	if( mac==NULL || strcmp((char *)mac, "") )
// 		return "";

	memset(str, 0, sizeof(str));
	sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return str;
}

static void *workfunc(void *param)
{
    int thread_id = *((char *)param);
    int errcode = 0;
    workthread_t *cur_thread = thread_pool[thread_id];
    sk_info_t sk_info;
    nlink_packet_t *pPacket = NULL;
    nlink_packet_t *pResultPkt = NULL;
    judge_info_t judge_info;
    
    char str_mac[20];
    char str_ip[100];
	
	char *blkpage_buf = NULL;
	int  ret = -1;
	http_message_t http_info;

	tm_dbg("ratingThread #%d start ...", thread_id);

	//tlhhh. ignore term signal in work thread, main thread will notify us.
	//signal(SIGTERM, SIG_IGN);

    while (1)
    {
        struct in_addr tmp_addr;
        struct in6_addr tmp_addr6;
		//tlhhh. 2010-7-29
		int wlist_flag = 0;
		unsigned long srcip;
		char *host, *path;

        /* wait for a semephore */
        errcode = sem_wait(&cur_thread->sem);
        if (errcode == -1)
        {
			if (errno == EINTR)
				continue;
            printf("sem_wait err: %d", errno);
			break;
        }

		if(do_exit)	break;


        pthread_mutex_lock(&cur_thread->f_lock);
        pPacket = (nlink_packet_t *)cur_thread->data;
        pthread_mutex_unlock(&cur_thread->f_lock);	//release data pointer until we already copy that. tlhhh 2010-8-4.

        if (pPacket == NULL)
        {
            printf("thread %d get a null packet", thread_id);
            goto __teardown;
        }

        if ((pPacket->type != NETLINK_REQUEST) || 
				(pPacket->subtype != NETLINK_RATEURL_WP && pPacket->subtype != NETLINK_RATEURL_PC))
        {
            tm_dbg("unrecognized request from kernel: type=[%d], subtype=[%d]\n", pPacket->type, pPacket->subtype);
            goto __teardown;
        }

		memset(&judge_info, 0, sizeof(judge_info));

		//get Host
		memset( judge_info.host, 0, sizeof(judge_info.host) );
        strncpy(judge_info.host, PTRGET_NLREQ_HOST(pPacket), sizeof(judge_info.host) - 1);
        judge_info.host[sizeof(judge_info.host) - 1] = '\0';
		
		//get Path
		memset( judge_info.path, 0, sizeof(judge_info.path) );
        strncpy(judge_info.path, PTRGET_NLREQ_URL(pPacket), sizeof(judge_info.path) - 1);
        judge_info.path[sizeof(judge_info.path) - 1] = '\0';

		//get Mac
		memset( str_mac, 0, sizeof(str_mac) );
		strncpy(str_mac, mac2str(PTRGET_NLREQ_MAC(pPacket)), sizeof(str_mac) - 1);
        str_mac[sizeof(str_mac) - 1] = '\0';

		//get DestIP
		memset( judge_info.dest_ip, 0, sizeof(judge_info.dest_ip) );
        tmp_addr.s_addr = PTRGET_NLREQ_DADDR(pPacket);
        strncpy(judge_info.dest_ip, inet_ntoa(tmp_addr), sizeof(judge_info.dest_ip) - 1);
        judge_info.dest_ip[sizeof(judge_info.dest_ip) - 1] = '\0';
        
		//get ClientIP
        memset(str_ip, 0, sizeof(str_ip));
	if(PTRGET_NLREQ_FAMILY(pPacket) == AF_INET6) {
		memcpy(&tmp_addr6, PTRGET_NLRES_SADDR6(pPacket), sizeof(tmp_addr6));
		inet_ntop(AF_INET6, (void *)&tmp_addr6, str_ip, sizeof(tmp_addr6));
	}
	else {
		tmp_addr.s_addr = PTRGET_NLREQ_SADDR(pPacket);
		strncpy(str_ip, inet_ntoa(tmp_addr), sizeof(str_ip) - 1);
		str_ip[sizeof(str_ip) - 1] = '\0';

		//record source ip. tlhhh 2010-7-29
		srcip = (unsigned long) (tmp_addr.s_addr);
	}
	tm_dbg("szHost=%s, szPath=%s, szClientIP=%s szDestIP=%s, szMac=%s", 
			judge_info.host, judge_info.path, str_ip, judge_info.dest_ip, str_mac);

		/* Avoid to read from /proc/net/arp to get MAC, that sucks on multi-thread. Kernel has handled this. tlhhh 2010-8-6 */
        //getIP_MAC(nClientIP, str_ip, sizeof(str_ip), str_mac, sizeof(str_mac));
        
        memcpy(&sk_info, &PTRGET_NLREQ_HANDLE(pPacket), sizeof(sk_info));
		
		//clear http_info struct
		memset(&http_info, 0, sizeof(http_message_t));

		memset(http_info.host, 0, sizeof(http_info.host));
		memset(http_info.path, 0, sizeof(http_info.path));
		memset(http_info.pszMAC, 0, sizeof(http_info.pszMAC));

		http_info.action = HTTP_MSG_ACTION_UNKNOWN;	//default value.

		/* tlhhh 2010-7-29. use stack space, avoid to thread-lock the malloced memory */

		//get Mac 
		memcpy(http_info.pszMAC, str_mac, strlen(str_mac));

		if ( pPacket->subtype == NETLINK_RATEURL_WP )
		{
			//if wireless warning page, no need for URL escape.
			snprintf( http_info.host, sizeof(http_info.host)-1 , "%s", judge_info.host );
			http_info.host[sizeof(http_info.host)-1] = '\0';

			snprintf( http_info.path, sizeof(http_info.path)-1, "%s", judge_info.path );
			http_info.path[sizeof(http_info.path)-1] = '\0';

			goto __skip_rating;
		}
		else
		{
			//get Host
			host = url_escape(judge_info.host);
			if (host){
				snprintf( http_info.host, sizeof(http_info.host)-1, "%s", host );
				http_info.host[sizeof(http_info.host)-1] = '\0';
				free(host);
			} else {
				goto __teardown;
			}

			//get Path
			path = url_escape(judge_info.path);
			if (path){
				snprintf( http_info.path, sizeof(http_info.path)-1, "%s", path );
				http_info.path[sizeof(http_info.path)-1] = '\0';
				free(path);
			} else {
				goto __teardown;
			}
		}


		tm_dbg("______%s[%d]______", __func__, __LINE__);
	
		//tlhhh. 2010-7-29
        /* ---------------  1. WhiteList check --------------- */
		pthread_mutex_lock( &mutex_pc_list );
		//wlist_flag = checkLinksysWList(judge_info.host, judge_info.path); //wangfei sync patch from RC4-RC8
		/* E2000, E3000 use this, which define in shared. tlh 2010-11-1 */
		wlist_flag = check_white_list(judge_info.host, judge_info.path); 
		pthread_mutex_unlock( &mutex_pc_list );

		tm_dbg("______%s[%d]wlist_flag=%d______", __func__, __LINE__, wlist_flag);
        if( wlist_flag == 6 )
        //if( wlist_flag != 0 )
		{
			http_info.action = HTTP_MSG_ACTION_WHITELIST;
            goto __skip_rating;  // means do not rating
        }

        /* ---------------  2. TimeBlock check --------------- */
        //IR-B0013570 iPhone needs 2 attempts. //wangfei sync patch from RC4-RC8
        if ( strstr(judge_info.host, "www.apple.com") && strstr(judge_info.path, "library/test/success.html") )
        {
			pthread_mutex_lock( &mutex_pc_list );
			if( 0 != CheckTimeBlock(str_mac, judge_info.host, srcip >> 24) )
			{
				pthread_mutex_unlock( &mutex_pc_list );
				http_info.action = HTTP_MSG_ACTION_BLOCK;
				goto __skip_rating;  // means do not rating
			}
			pthread_mutex_unlock( &mutex_pc_list );
        }

         
__skip_rating:

		//Now, ready to alloc memory to Result packet, and send to kernel.	tlhhh 2010-08-04
		pResultPkt = (nlink_packet_t *)malloc(sizeof(nlink_packet_t) + sizeof(nlink_urlresp_t));
		if( pResultPkt == NULL )
		{
			perror("can't allocate result package");
			goto __teardown;
		}
		PTRGET_NLRES_RESULTCODE(pResultPkt) = NETLINK_PASS;

		blkpage_buf = PTRGET_NLRES_BLOCKLOC(pResultPkt);	//buffer to save blockpage url.
		memset(blkpage_buf, 0, MAX_URL_LENGTH);

		//With http action, we will check if need block. tlhhh 2010-7-29
		pthread_mutex_lock( &mutex_pc_list );

		ret = 0;
		if( pPacket->subtype == NETLINK_RATEURL_WP )	//Warning Page
			ret = wp_should_block(&http_info, blkpage_buf, sk_info.family);
		else	//Paretanl CTRL
		{
			if(nvram_match("tmsss_enabled", "1") && wlist_flag != 6)	//pc not enabled
				ret = should_block(&http_info, blkpage_buf, srcip, tmp_addr6, sk_info.family);
		}

		pthread_mutex_unlock( &mutex_pc_list );

		tm_dbg("______%s[%d]______", __func__, __LINE__);

		PTRGET_NLRES_BLOCKLOCSIZE(pResultPkt) =  strlen(blkpage_buf);

		tm_dbg("block result = [%s], blocking page locate at: [%s]\n", ret==1 ? "BLOCK" : "PASS", blkpage_buf);
		if( ret >= 0 )		//1: block; 0: pass
		{
			PTRGET_NLRES_RESULTCODE(pResultPkt) = (ret==1) ? NETLINK_FAIL : NETLINK_PASS;
			if ( pPacket->subtype == NETLINK_RATEURL_PC && wlist_flag == 6 ) {
				PTRGET_NLRES_RESULTCODE(pResultPkt) = NETLINK_WHITE_PASS;
			}

			pResultPkt->type = NETLINK_RESPONSE;

			if ( pPacket->subtype == NETLINK_RATEURL_WP )
				pResultPkt->subtype = NETLINK_URLRESULT_WP;
			else
				pResultPkt->subtype = NETLINK_URLRESULT_PC;
			memcpy(&PTRGET_NLRES_HANDLE(pResultPkt), &sk_info, sizeof(sk_info));

			errcode = nlink_send(pResultPkt, sizeof(nlink_packet_t) + sizeof(nlink_urlresp_t));
			if (errcode == -1)
			{
				perror("nlink_send");
			}
		}
	
        free(pResultPkt);

__teardown:
        pthread_mutex_lock(&cur_thread->f_lock);
        cur_thread->is_busy = 0;
        pthread_mutex_unlock(&cur_thread->f_lock);
    }

	pthread_exit(NULL);
}

static void signal_handler(int nSignal)
{
    switch (nSignal)
    {
		case SIGUSR1:
			pthread_mutex_lock( &mutex_pc_list );
			if (unblking) {
				pthread_mutex_unlock( &mutex_pc_list );
				return ;
			}
			else {
				unblking = 1;
				unblockCTRL(nSignal);
				unblking = 0;
			}
			pthread_mutex_unlock( &mutex_pc_list );
			break;

		case SIGTERM:
			do_exit = 1;
			tm_dbg("nlinkd to be terminated");
			//exit(0);
			break;

		default:
			tm_dbg("Catched a signal: [%d]\n", nSignal);
			break;
    }
}



int main(int argc, char *argv[])
{
    int i;
    int flag;
	int ret = -1;

	tm_dbg("Nlinkd start running...");

	if( read_pid(PROXY_PID_FILE) > 0 )	//already exist a process
	{
		tm_dbg("already exist [nlinkd] process, exiting...");
		return -1;
	}
	
#ifdef LINUX26
	/* daemonize */
	switch(fork())	
	{
		case -1:
			perror("fork failed");
			exit(1);
			break;
		case 0:
			break;
		default:	/* parent exit */
			exit(0);
			break;
	}
#endif

    /* netlink initialization */
    if (nlink_init() < 0)	
	{
		remove_pid(PROXY_PID_FILE);
		return -1;
	}

	write_pid(PROXY_PID_FILE);
	
	//tlhhh. 2010-7-29
	initlist();

	k_init_tblk();

	/* tlhhh 2011-02-23
	 * if system call is interrupted, maybe receive abort signal
	 * to cause the process exit. so, just ignore it and try again.
	 */
    signal(SIGABRT, SIG_IGN); /* ignore abort signal */
    signal(SIGPIPE, SIG_IGN); /* ignore pipe broken signal */
    /* install term handler */
    //signal(SIGINT, signal_handler); /* catch ctrl-c signal */
    
    signal(SIGTERM, signal_handler); /* catch term signal */
    signal(SIGUSR1, signal_handler); /* catch SIGUSR1 signal */

	pthread_mutex_init( &mutex_pc_list, NULL);

#if 1
	PROCESS_COUNT = atoi(nvram_safe_get("nlinkd_count"));
	if( PROCESS_COUNT <= 0 || PROCESS_COUNT > 50 ) 
		PROCESS_COUNT = 50;
#endif

    thread_pool = (workthread_t**) malloc(sizeof(workthread_t*)*PROCESS_COUNT);

    for (i=0;i<PROCESS_COUNT;i++)
    {
        thread_pool[i] = (workthread_t*) malloc(sizeof(workthread_t));
        thread_pool[i]->number_id = i;
        thread_pool[i]->is_busy = 0;
        memset(thread_pool[i]->data, 0, sizeof(thread_pool[i]->data));
        
        ret = pthread_mutex_init(&(thread_pool[i]->f_lock),NULL);
        ASSERT(ret!=0, "Init f_lock %d error \n", i);
    }

    for (i=0;i<PROCESS_COUNT;i++)
    {
        ret=sem_init(&(thread_pool[i]->sem), 0, 0);
        ASSERT(ret==-1, "Init sem %d error \n", i);
    }

    for (i=0;i<PROCESS_COUNT;i++)
    {
        ret=pthread_create(&(thread_pool[i]->id), NULL, (void  *)workfunc, (void *)(&(thread_pool[i]->number_id)));
        ASSERT(ret!=0, "Create %d pthread error \n", i);
    }

    /* main loop: do thread dispatch */
    for (; do_exit==0 ;)
    {
        int r;
		char packet[MAX_BUF_SIZE];

		memset(packet, 0, sizeof(packet));

		//select read, to avoid read blocking. tlhhh 2010-8-4
        do
        {
#if 0
            r = nlink_recv(packet);
#else
			r = nlink_unblk_recv(packet);
#endif
        }
        while (r <= 0 && do_exit == 0);

		if( do_exit )	break;
		
        /* find an idle thread and dispatch it the packet */
        do
        {
            flag=0;

            for (i=0;i<PROCESS_COUNT;i++)
            {
				pthread_mutex_lock(&(thread_pool[i]->f_lock));

                //if (thread_pool[i]->is_busy == 0 && thread_pool[i]->data == NULL)
                if (thread_pool[i]->is_busy == 0)
                {
                    thread_pool[i]->is_busy = 1;
					memset(thread_pool[i]->data, 0, sizeof(thread_pool[i]->data));
                    memcpy(thread_pool[i]->data, packet, r);
                    
                    tm_dbg("Packet assigned thread %d to process", i);
                    
					ret = sem_post(&(thread_pool[i]->sem));
					ASSERT(ret==-1, "sem_post err: %s\n", strerror(errno));
					flag=1;
                }

                pthread_mutex_unlock(&(thread_pool[i]->f_lock));

                if (flag)
                {
                    break;
                }
            }
		}
        while (flag == 0 && do_exit == 0);
		
    }

	for( i=0; i<PROCESS_COUNT; i++) 
	{
		int sem_ret = -1;

		//Post semaphore to all work threads, let rating thread exit. tlhhh 2010-8-4
        pthread_mutex_lock(&(thread_pool[i]->f_lock));
		
		sem_ret = sem_post(&(thread_pool[i]->sem));
		ASSERT(sem_ret==-1, "sem_post err: %s\n", strerror(errno));
		
        pthread_mutex_unlock(&(thread_pool[i]->f_lock));

		//tlhhh 2010-8-4. main thread wait here to join all workfunc
		pthread_join(thread_pool[i]->id, NULL);
	}

	/* free all memories */
	for( i=0; i<PROCESS_COUNT; i++) 
	{
		if (thread_pool[i])
			free(thread_pool[i]);
	}

	if (thread_pool)
		free(thread_pool);


	nlink_fini();
	remove_pid(PROXY_PID_FILE);

	tm_dbg("nlinkd exiting gracefully ..");

    return	0;
}
