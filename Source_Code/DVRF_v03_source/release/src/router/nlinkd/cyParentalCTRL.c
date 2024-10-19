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


#include <bcmnvram.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <utils.h>

#include "nlinkd.h"
#include "cyParentalCTRL.h"

/*#if M_ROUTER*/
/*#include "tmPropAccess.h"*/
/*#endif*/


char *strcasestr(const char *haystack, const char *needle);

#define PASS_WITH_NO_MATCH 0
#define ALL_DAY_PASS "111111111111111111111111111111111111111111111111"  /* 48bits */
//#define BLOCK_BY_TIME 0
//#define BLOCK_BY_SITE 1
#define MAX_MAC_BLOCKED 10
#define ALL_DAY_BLOCK "000000000000000000000000000000000000000000000000"
#define MAX_POLICY_NUMBER 14
#define HTTP_PREFIX "http://"


#define URL_FILTER_NUMBER_MAX     20		//add by seal 100924
//char *block_url_list[MAX_POLICY_NUMBER][10];
char *block_url_list[MAX_POLICY_NUMBER][URL_FILTER_NUMBER_MAX];	//modify by seal 100924
char *block_mac_list[MAX_POLICY_NUMBER][MAX_MAC_BLOCKED];
int block_ip_list[MAX_POLICY_NUMBER][254];
int block_gn_ip_list[MAX_POLICY_NUMBER][254];
int policy_list[MAX_POLICY_NUMBER]={1,1,1,1,1,1,1,1,1,1,1,1,1,1};  /* Record the policy enabled or diabled */
extern unblock_t *unblock_list[MAX_POLICY_NUMBER];  // temp give 100 entry

char *get_strdel(char **src, char *delim )
{
    char *ptr, *ret;

    ptr = strstr( *src, delim );
    if( ptr == NULL )
        return NULL;
    *ptr = '\0';

    ret = *src;
    *src = ptr+ strlen(delim);

    return ret;
}

//add by seal 100917	---
#define MAX_DOMAIN_NAME_ARRAY 20
int del_oldestnode_over20(const char *mac)	//modify by seal 101011
//int del_oldestnode_over20(const char *mac, const char *url)
{
	if (mac == NULL)
		return 0;

	int policy = 0, cnt = 0;
	unsigned long min_value = ~0;//MAX
	unblock_t *prev_oldest = NULL, *cur_oldest = NULL;
	int policy_oldest = -1;

	for(policy=0; policy<MAX_POLICY_NUMBER; policy++)
	{
		unblock_t *tmp = unblock_list[policy];
		unblock_t *prev = NULL;
		while(tmp != NULL)
		{
		 	if (!strcasecmp(mac, tmp->mac)
			//				&& !strcasecmp(url, tmp->url)
			) {
				if (min_value > tmp->secs) {
					min_value = tmp->secs;
					cur_oldest = tmp;
					prev_oldest = prev;
					policy_oldest = policy;
				}	
					
				if (++ cnt >= MAX_DOMAIN_NAME_ARRAY) {
					pwarning("%s:%s: Over 20 domain names per device\n", __FILE__, __FUNCTION__);
					//del the oldest node
					if (NULL == prev_oldest) {//first node	
						unblock_list[policy_oldest] = cur_oldest->next;
						free(cur_oldest);
					} else {
						prev_oldest->next = cur_oldest->next;
						free(cur_oldest);
					}	
					return 1;
				}
			} 
			prev = tmp;
			tmp = tmp->next;
		}
        }
	pdebug("%s:%s: device:%s-url:%d\n", __FILE__, __FUNCTION__, mac, cnt);
	return 1;
}
//add by seal 100917	+++

//void find_space(unblock_t* element)
int find_space(unblock_t* element)	//modify by seal 100917
{
	int policy=element->policy;
	time_t now;
	unblock_t *tmp = unblock_list[policy];
	unblock_t *prev = NULL;

	//add by seal 101011	------------
	del_oldestnode_over20(element->mac);	//modify by seal 101011
	//add by seal 101011	++++++++++++	

	time_wrap_new(&now);
	
	if(tmp != NULL)
	{  // if this policy is not empty
		while(tmp != NULL)
		{
			if ( (element->srcip != 0 && tmp->srcip == element->srcip) 
					//|| (element->mac != NULL && !strcasecmp(element->mac, tmp->mac)) /*&& element->flag == tmp->flag*/)
					||  (element->mac != NULL && !strcasecmp(element->mac, tmp->mac) && element->url != NULL && !strcasecmp(element->url, tmp->url)))		//modify by seal 100908
				
			{  // policy matched.
/*
				if(prev == NULL)
				{  // this element is the first one of this policy.
					free(tmp);
					unblock_list[policy] = element;
					return;
				}
				else
				{
					prev->next = element; 
					element->next = tmp->next;
					free(tmp);
					return;
				}
*/
				tmp->secs = element->secs;
				return 1;	//modify by seal 100917
			}
			prev = tmp;
			tmp = tmp->next;
		}
		prev->next = element;
	}
	else
		unblock_list[policy] = element;
	
	return 1;	//add by seal 100917
}

//fix the IR-B0013186 GetWanAccessStatus show wrong status of HasWanAccess at 20091105
void dump_to_file()
{
	FILE *fp = fopen("/tmp/unblock.list", "w");
	if(fp == NULL)
		return;
	int policy = 0;
	for(policy=0; policy<MAX_POLICY_NUMBER; policy++)
	{
		unblock_t *tmp = unblock_list[policy];
		while(tmp != NULL)
		{
			//fprintf(fp, "%d %s %ld\n", policy, tmp->mac, tmp->secs);
			//fprintf(fp, "%d %s %s %ld\n", policy, tmp->mac, tmp->url, tmp->secs);	//modify by seal 100917
			fprintf(fp, "%d %s %s %ld %d\n", policy, tmp->mac, tmp->url, tmp->secs, tmp->flag);	//modify by seal 101009
			tmp = tmp->next;
		}
	}
	fclose(fp);
}

/* Signal handler 
 * Create a structure to store Unblock info. */
void unblockCTRL(int signo)
{
	time_t time_now;
	
	time_wrap_new(&time_now);
	
	unblock_t *now = malloc(sizeof(unblock_t));
	if(now == NULL)
		return;
	now->policy = atoi(nvram_safe_get("hnd_unblock_policy"))-1;
//	now->secs = time_now + (unsigned long)atoi(nvram_safe_get("hnd_unblock_secs"));
	now->secs = time_now + 3600;  // 1 hr
//	now->secs = time_now + 600;	//3600;  //10min, 1 hr	//modify by seal 100917	for test
	now->srcip = atoi(nvram_safe_get("hnd_unblock_ip"));
	strncpy(now->mac, nvram_safe_get("hnd_unblock_mac"), 18);
	now->flag = atoi(nvram_safe_get("hnd_unblock_flag"));
	now->next = NULL;
	
	//add by seal 100917	----
	char *pos, *block_url;
	block_url = nvram_safe_get("hnd_unblock_url");
	block_url = block_url + 7;	//del "http://"
	//printf("block:%s---unblock:%s\n", nvram_safe_get("hnd_block_url"), nvram_safe_get("hnd_unblock_url"));
	if ((pos = strchr(block_url, '/')) != NULL) {// '/'
		if ((pos - block_url) > MAX_DOMAIN_NAME_LEN) {
			printf("len: %d\n", pos-block_url);
			goto EXIT_ERROR;
		}
		strncpy(now->url, block_url, pos-block_url);
		now->url[pos-block_url]=0;
	} else {
		if (strlen(block_url) > MAX_DOMAIN_NAME_LEN) {
			goto EXIT_ERROR;
		}
		strcpy(now->url, block_url);
	}
	//add by seal 100917	++++

	if (find_space(now) == 0) {	//modify by seal 100917
		goto EXIT_ERROR1;
	}

	//find_space(now);
//fix the IR-B0013186 GetWanAccessStatus show wrong status of HasWanAccess at 20091105
	dump_to_file();  // dump all unblock list to file

	//add by seal 100917	----
	return ;
EXIT_ERROR:
	pwarning("Length of domain name is over(%s)!\n", block_url);
EXIT_ERROR1:
	free(now);
	return ;
	//add by seal 100917	++++
}

/* Check Unblock or now
 * If unblock, return 1
 * If block still, return 0 */
//int check_unblock(int flag, int policy, unsigned int srcip, const char *mac, unsigned long time_now)
int check_unblock(int flag, int policy, const char *mac, const char *url, unsigned long time_now)	//add by seal 100917
{
	unblock_t *tmp = unblock_list[policy];
	unblock_t *prev = NULL;
	
	if(tmp != NULL)
	{  // if this policy is not empty
		while(tmp != NULL)
		{
			//if((tmp->srcip == srcip || !strcasecmp(mac, tmp->mac)) /*&& tmp->flag == flag*/)
			if(!strcasecmp(mac, tmp->mac) && !strcasecmp(url, tmp->url)	//modify by seal 100917
					/*|| tmp->srcip == srcip*/)
			{  // policy matched, also figure out figure out block by time or site
				if(tmp->secs < time_now)
				{  // expired.
					if(prev == NULL)
					{  // this element is the first one of this policy.
						unblock_list[policy] = tmp->next;
						free(tmp);
						return 0;
					}
					else
					{
						prev->next = tmp->next; 
						free(tmp);
						tmp = prev->next;
					}
				}
				else
					return 1;  // Unblock
			}
			else
			{
				prev = tmp;
				tmp = tmp->next;
			}
		}
	}
	return 0; // No unblock setting found.
}

/* Check the IP and Mac
 * If matched, return 1
 * If not matched, return 0 */
int checkIPMAC(int policy, unsigned int srcip, const char* mac, int gn_flag)
{
	int ip_list_number = 0;
	int mac_list_number = 0;
	
	if(srcip)
	{
		if(gn_flag == 0)
		{
			while (ip_list_number < 255 && block_ip_list[policy][ip_list_number] != 0)
			{
				if(srcip == block_ip_list[policy][ip_list_number])
					return 1;  /* Bingo */
				else
					ip_list_number++;
			}
		}
		else
		{
			while (ip_list_number <255 && block_gn_ip_list[policy][ip_list_number] != 0)
			{
				if(srcip == block_gn_ip_list[policy][ip_list_number])
					return 1;  /* Bingo */
				else
					ip_list_number++;
			}
		}
	}
	while ( mac_list_number < MAX_MAC_BLOCKED && block_mac_list[policy][mac_list_number] != NULL)
	{
		if(!strcasecmp(mac, block_mac_list[policy][mac_list_number]))
			return 1;  /* Bingo */
		else
			mac_list_number++;
	}
	return 0;  /* No match */
}

/* Check the url and host
 * If matched, return 1(BLOCK)
 * If not matched, return 0(PASS) */
int checkURL(int policy, const char* incoming)
{
#if 0	// New requirement
	int index,list_number = 0;
	//while (list_number <10 && block_url_list[policy][list_number] != NULL)
	while (list_number < URL_FILTER_NUMBER_MAX && block_url_list[policy][list_number] != NULL)	//modify by seal 100924
	{
		if(!strcasecmp(incoming, block_url_list[policy][list_number]))
		{
			return BLOCK_BY_SITE;  /* Bingo! HEAD matched */
		}

		index = strlen(incoming) - strlen(block_url_list[policy][list_number]);
		if((index > 0) && (incoming[index-1] == '.') && (!strcasecmp(&incoming[index],block_url_list[policy][list_number])) )
		{
			return BLOCK_BY_SITE;  /* Bingo! body matched */
		}
		list_number++;
	}
	return PASS_WITH_NO_MATCH;
#else	// G5 spec use old algorithm
	int list_number = 0;
	//while (list_number < 10 && block_url_list[policy][list_number] != NULL)
	while (list_number < URL_FILTER_NUMBER_MAX && block_url_list[policy][list_number] != NULL)	//modify by seal 100924
	{
		tm_dbg("incoming=%s, block_url_list=%s", incoming, block_url_list[policy][list_number]);

/* 2011-09-13, CBTS#28016: use Parental Control to block specific site (IPv6 address) doesn't take effect */
#if 0
		if(!strncasecmp(incoming, block_url_list[policy][list_number], strlen(block_url_list[policy][list_number])))
#else
		char *host_url;
		if (incoming[0] == '[') {
		/* If host url is IPv6 address, ex: [ A:B:C:D:E:F:G:H ], skip the first '[' character... */
			host_url = incoming + 1;
		} else
			host_url = incoming;
	
		if( !strncasecmp(host_url, url_escape(block_url_list[policy][list_number]), strlen(block_url_list[policy][list_number])))
#endif //0
		{
			return BLOCK_BY_SITE;  /* Bingo! HEAD matched */
		}
		char *tmp = strcasestr(incoming, block_url_list[policy][list_number]);
        while (tmp != NULL )
		{
			char *ptr = tmp - 1;
			if(ptr != NULL)  // Basically, ptr always is not NULL
				if(*ptr == '.')
				{
					return BLOCK_BY_SITE;  /* Bingo! body matched */
				}
			//tmp = strcasestr(tmp, incoming);
            tmp = tmp + strlen(block_url_list[policy][list_number]);
            tmp = strcasestr(tmp, block_url_list[policy][list_number]);
		}
		list_number++;
	}
	return PASS_WITH_NO_MATCH;
#endif
}

//add by seal 100923	--------------------------------
#ifdef PARENTAL_CONTROL_ALLOWEDLIST_SUPPORT 	//add by seal 100908
#if (LINKSYS_MODEL == WRT120N_M10) || (LINKSYS_MODEL == WRT120N_M10V2) || (LINKSYS_MODEL == WRT310NV2_M20)
#define PASS_BY_SITE 1
#define NO_MATCH 0
#define URL_ALLOWED_NUMBER_MAX 10
char *allowed_url_list[MAX_POLICY_NUMBER][URL_ALLOWED_NUMBER_MAX];
int checkWList_Url(int policy, const char* incoming)
{
	int list_number = 0;
	//printf("Enter %s\n", __FUNCTION__);
	while (list_number < URL_ALLOWED_NUMBER_MAX && allowed_url_list[policy][list_number] != NULL)	//modify by seal 100907
	{
		if(!strncasecmp(incoming, allowed_url_list[policy][list_number], strlen(allowed_url_list[policy][list_number])))
		{
			//printf("Pass\n");
			return PASS_BY_SITE;  /* Bingo! HEAD matched */
		}
		char *tmp = strcasestr(incoming, allowed_url_list[policy][list_number]);
		while (tmp != NULL)
		{
			char *ptr = tmp - 1;
			if(ptr != NULL)  // Basically, ptr always is not NULL
				if(*ptr == '.')
					return PASS_BY_SITE;  /* Bingo! body matched */
			tmp = strcasestr(tmp, incoming);
		}
		list_number++;
	}
	//printf("No match\n");
	return NO_MATCH;
}

/* Check the url and host
 *  * If matched, return 1(Bypass)
 *   * If not matched, return 0 */
int checkWList(const char *mac, const char* incoming)
{
	int IPMACMatched = 0;
	int policy_number = 0;
	for(policy_number=0; policy_number<MAX_POLICY_NUMBER; policy_number++)
	{
		if(policy_list[policy_number]==0)
			continue;

		if(checkIPMAC(policy_number, mac))  /* STEP1. Check IP list */
		{	/* STEP2. IP matched, check time range */
			IPMACMatched = 1;

			if(checkWList_Url(policy_number, incoming) == PASS_BY_SITE)
				return PASS_BY_SITE;
		}
	}
#if M_ROUTER
	if(IPMACMatched == 0)
	{  // There is no IP or MAC matched, check default policy.
		char *nvstr_default = nvram_safe_get("hnd_filter_default_num");
		int default_policy = (nvstr_default != "") ? atoi(nvstr_default)-1 : TMHRS_DEFAULT_PROFILE-1;  // IR-B0013453

		if(policy_list[default_policy]==1)
		{
				if(checkWList_Url(default_policy, incoming) == PASS_BY_SITE)
				return PASS_BY_SITE;
		}
		else 
			return NO_MATCH;
	}
#endif
	return NO_MATCH;
}
#endif
#endif
//add by seal 100923	+++++++++++++++++++++++++++++++++++


char * get_policy_weekday(struct tm *local, int policy)
{
	static char weekday[49];
	char nvstr_weekday[20];
	char *week[7] = {"sun", "mon", "tue", "wed", "thu", "fri", "sat"};

	if(local->tm_year == 0) {  /* NTP client cannot get time */
		int i;
		for(i=0; i<7; i++)
		{
			sprintf(nvstr_weekday, "hnd_filter_%s%d", week[i], policy+1);
			if(strcmp(ALL_DAY_BLOCK, nvram_safe_get(nvstr_weekday)))
			//if(strcmp(ALL_DAY_BLOCK, access_schedule_hex2bin( nvram_safe_get(nvstr_weekday)) ))
				break;
		}
		if(i == 7)
			strcpy(weekday, ALL_DAY_BLOCK);
		else
			strcpy(weekday, ALL_DAY_PASS);
	}
	else {
		bzero(nvstr_weekday, sizeof(nvstr_weekday));
		switch(local->tm_wday) {
			case 0:
			case 1:
			case 2:
			case 3:
			case 4:
			case 5:
			case 6:
				sprintf(nvstr_weekday, "hnd_filter_%s%d", week[local->tm_wday], policy+1);
				break;
			default:
				strcpy(weekday, ALL_DAY_PASS);
				break;
		}
		strcpy(weekday, nvram_safe_get(nvstr_weekday));
		//strcpy(weekday, access_schedule_hex2bin( nvram_safe_get(nvstr_weekday) ));
	}
	return weekday;
}

//int CheckTimeBlock(const char *mac, unsigned int srcip)
int CheckTimeBlock(const char *mac, const char *url, unsigned int srcip)	//add by seal 100917
{
	int policy_number = 0;
	int IPMACMatched = 0;
	char *weekday = ALL_DAY_BLOCK;
	time_t secs_now;
	struct tm *local;

	time_wrap_new(&secs_now);
	local = localtime(&secs_now);

	/* Find the time section(0~47, 1 for 30min) right now */
	int time_now=0;
	time_now = local->tm_hour * 2;

	if(local->tm_year < 110)	/* 2010 */
		return PASS_WITH_NO_MATCH;	/* Cannot get time from NTP server */
	else if(local->tm_min >= 30)
		time_now = time_now + 1;

//	int flag_match_Whitelist=0;
//	if( checkLinksysWList(http_message->host, "") != 0 )  { flag_match_Whitelist = 1; }

	for(policy_number=0; policy_number<MAX_POLICY_NUMBER; policy_number++)
	{
		if(policy_list[policy_number]==0)
			continue;

		if(checkIPMAC(policy_number, srcip, mac, 0))  /* STEP1. Check IP list */
		{	/* STEP2. IP matched, check time range */
			IPMACMatched = 1;

			weekday = get_policy_weekday(local, policy_number);
			if(local->tm_year >= 110 && weekday[time_now] == '0')	/* If NTP server is available and time to block */
			{	/* Time to BLOCK */
				//if(check_unblock(BLOCK_BY_TIME, policy_number, srcip, mac, secs_now)){
				if(check_unblock(BLOCK_BY_TIME, policy_number, mac, url, secs_now)){	//modify by seal 100917
//					if(checkURL(policy_number, http_message->host)
//						&& !check_unblock(BLOCK_BY_SITE, policy_number, srcip, http_message->pszMAC, secs_now)) /* STEP3. Check URL entries */
//						return (policy_number+1)  | REASON_URL;
					continue;
				}
				else
					return (policy_number+1);
			}
		}
   }

#if M_ROUTER
	if(IPMACMatched == 0)
	{  
		// There is no IP or MAC matched, check default policy.
		char *nvstr_default = nvram_safe_get("hnd_filter_default_num");
		int default_policy = (nvstr_default != "") ? atoi(nvstr_default)-1 : TMHRS_DEFAULT_PROFILE-1;  // IR-B0013453

		if(policy_list[default_policy]==1)
		{
			weekday = get_policy_weekday(local, default_policy);
			if(local->tm_year >= 110 && weekday[time_now] == '0')
			{	/* Time to BLOCK */
				//if(check_unblock(BLOCK_BY_TIME, default_policy, srcip, mac, secs_now)){
				if(check_unblock(BLOCK_BY_TIME, policy_number, mac, url, secs_now))	//modify by seal 100917
				{
//					if(checkURL(default_policy, http_message->host)
//						&& !check_unblock(BLOCK_BY_SITE, default_policy, srcip, http_message->pszMAC, secs_now)) /* STEP3. Check URL entries */
//						return (default_policy+1)  | REASON_URL;
					/* No operation */;
				}
				else
					return (default_policy+1);
			}
		}
		else
			return PASS_WITH_NO_MATCH;  // THe defualt policy is disabled.
	}
#endif //LINKSYS_MODEL

   return PASS_WITH_NO_MATCH;
}

/* Main process here
 * return 1 as BLOCKED, 0 as PASS */
int ParetanlCTRL(http_message_t *http_message, unsigned int srcip, int gn_flag)
{
	int policy_number = 0;
	int IPMACMatched = 0;
	char weekday[49];
	char nvstr_weekday[20];
	time_t secs_now;
	struct tm *local;
	char *week[7] = {"sun", "mon", "tue", "wed", "thu", "fri", "sat"};
	
	time_wrap_new(&secs_now);
	local = localtime(&secs_now);

	/* 2009.10.29  update whitelist rev1.5 by Elijah.Tsai */
	int flag_match_Whitelist = 0;
	if(check_white_list(http_message->host,"") != 0) { flag_match_Whitelist = 1; }

	//modified by michael to fix the MaxPolicy can't be use at 20091026	
	for(; policy_number<MAX_POLICY_NUMBER; policy_number++)
	{		
		if(policy_list[policy_number]==0)
			continue;
		
		if(local->tm_year == 0) {  /* NTP client cannot get time */
			int i;
			for(i=0; i<7; i++)
			{
				sprintf(nvstr_weekday, "hnd_filter_%s%d", week[i], policy_number+1);
				if(strcmp(ALL_DAY_BLOCK, nvram_safe_get(nvstr_weekday)))
					break;
			}
			if(i == 7)
				strcpy(weekday, ALL_DAY_BLOCK);
			else
				strcpy(weekday, ALL_DAY_PASS);
		}
		else {
			bzero(nvstr_weekday, sizeof(nvstr_weekday));
			switch(local->tm_wday) {
				case 0:
				case 1:
				case 2:
				case 3:
				case 4:
				case 5:
				case 6:
					sprintf(nvstr_weekday, "hnd_filter_%s%d", week[local->tm_wday], policy_number+1);
					break;
				default:
					strcpy(weekday, ALL_DAY_PASS);
					break;
			}
			strcpy(weekday, nvram_safe_get(nvstr_weekday));
		}
		
		if(checkIPMAC(policy_number, srcip, http_message->pszMAC, gn_flag))  /* STEP1. Check IP list */
		{	/* STEP2. IP matched, check time range */
			int time_now=0;
			
			IPMACMatched = 1;
			/* Find the time section(0~47, 1 for 30min) right now */
			time_now = local->tm_hour * 2;
			if(local->tm_min >= 30)
				time_now = time_now + 1;
			
			if(local->tm_year >= 110 && weekday[time_now] == '0')
			{	/* Time to BLOCK */
				//if(check_unblock(BLOCK_BY_TIME, policy_number, srcip, http_message->pszMAC, secs_now)){
				if(check_unblock(BLOCK_BY_TIME, policy_number, http_message->pszMAC, http_message->host, secs_now)){	//modify by seal 100917
					tm_dbg("mac:%s, host:%s matched [unblock list]\n", http_message->pszMAC, http_message->host);
//					if(checkURL(policy_number, http_message->host)
//						&& !check_unblock(BLOCK_BY_SITE, policy_number, srcip, http_message->pszMAC, secs_now)) /* STEP3. Check URL entries */
//						return (policy_number+1)  | REASON_URL; 
					continue;
				}
				else
				{
					tm_dbg("mac:%s, host:%s UNmatched [unblock list]\n", http_message->pszMAC, http_message->host);
					return (policy_number+1);
				}
			}
			else  
			{	/* Time to PASS */
				/* 2009.10.29  update whitelist rev1.5 by Elijah.Tsai */
				if( flag_match_Whitelist == 1) continue;
				if(checkURL(policy_number, http_message->host)
					//&& !check_unblock(BLOCK_BY_SITE, policy_number, srcip, http_message->pszMAC, secs_now))  /* STEP3. Check URL entries */
					&& !check_unblock(BLOCK_BY_SITE, policy_number, http_message->pszMAC, http_message->host, secs_now))  /* STEP3. Check URL entries */		//modify by seal 100917
					{
						tm_dbg("mac:%s, host:%s UNmatched [url list] && UNmatched [unblock list]==BLOCK\n", http_message->pszMAC, http_message->host);
					return (policy_number+1)  | REASON_URL;  
					}
			}
		}
	}
	if(IPMACMatched == 0)
	{  // There is no IP or MAC matched, check default policy.
		int default_policy = 0;
		char *nvstr_default = nvram_safe_get("hnd_filter_default_num");
		
		if(nvstr_default != "")
			default_policy = atoi(nvstr_default)-1;
		else
			return PASS_WITH_NO_MATCH;  // No default policy set in nvram.
		
		if(policy_list[default_policy]==1)
		{
			bzero(weekday, sizeof(weekday));
			if(local->tm_year == 0) {  /* NTP client cannot get time */
				int i;
				for(i=0; i<7; i++)
				{
					sprintf(nvstr_weekday, "hnd_filter_%s%d", week[i], policy_number+1);
					if(strcmp(ALL_DAY_BLOCK, nvram_safe_get(nvstr_weekday)))
						break;
				}
				if(i == 7)
					strcpy(weekday, ALL_DAY_BLOCK);
				else
					strcpy(weekday, ALL_DAY_PASS);
			}
			else {
				bzero(nvstr_weekday, sizeof(nvstr_weekday));
				switch(local->tm_wday) {
					case 0:
					case 1:
					case 2:
					case 3:
					case 4:
					case 5:
					case 6:
						sprintf(nvstr_weekday, "hnd_filter_%s%d", week[local->tm_wday], policy_number+1);
						break;
					default:
						strcpy(weekday, ALL_DAY_PASS);
						break;
				}
				strcpy(weekday, nvram_safe_get(nvstr_weekday));
			}
			
			int time_now=0;
			
			/* Find the time section(0~47, 1 for 30min) right now */
			time_now = local->tm_hour * 2;
			if(local->tm_min >= 30)
				time_now = time_now + 1;
			
			if(local->tm_year >= 110 && weekday[time_now] == '0')
			{	/* Time to BLOCK */
				//if(check_unblock(BLOCK_BY_TIME, default_policy, srcip, http_message->pszMAC, secs_now)){
				if(check_unblock(BLOCK_BY_TIME, default_policy, http_message->pszMAC, http_message->host, secs_now)){	//modify by seal 100917
//					if(checkURL(default_policy, http_message->host)
//						&& !check_unblock(BLOCK_BY_SITE, default_policy, srcip, http_message->pszMAC, secs_now)) /* STEP3. Check URL entries */
//						return (default_policy+1)  | REASON_URL; 
					/* No operation */;
				}
				else
					return (default_policy+1);
			}
			else  
			{	/* Time to PASS */
				/* 2009.10.29  update whitelist rev1.5 by Elijah.Tsai */
				if( flag_match_Whitelist == 1) return PASS_WITH_NO_MATCH;
				if(checkURL(default_policy, http_message->host)
					//&& !check_unblock(BLOCK_BY_SITE, default_policy, srcip, http_message->pszMAC, secs_now))  /* STEP3. Check URL entries */
					&& !check_unblock(BLOCK_BY_SITE, default_policy, http_message->pszMAC, http_message->host, secs_now))  /* STEP3. Check URL entries */	//modify by seal 100917
					return (default_policy+1)  | REASON_URL;  
			}
		}
		else
			return PASS_WITH_NO_MATCH;  // THe defualt policy is disabled.
	}
	return PASS_WITH_NO_MATCH;
}

void scan_ip_list(int type, int policy_number)
{
	char nvstr_ip[32], buf[200];
	int list_number=0;
	int home_ip[30];
	int guest[30];
	int i;
	
	bzero(nvstr_ip, sizeof(nvstr_ip));
	bzero(buf, sizeof(buf));
	if(type == 0)
	{
		memset(block_ip_list[policy_number], 0,sizeof(int) * 254);
		memset(home_ip,0,sizeof(int) * 30);
		sprintf(nvstr_ip, "%s%d", "hnd_filter_ip_grp", policy_number+1);  // hnd_filter_ip1~hnd_filter_ip14
		strcpy(buf, nvram_safe_get(nvstr_ip));
		if(strlen(buf) != 0)
		{
			int temp;
			temp = sscanf(buf, "%d %d %d %d %d %d %d %d %d %d %d-%d %d-%d %d-%d %d-%d %d-%d %d-%d %d-%d %d-%d %d-%d %d-%d "
					, &home_ip[0], &home_ip[1], &home_ip[2], &home_ip[3], &home_ip[4], &home_ip[5], &home_ip[6], &home_ip[7], 
					&home_ip[8], &home_ip[9], &home_ip[10], &home_ip[11], &home_ip[12], &home_ip[13], &home_ip[14], &home_ip[15], 
					&home_ip[16], &home_ip[17], &home_ip[18], &home_ip[19], &home_ip[20], &home_ip[21], &home_ip[22], &home_ip[23], 
					&home_ip[24], &home_ip[25], &home_ip[26], &home_ip[27], &home_ip[28], &home_ip[29]);
		
			for(i=0; i<30; i++)
			{
				if( i<10 && home_ip[i] != 0)
				{
					//check whether the ip is in the block ip list already
					int j;
					int ip_existed = 0;
					for(j=0; j<list_number; j++)
					{
						if(block_ip_list[policy_number][j] == home_ip[i])
						{
							ip_existed = 1;
							break;
						}	
					}
					if( ip_existed == 1)	//already in the block ip list, ignore and go the new next one 
						continue;

					block_ip_list[policy_number][list_number] = home_ip[i];
					list_number++;
				}
				else if(i >= 10 && home_ip[i] != 0 && home_ip[i+1] != 0)
				{
					while(home_ip[i] <= home_ip[i+1])
					{
						//check whether the ip is in the block ip list already
						int j;
						int ip_existed = 0;
						for(j=0; j<list_number;j++)
						{
							if(block_ip_list[policy_number][j] == home_ip[i])
							{
								ip_existed = 1;
								break;
							}
						}
						if(ip_existed == 1)	// ip is in the list , go to the next one
						{
							home_ip[i]++;
							continue;
						}

						block_ip_list[policy_number][list_number] = home_ip[i];
						home_ip[i]++;
						list_number++;
					}
					i = i+1;
				}
			}
		}
	}
	else
	{
		memset(block_gn_ip_list[policy_number],0,sizeof(int) * 254);
		memset(guest,0,sizeof(int) * 30);
		sprintf(nvstr_ip, "%s%d", "hnd_filter_gn_ip_grp", policy_number+1);  // hnd_filter_gn_ip1~hnd_filter_gn_ip14
		strcpy(buf, nvram_safe_get(nvstr_ip));
		if(strlen(buf) != 0)
		{
			sscanf(buf, "%d %d %d %d %d %d %d %d %d %d %d-%d %d-%d %d-%d %d-%d %d-%d %d-%d %d-%d %d-%d %d-%d %d-%d ", 
					&guest[0], &guest[1], &guest[2], &guest[3], &guest[4], &guest[5], &guest[6], &guest[7], &guest[8], &guest[9], 
					&guest[10], &guest[11], &guest[12], &guest[13], &guest[14], &guest[15], &guest[16], &guest[17],&guest[18], &guest[19],
					&guest[20], &guest[21], &guest[22], &guest[23], &guest[24], &guest[25], &guest[26], &guest[27],&guest[28], &guest[29]);
					
			for(i=0; i<30; i++)
			{
				if( i<10 && guest[i] != 0)
				{
					//check whether the ip is in the block ip list already
					int j;
					int ip_existed = 0;
					for(j=0; j<list_number; j++)
					{
						if(block_gn_ip_list[policy_number][j] == guest[i])
						{
							ip_existed = 1;
							break;
						}	
					}
					if( ip_existed == 1)	//already in the block ip list, ignore and go the new next one 
						continue;

					block_gn_ip_list[policy_number][list_number] = guest[i];
					list_number++;
				}
				else if(i >= 10 && guest[i] != 0 && guest[i+1] != 0)
				{
					while(guest[i] <= guest[i+1])
					{
						//check whether the ip is in the block ip list already
						int j;
						int ip_existed = 0;
						for(j=0; j<list_number;j++)
						{
							if(block_gn_ip_list[policy_number][j] == guest[i])
							{
								ip_existed = 1;
								break;
							}
						}
						if(ip_existed == 1)	// ip is in the list , go to the next one
						{
							guest[i]++;
							continue;
						}

						block_gn_ip_list[policy_number][list_number] = guest[i];
						guest[i]++;
						list_number++;
					}
					i = i+1;
				}
			}
		}
	}
}

//add by seal 100917 for test	----
//#define NEW_FEATURE_TEST
#ifdef NEW_FEATURE_TEST
void dump_to_stdio()
{
	int policy = 0;
	printf("%s:%s: unblock list:\n", __FILE__, __FUNCTION__);
	for(policy=0; policy<MAX_POLICY_NUMBER; policy++)
	{
		unblock_t *tmp = unblock_list[policy];
		while(tmp != NULL)
		{
			//fprintf(fp, "%d %s %ld\n", policy, tmp->mac, tmp->secs);
			//printf("%d %s %s %ld\n", policy, tmp->mac, tmp->url, tmp->secs);	//modify by seal 100917
			printf("%d %s %s %ld %d\n", policy, tmp->mac, tmp->url, tmp->secs, tmp->flag);	//modify by seal 100917
			tmp = tmp->next;
		}
	}

#ifdef PARENTAL_CONTROL_ALLOWEDLIST_SUPPORT
#if M_ROUTER
	printf("%s:%s: allowed list:\n", __FILE__, __FUNCTION__);
	for(policy=0; policy<MAX_POLICY_NUMBER; policy++)
	{
		unblock_t *tmp = allowed_url_list[policy];
		int list_number = 0;
		while(list_number < 10 && allowed_url_list[policy][list_number] != NULL)
		{
			printf("%d:%s\n", policy, allowed_url_list[policy][list_number]);	//modify by seal 100923
			list_number++;
		}
	}
#endif
#endif
}

#include <signal.h>
void signal_dump(int sig)
{
	switch(sig) {
	case SIGUSR2:
		dump_to_stdio();
		break;
	default:
		break;
	}
}
#endif
//add by seal 100917 for test	++++

void initlist()
{
	//fix by michael to extend the length of the string to avoid the error at 20091026 for strlen("hnd_filter_web_url14") is 20.
	char nvstr_url[32], nvstr_mac[32],  nvstr_policy[32];
	int policy_number = 0;
	char nvram_policy[50];  /* data type: $STAT:1$NAME:Kids */

#ifdef NEW_FEATURE_TEST
	signal(SIGUSR2, signal_dump);	//add by seal 100917 	for test
#endif

	nvram_safe_unset("hnd_unblock_mac");
	nvram_safe_unset("hnd_wtp_url");
	if(nvram_match("unblock_reset", "1"))
	{
		system("rm -f /tmp/unblock.list");  /* important! Make HNAP GetWANAccessStatus correct */
		nvram_set("unblock_reset", "0");
	}
	else
	{
		FILE *unblock_list = fopen("/tmp/unblock.list", "r");
		if(unblock_list)
		{
			int policy;
			char mac[18];
			char url[MAX_DOMAIN_NAME_LEN + 1];	//add by seal 100917
			unsigned long deadline;
			time_t time_now;
			int flag;	//add by seal 101009
			
			time_wrap_new(&time_now);
			
			while(!feof(unblock_list))
			{
				//if(fscanf(unblock_list, "%d%s%ld", &policy, mac, &deadline) == -1) 
 				//if(fscanf(unblock_list, "%d%s%s%ld", &policy, mac, url, &deadline) == -1) //modify by seal 100917
 				if(fscanf(unblock_list, "%d%s%s%ld%d", &policy, mac, url, &deadline, &flag) == -1) //modify by seal 100917
					break;
				if(deadline > time_now)  // The unblock device which is still in unblock period.
				{
					unblock_t *now = malloc(sizeof(unblock_t));
					if(now == NULL)
						break;
					now->policy = policy;
					now->secs = deadline;  // Record the deadline
					now->srcip = 0;
					strncpy(now->mac, mac,18);
					strcpy(now->url, url);	//add by seal 100917
					//now->flag = 0;  // No use right now;
 					now->flag = flag;  //modify by seal 101009
					now->next = NULL;
					
					//find_space(now);
					if (find_space(now) == 0) {	//modify by seal 100917
						free(now);	//never
						continue;
					}

//#if M_ROUTER
#if 0	//removed by tlhhh. E-series do _not_ need this.
					/* Write tmsss.conf to Make Category block PASS */
					int i = 1, ret = 0;
					for ( i = 1 ; -1 != ret ; i++ )
					{
						ret = set_client_expired_time(now->mac, i, now->secs);     // -1 if error
						if(ret == 0)
							break;
					}
					tmLoadClientTable();
#endif
				}
			}
			fclose(unblock_list);
		}
	}

	
//	memset(policy_list, 1, 14);
	for(; policy_number<MAX_POLICY_NUMBER; policy_number++)
	{
		char buf[1000] = "";
		char *tmp = NULL;
		char *token = NULL;
		int list_number = 0;

		bzero(nvstr_url, sizeof(nvstr_url));
		bzero(nvstr_mac, sizeof(nvstr_mac));

		/* Policy */
		bzero(nvstr_policy, sizeof(nvstr_policy));
		sprintf(nvstr_policy, "%s%d", "hnd_filter_rule", policy_number+1);

		bzero(nvram_policy, sizeof(nvram_policy));
		strcpy(nvram_policy, nvram_safe_get(nvstr_policy));
		if(nvram_policy[6]!='1') {  /* $STAT:0, disable this policy and parse next one */
			policy_list[policy_number] = 0;
			continue;
		}

		/* URL */
		sprintf(nvstr_url, "%s%d", "hnd_filter_web_url", policy_number+1);  // hnd_filter_url1~hnd_filter_url14
		strcpy(buf, nvram_safe_get(nvstr_url));
		tmp = buf;
		list_number=0;
		token = get_strdel(&tmp, "<&nbsp;>");
		while(token != NULL)
		{
			char *lastchar;
			char *pureurl = strcasestr(token, HTTP_PREFIX);
			block_url_list[policy_number][list_number] = malloc(64);
			if (pureurl)
				token = pureurl + strlen(HTTP_PREFIX);

			lastchar = token + strlen(token) - 1;  /* lastchar = The last position of the string */
			if (*lastchar == '/')
				*lastchar = '\0';
			strcpy(block_url_list[policy_number][list_number], token);
			list_number++;
			token = get_strdel(&tmp, "<&nbsp;>");
		}
		
#ifdef PARENTAL_CONTROL_ALLOWEDLIST_SUPPORT 	//add by seal 100923
#if M_ROUTER
//add by seal 100923 -----------------------------
		/* White URL */
		bzero(nvstr_url, sizeof(nvstr_url));
		sprintf(nvstr_url, "%s%d", "hnd_filter_allowed_url", policy_number+1);  // hnd_filter_url1~hnd_filter_url14
		strcpy(buf, nvram_safe_get(nvstr_url));
		tmp = buf;
		list_number=0;
		if (*tmp != '\0')
		{
			token = get_strdel(&tmp, "<&nbsp;>");
			while(token != NULL)
			{
				char *lastchar;
				char *pureurl = strcasestr(token, HTTP_PREFIX);//sync from ethan by seal 100624
				allowed_url_list[policy_number][list_number] = malloc(64);
				if (pureurl)
					token = pureurl + strlen(HTTP_PREFIX);

				lastchar = token + strlen(token) - 1;  /* lastchar = The last position of the string */
				if (*lastchar == '/')
					*lastchar = '\0';
				strcpy(allowed_url_list[policy_number][list_number], token);

				list_number++;
				token = get_strdel(&tmp, "<&nbsp;>");
			}
		}
#endif
#endif
//add by seal 100923 +++++++++++++++++++++++++++++ 

		/* MAC */
		sprintf(nvstr_mac, "%s%d", "hnd_filter_mac_grp", policy_number+1);  // hnd_filter_mac1~hnd_filter_mac14
		bzero(buf, sizeof(buf));
		strcpy(buf, nvram_safe_get(nvstr_mac));
		/* FIXME: what is this ??? */
		sprintf(buf, "%s ", buf);
		tmp = buf;
		list_number=0;
		if(*tmp != '\0') /*Something is set in URLblocking*/
		{
			token = get_strdel(&tmp, " ");
			while(token != NULL)
			{
				block_mac_list[policy_number][list_number] = malloc(18);
				strcpy(block_mac_list[policy_number][list_number], token);
				list_number++;
				token = get_strdel(&tmp, " ");
			}
		}
		
		/* IP */
		scan_ip_list(0, policy_number);
		scan_ip_list(1, policy_number);
	}
}

void k_init_tblk(void)
{
	char nvstr_mac[32];
	int policy_number = 0;
	int list_number = 0;
	char cmd[100];
	char buf[1024];
	char *p = buf;

	char *weekday = ALL_DAY_BLOCK;
	time_t secs_now;
	struct tm *local;

	time_wrap_new(&secs_now);
	local = localtime(&secs_now);

	system("echo \"flush\" > /proc/tblock_proc");

	/* Find the time section(0~47, 1 for 30min) right now */
	int time_now=0;
	time_now = local->tm_hour * 2;

	if(local->tm_year < 110)	/* 2010 */
		return ;	/* Cannot get time from NTP server */
	else if(local->tm_min >= 30)
		time_now = time_now + 1;


	for(policy_number=0; policy_number<MAX_POLICY_NUMBER; policy_number++) {
		weekday = get_policy_weekday(local, policy_number);
		if(local->tm_year >= 110 && weekday[time_now] == '0')	/* If NTP server is available and time to block */
		{
			/* MAC */
			sprintf(nvstr_mac, "%s%d", "hnd_filter_mac_grp", policy_number+1);  // hnd_filter_mac1~hnd_filter_mac14

			memset(buf, 0, sizeof(buf));
			strcpy(buf, nvram_safe_get(nvstr_mac));

			p = buf;
			list_number=0;
			if ( strcmp(p, "") ) /*Something is set in URLblocking*/
			{
				char *token = get_strdel(&p, " ");
				while(token != NULL)
				{
					snprintf(cmd, sizeof(cmd)-1, "echo \"add %s\" > /proc/tblock_proc", token);
					cmd[sizeof(cmd)-1] = '\0';
					system(cmd);
					usleep(100);

					list_number++;
					token = get_strdel(&p, " ");
				}
			}
		}
	}

	return ;
}

