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
#include <string.h>
#include <time.h>
#include <bcmnvram.h>

int FoundMac = 0;
int CheckDefaultPolicy = 0;

enum XYZ {
    POLICY_TIME_RANGE_MATCH /*0*/,
    POLICY_URL_BLK_MATCH    /*1*/,
    POLICY_KEY_BLK_MATCH    /*2*/,
    POLICY_NO_MATCH         /*3*/
};

/* Return 1 for match, 0 for accept, -1 for partial. */
static int find_pattern(
            const char *data, size_t dlen,
            const char *pattern, size_t plen,
            char term,
            unsigned int *numoff,
            unsigned int *numlen)
{
    size_t i, j, k;

    if (dlen == 0)
        return 0;

    if (dlen <= plen) {
        /* Short packet: try for partial? */
        if (strncmp(data, pattern, dlen) == 0)
            return -1;
        else return 0;
    }

    for(i=0; i<= (dlen - plen); i++){
        if( memcmp(data + i, pattern, plen ) != 0 ) continue;

        /* patten match !! */
        *numoff=i + plen;
        for (j=*numoff, k=0; data[j] != term; j++, k++)
            if( j > dlen ) return -1 ;  /* no terminal char */

        *numlen = k;
        return 1;
    }

    return 0;
}

static const char sccHex2Dec[256] =
{
    /*       0  1  2  3   4  5  6  7   8  9  A  B   C  D  E  F */
    /* 0 */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* 1 */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* 2 */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* 3 */  0, 1, 2, 3,  4, 5, 6, 7,  8, 9,-1,-1, -1,-1,-1,-1,

    /* 4 */ -1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* 5 */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* 6 */ -1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* 7 */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,

    /* 8 */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* 9 */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* A */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* B */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,

    /* C */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* D */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* E */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* F */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1
};

/*
* psrc, len : IN
*
* pres: OUT
*/
static void svUrlDecode(const char * psrc, const int len, char * pres)
{
    const unsigned char * const SRC_END = psrc + len ;
    const unsigned char * const SRC_LAST_DEC = SRC_END - 2;

    char * const pstart = (char *)malloc(len) ;
    char * pend = pstart ;

    while (psrc < (char *)SRC_LAST_DEC)
    {
        if (*psrc == '%')
        {
            char dec1, dec2;
            if (-1 != (dec1 = sccHex2Dec[(int)*(psrc + 1)])
                && -1 != (dec2 = sccHex2Dec[(int)*(psrc + 2)]))
            {
                *pend++ = (dec1 << 4) + dec2;
                psrc += 3;
                continue;
            }
        }
        *pend++ = *psrc++;
    }

    while (psrc < (char *)SRC_END)
        *pend++ = *psrc++;

    memcpy(pres, pstart, (pend - pstart)) ;
    free(pstart) ;
//    pstart = NULL;
}

int checkTMSSSPolicyByNumber( const char *host,
                              const char *url,
                              const char *mac,
                              const int number )
{
    int offset, len;
    char nvramKey[32]="", *nvramVal=NULL, buf[64]="";

    int enable, allow;
    int weekday[7]={ 0,0,0,0,0,0,0 };
    int s_mins = 0, e_mins = 0;
    char blk_host[4][80]={ "","","","" };
    char blk_keyword[4][80]={ "","","","" };

    sprintf(nvramKey, "TMSSS_filter_rule%d", number);
    nvramVal = nvram_safe_get( nvramKey );
    if (strcmp(nvramVal,"") == 0)
        return (int) POLICY_NO_MATCH;

    find_pattern(nvramVal, strlen(nvramVal), "$STAT:", sizeof("$STAT:") - 1, '$', &offset, &len);
    if (len < 1)
        return (int) POLICY_NO_MATCH;   /* error format */

    strncpy(buf, nvramVal + offset, len);
    *(buf + len) = 0;

    /* Drop the targets in allow rule but not in scheduled time */
    switch (atoi(buf)) {
        case 1: //enable & deny
            enable = 1;
            allow = 0;
            break;

        case 2: //enable & allow
            enable = 1;
            allow = 1;
            break;

        case 0: //disable
        default:
            return (int) POLICY_NO_MATCH; //[DBG] match next policy...
    }

    //[0] Is MAC match
    //  [0.a] No, check next policy
    //  [0.b] Yes, goto [1]

    if ( CheckDefaultPolicy == 0 ) {
        char *pp=NULL;
        sprintf(nvramKey, "TMSSS_filter_mac_grp%d", number);
        nvramVal = nvram_safe_get( nvramKey );

        if (strcmp(nvramVal,"") == 0)
            return (int) POLICY_NO_MATCH;

        char mac_buf[ strlen(nvramVal)+1 ];
        strcpy(mac_buf, nvramVal);

        pp = strtok(mac_buf, " ");
        while ( pp != NULL )
        {
            if (strcasecmp(pp, /*http_message->pszMAC*/mac) == 0)
                break;
            pp = strtok(NULL, " ");
        }
        if (pp == NULL)
            return (int) POLICY_NO_MATCH;

        FoundMac = 1;
    }

    int ii;
    int sched=0, allday=0;
    int hr_st, hr_end;  /* hour */
    int mi_st, mi_end;  /* minute */
    char wday[128]="";
    sprintf(nvramKey, "TMSSS_filter_tod%d", number);
    nvramVal = nvram_safe_get( nvramKey );
    if (strcmp(nvramVal,"") == 0)
        return (int) POLICY_NO_MATCH;

    if (strcmp(nvramVal, "0:0 23:59 0-0") == 0 || /*Everyday*/
        strcmp(nvramVal, "0:0 23:59 0-6") == 0) /*Sun, Mon, Tue, Wed, Thu, Fri, Sat*/ {
        sched = 0;
        for (ii=0; ii<7; ii++)
            weekday[ii] = 1;
        s_mins = 0;
        e_mins = 60*24;
    }
    else {
        sched = 1;
        if (sscanf(nvramVal, "%d:%d %d:%d %s",
            &hr_st, &mi_st, &hr_end, &mi_end, wday) != 5)
            return 0; /* error format */

        if (strncmp(nvramVal, "0:0 23:59",9) == 0) {  /* 24-hour, but not everyday */
            allday = 1;
            s_mins = 0;
            e_mins = 60*24;
        }
        else {                                        /* Nither 24-hour, nor everyday */
            s_mins = 60*hr_st + mi_st;
            e_mins = 60*hr_end + mi_end;
        }

        /* Week Scheduled */
        int rotate = 0;     /* wday continugoue */
        char sep[]=",";     /* wday seperate character */
        char *token;
        int st, end;

        /* If its format looks like as "0-1,3,5-6" */
        if (*wday == '0')
            if (*(wday + strlen(wday) - 1) == '6')
                rotate = 1; /* 3, 5-6-0-1 */

        /* Parse the 'wday' format for crontab */
        token = strtok(wday, sep);
        while (token != NULL) {
            /* which type of 'wday' ? */
            if (sscanf(token, "%d-%d", &st, &end) != 2)
                st = end = atoi(token);

            for (ii=st; ii <= end; ii++)
                weekday[ii] = 1;

            token = strtok(NULL, sep);
        }
    }

    //[1] Is Time-range match
    //  [1.a] No, allow->drop & deny->accept
    //  [1.b] Yes, allow->goto [2] & deny->drop
    //  [P.S.] NTP time is not available, (alldays, 24hours)->match, goto [2] & otherwise->goto [1.a]

    time_t ct;  /* Calendar time */
    struct tm *bt;  /* Broken time */
    int now_wday, now_min, get_NTP = 0;

    /* Get local calendar time */
    time_wrap_new(&ct);
    bt=localtime(&ct);
    now_wday = bt->tm_wday;
    now_min = 60* bt->tm_hour + bt->tm_min;

    // [BUG] #15061, by Gavin.ke 2008/09/09
    // [BUG] IR-B0008831,
    // If NTP time is not ready and Time-range is (alldays, 24hours), treat it as match.
    // If NTP time is not ready and Time-range is not (alldays, 24hours), treat it as not match.
    // by marcel   2008/09/18
    if ( ct > 1220198400 )      // 1220198400 -> 2008/09/01
        get_NTP = 1;

	if( get_NTP)
	{
		if( sched) { /*time-range*/
			if ( weekday[now_wday] && (s_mins <= now_min && now_min < e_mins)) { /* ......match*/
				if( !allow) {
					return (int) POLICY_TIME_RANGE_MATCH;
					#if 0 //<==========
					#define HTTP_DENY_HEADER1 \
					    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" \
					    "Block website access at this moment.\n"
					encoded_url = tmUrlEscape(http_message->url);
					sprintf(buf, HTTP_DENY_HEADER1);
					ret = write(http_message->ntfsd, buf, strlen(buf));
					free(encoded_url);
					encoded_url = NULL;
					if(ret < 0 )
					    goto END;
					close(http_message->ntfsd);
					return -1;
					#endif //<==========
				}
			}
			else { /* ......NOT match*/
				if( allow) { return (int) POLICY_TIME_RANGE_MATCH; }
				else { return (int) POLICY_NO_MATCH; }
			}
		}
		else { /*(alldays, 24hours) ......always match*/
			if( !allow) { return (int) POLICY_TIME_RANGE_MATCH; }
		}
	}
	else /*no NTP time*/
	{
		if( sched) { /*time-range ......always NOT match*/
#if 0 /*ryan modify*/
			if( allow) { return (int) POLICY_TIME_RANGE_MATCH; }
			else { return (int) POLICY_NO_MATCH; }
#else
/*
fix the bug
IR-B0010229 : When "current time" is Not Available,
             policy should be valid only with time setting "Everyday" & "24 hours".
*/
            return (int) POLICY_NO_MATCH;
#endif
		}
		else { /*(alldays, 24hours) ......always match*/
			if( !allow) { return (int) POLICY_TIME_RANGE_MATCH; }
		}
	}

    char *qq1=NULL, *qq2=NULL;
    sprintf(nvramKey, "TMSSS_filter_web_host%d", number);
    nvramVal = nvram_safe_get( nvramKey );
	/* [BUG] #14872, it need to complete all checking procedure */
	/* by Gavin.Ke 2008/08/26 */
	//if (strcmp(nvramVal,"") == 0)
	//	continue;

    qq1 = nvramVal;
    qq2 = strstr(nvramVal, "<&nbsp;>");
    for (ii=0; qq2 != NULL; ii++)
    {
        strncpy(blk_host[ii], qq1, (qq2-qq1));
        blk_host[ii][qq2-qq1] = 0;

        qq1 = qq2+strlen("<&nbsp;>");
        qq2 = strstr(qq1, "<&nbsp;>");
    }

    char *rr1=NULL, *rr2=NULL;
    sprintf(nvramKey, "TMSSS_filter_web_url%d", number);
    nvramVal = nvram_safe_get( nvramKey );
	/* [BUG] #14873 #14874, it need to complete all checking procedure */
	/* by Gavin.Ke 2008/08/26 */
	//if (strcmp(nvramVal,"") == 0)
	//	continue;

    rr1 = nvramVal;
    rr2 = strstr(nvramVal, "<&nbsp;>");
    for (ii=0; rr2 != NULL; ii++)
    {
        strncpy(blk_keyword[ii], rr1, (rr2-rr1));
        blk_keyword[ii][rr2-rr1] = 0;

        rr1 = rr2+strlen("<&nbsp;>");
        rr2 = strstr(rr1, "<&nbsp;>");
    }

    //[2] Is URL match
    //  [2.a] No, goto [3]
    //  [2.b] Yes, drop

    int ll;
    for (ll=0; ll<4; ll++)
    {
    	/* IR-B0010919: Blocking websites with Home  Network Defender doesn't work (issue about HTTP:// prefix) */
    	if ( strncasecmp( blk_host[ll], "http://", 7) == 0 ) {
    		char tmp[80];
    		strcpy( tmp, blk_host[ll]+7);
    		strcpy( blk_host[ll], tmp );
    	}

        if ('\0' != *blk_host[ll]
            && strlen(blk_host[ll]) == strlen(/*http_message->host*/host)
            && NULL != strstr(/*http_message->host*/host, blk_host[ll]))
        {
            return (int) POLICY_URL_BLK_MATCH;
                #if 0 //<==========
                #define HTTP_DENY_HEADER2 \
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" \
                    "Block website access of this Host.\n"
                sprintf(buf, HTTP_DENY_HEADER2);
                ret = write(http_message->ntfsd, buf, strlen(buf));
                free(encoded_url);
                encoded_url = NULL;
                if(ret < 0 )
                    goto END;
                close(http_message->ntfsd);
                return -1;
                #endif //<==========
        }
    }

    //[3] Is Keyword match
    //  [3.a] No, accept
    //  [3.b] Yes, drop

#if 0
        char buffUrl[ strlen(host)+strlen(url)+1 ];

        sprintf(buffUrl, "%s%s", /*http_message->host*/host, /*http_message->url*/url);
        for (ll=0; ll<4; ll++)
        {
            if ('\0' != *blk_keyword[ll]
                && NULL != strstr(buffUrl, blk_keyword[ll]))
            {
                return (int) POLICY_KEY_BLK_MATCH;
                #if 0 //<==========
                #define HTTP_DENY_HEADER3 \
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" \
                    "Block website access of this URL.\n"
                sprintf(buf, HTTP_DENY_HEADER3);
                ret = write(http_message->ntfsd, buf, strlen(buf));
                free(encoded_url);
                encoded_url = NULL;
                if(ret < 0 )
                    goto END;
                close(http_message->ntfsd);
                return -1;
                #endif //<==========
            }
        }
#else
/*
fix the bug:
SSS can not block the URL(Router Access Restriction)
1.set keyword to "hehe"
2.visit "http://www.google.cn/search?hl=zh-CN&newwindow=1&q=h%65h%65&meta=
*/
    int key_len = strlen(host)+strlen(url)+1;
    char buffUrl[key_len];
    sprintf(buffUrl, "%s%s", /*http_message->host*/host, /*http_message->url*/url);
//printf("RYAN before decode: host=%s url=%s\n", host, url);
    char cUrlDec[key_len];
    svUrlDecode(buffUrl, key_len, cUrlDec);
//printf("RYAN after decode: cUrlDec=%s\n", cUrlDec);

    for (ll=0; ll<4; ll++)
    {
        if ('\0' != *blk_keyword[ll]
            && NULL != strstr(cUrlDec, blk_keyword[ll]))
        {
            return (int) POLICY_KEY_BLK_MATCH;
        }
    }
#endif

    return (int) POLICY_NO_MATCH;
}

int checkTMSSSPolicy( const char *host,
                      const char *url,
                      const char *mac )
{
    int kk, result;
    FoundMac = 0;
    CheckDefaultPolicy = 0;

    for (kk=1; kk<=10; kk++)
    {
    	result = checkTMSSSPolicyByNumber( host, url, mac, kk );
    	if ( FoundMac == 1 )
    		break;
    }

    /* IR-B0010923 check default policy only if MAC not in the list, by Gavin 2009/05/05 */
    if ( FoundMac == 0 ) {
    	CheckDefaultPolicy = 1;
        kk = atoi( nvram_safe_get("TMSSS_default_num") );
        result = checkTMSSSPolicyByNumber( host, url, mac, kk );
    }

    return result;
}

/***********************************************************
 * Function: checkLinksysWList
 * Input: const char  *szHost
 *        const char  *szPath
 * Output: None
 * Return: 0 if no predefined URLs matched, > 0 otherwise
 ************************************************************/
typedef struct
{
  char		word[20];
  short		start;
  short		end;
  short		match;//{ 1:cont., 2:end(partial), 3:partial+PATH, 4:end(full), 5:full+PATH, 6:won't block by schedule }
  //unsigned int	checksum;
} whitelist;

whitelist WList_HostScope_0[] = {
  { "eu",	0,0,  1 },
  { "org",	1,1,  1 },
  { "net",	2,9,  1 },
  { "com",	10,54, 1 },
};

whitelist WList_HostScope_1[] = {
  { "linksys",				-1,-1, 2 },
  { "tzo",					-1,-1, 2 },
  { "ciscomediahub",		-1,-1, 2 },
  { "linksyscam",			-1,-1, 2 },
  { "mylinksysrouter",		-1,-1, 2 },
  { "mylinksysmedia",		-1,-1, 2 },
  { "mynas200",				-1,-1, 2 },
  { "tzo",					-1,-1, 2 },
  { "nohold",				-1,-1, 6 },
  { "speedtest",			-1,-1, 6 },
  { "ciscomediahub",		-1,-1, 2 },
  { "ciscomediatv",			-1,-1, 2 },
  { "vovici",			0, 1, 1 },
  { "cisco",				-1,-1, 6 },
  { "linksyscam",			-1,-1, 2 },
  { "linksys-cam",			-1,-1, 2 },
  { "linksysnet",			-1,-1, 2 },
  { "linksysstorage",		-1,-1, 2 },
  { "linksyshomemonitor",	-1,-1, 2 },
  { "linksysremotecam",		-1,-1, 2 },
  { "linksysremoteview",	-1,-1, 2 },
  { "moduslink",		2, 2, 1 },
  { "webex",			3, 3, 1 },
  { "linksysdata",			-1,-1, 2 },
  { "linksysbycisco",		-1,-1, 6 }, //wangfei sync patch from RC4-RC8
  { "linksys",				-1,-1, 6 },
  { "mylinksysrouter",		-1,-1, 2 },
  { "mylinksysfiles",		-1,-1, 2 },
  { "mylinksysmedia",		-1,-1, 2 },
  { "mylinksysstuff",		-1,-1, 2 },
  { "mynas200",				-1,-1, 2 },
  { "mynas200stuff",		-1,-1, 2 },
  { "mylinksyscam",			-1,-1, 2 },
  { "mylinksyscamera",		-1,-1, 2 },
  { "mylinksyshome",		-1,-1, 2 },
  { "mylinksysview",		-1,-1, 2 },
  { "myhomeserver",			-1,-1, 2 },
  { "myciscocommunity",		-1,-1, 2 },
  { "tzo",					-1,-1, 2 },
  { "sipura",				-1,-1, 2 },
  { "kiss-technology",		-1,-1, 2 },
  { "ourlinksys",			-1,-1, 2 },
  { "shoplinksys",			-1,-1, 2 },
  { "web-rebates",			-1,-1, 2 },
  { "networkmagic",			-1,-1, 6 },
  { "purenetworks",			-1,-1, 6 },
  { "ookla",				-1,-1, 2 },
  { "custhelp",				-1,-1, 2 },
  { "rightnow",				-1,-1, 2 },
  { "trialpay",				-1,-1, 2 },
  { "digitalriver",			-1,-1, 2 },
  { "trendmicro",			-1,-1, 2 },
  { "trendsecure",			-1,-1, 2 },
  { "allmusicguide",		-1,-1, 2 },
  { "allmusic",				-1,-1, 2 },
};

whitelist WList_HostScope_2[] = {
  { "ciscofeedback",	-1,-1, 2 },
  { "cisco",			-1,-1, 2 },
  { "linksysrma",		-1,-1, 2 },
  { "linksyssupport",	-1,-1, 2 },
};

whitelist WList_PathScope[] = {
  { "linksys",	-1,-1, 4 },
};

whitelist *WListScope[] = {
  WList_HostScope_0,
  WList_HostScope_1,
  WList_HostScope_2,
  NULL,
};

static int
checkWList1( const char *szHost, int *scope, int *index )
{
  char		*pHost = NULL;
  int		ii, jj;
  whitelist	*preWL=NULL;
  whitelist	*curWL=NULL;

  for( pHost=(char *)szHost; (*pHost!='.' && *pHost!=0x0); pHost++ ){
    //parse & calculate checksum
  }

  if( *pHost == 0x0 ){
    //recursive terminated(scope-0)
    curWL = WListScope[0];

    for( ii=0; ii<4; ii++ ){
      if( !strcmp(szHost,curWL[ii].word) ){
        (*scope) = 0;
        (*index) = ii;
        return (curWL[ii].match);
      }
    }
    printf("[DoRating]%s\n",szHost);
    return(0);//not found
  }
  else {
    //recursive call
    int retMatch;
    switch( retMatch = checkWList1(pHost+1,scope,index) ){
      case 1://URL(scope) match & continue
        switch( *scope ){
          case 0:
          case 1:
          case 2:
            preWL = WListScope[ (*scope)   ];
            curWL = WListScope[ (*scope)+1 ];
            break;

          default://unexpected case
            return(0);
        }

        for( jj=preWL[*index].start; jj<=preWL[*index].end; jj++ ){
          if( pHost-szHost == strlen(curWL[jj].word)
              && !strncmp(szHost,curWL[jj].word,strlen(curWL[jj].word)) ){
            (*scope) ++;
            (*index) = jj;
            return(curWL[jj].match);//try next scope if necessary
          }
        }
        printf("[DoRating]%s\n",szHost);
        return(0);//not found

      default:
        return(retMatch);
    }
  }
  return(0);//unexpected case
}

static int
checkWList2(const char *szPath)
{
  int	cnt=0;
  char	*pPath;

  for( pPath=(char *)szPath+1; (*pPath!='/' && *pPath!=0x0); pPath++ ){
    //parse & calculate checksum
    cnt++;
  }

  int aa;
  for( aa=0; aa<1; aa++ ){
    if( (cnt==strlen(WList_PathScope[aa].word))
        && !strncmp(szPath+1,WList_PathScope[aa].word,cnt) ){
      printf("[match]%s\n",WList_PathScope[aa].word);
      return(WList_PathScope[aa].match);//found
    }
  }
  return(0);//unexpected case
}

int checkLinksysWList(const char *szHost, const char *szPath)
{
  int  scope=(-1);
  int  index=(-1);
  int  retMatch;

  switch( retMatch = checkWList1(szHost,&scope,&index) ){
    //just match Host
    case 0:
    case 1:
    case 2:
    case 4:
    case 6:
      return(retMatch);

    //also match PATH
    case 3:
    case 5:
      return(checkWList2(szPath));
  }
  return(0);//unexpected case
}

