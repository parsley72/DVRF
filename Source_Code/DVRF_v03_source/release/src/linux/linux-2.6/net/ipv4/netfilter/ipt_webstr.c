/* Kernel module to match a string into a packet.
 *
 * Copyright (C) 2000 Emmanuel Roger  <winfield@freegates.be>
 * 
 * ChangeLog
 *	19.02.2002: Gianni Tedesco <gianni@ecsc.co.uk>
 *		Fixed SMP re-entrancy problem using per-cpu data areas
 *		for the skip/shift tables.
 *	02.05.2001: Gianni Tedesco <gianni@ecsc.co.uk>
 *		Fixed kernel panic, due to overrunning boyer moore string
 *		tables. Also slightly tweaked heuristic for deciding what
 * 		search algo to use.
 * 	27.01.2001: Gianni Tedesco <gianni@ecsc.co.uk>
 * 		Implemented Boyer Moore Sublinear search algorithm
 * 		alongside the existing linear search based on memcmp().
 * 		Also a quick check to decide which method to use on a per
 * 		packet basis.
 */

/*======================================================================
 *
 *          Copyright (C) 2010-2011 CyberTan Corporation
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *  Version: NA
 *
 * ----------------------------------------------------------------------------------
 *  File          :   ipt_webstr .c
 *
 *  Description   :   This is kernel module for web content inspection. It was 
 *                    derived from 'string' match module, declared as above.
 *
 *   The module follows the Netfilter framework, called extended packet  
 *   matching modules.  
 *
 ======================================================================*/
#include <linux/in.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/sock.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_webstr.h>


int checkLinksysWList(const char *szHost, const char *szPath, const int flags);

#if defined(CONFIG_BCM_NAT) || defined(HNDCTF)
//Zhijian add for fast nat or hndctf 2010-07-06
extern void force_slow_nat(struct sk_buff *pskb);
#endif

#define	isdigit(x) ((x) >= '0' && (x) <= '9')
#define	isupper(x) (((unsigned)(x) >= 'A') && ((unsigned)(x) <= 'Z'))
#define	islower(x) (((unsigned)(x) >= 'a') && ((unsigned)(x) <= 'z'))
#define	isalpha(x) (isupper(x) || islower(x))
#define	toupper(x) (isupper(x) ? (x) : (x) - 'a' + 'A')
#define tolower(x) (isupper(x) ? ((x) - 'A' + 'a') : (x))

#define split(word, wordlist, next, delim) \
    for (next = wordlist, \
	strncpy(word, next, sizeof(word)), \
	word[(next=strstr(next, delim)) ? strstr(word, delim) - word : sizeof(word) - 1] = '\0', \
	next = next ? next + sizeof(delim) - 1 : NULL ; \
	strlen(word); \
	next = next ? : "", \
	strncpy(word, next, sizeof(word)), \
	word[(next=strstr(next, delim)) ? strstr(word, delim) - word : sizeof(word) - 1] = '\0', \
	next = next ? next + sizeof(delim) - 1 : NULL)

#define BUFSIZE 	1024

/* Flags for get_http_info() */
#define HTTP_HOST	0x01
#define HTTP_URL	0x02
/* Flags for mangle_http_header() */
#define HTTP_COOKIE	0x04
#define HTTP_INIT	0x08
#define HTTP_WLIST	0x10
/* Flags for get_https_info() */
#define HTTPS_WLIST	0x20
/* Linksys White List support. */
#define HTTP_WLIST_SUPPORT	1
#define HTTPS_WLIST_SUPPORT	1
/* Flags for schedule block handling */
#define SCHE_WLIST 0x40

#if 0
#define SPARQ_LOG       printk
#else
#define SPARQ_LOG(format, args...)
#endif

typedef struct httpinfo {
    char host[BUFSIZE + 1];
    int hostlen;
    char url[BUFSIZE + 1];
    int urllen;
} httpinfo_t;

/* Return 1 for match, 0 for accept, -1 for partial. */
static int find_pattern2(const char *data, size_t dlen,
	const char *pattern, size_t plen,
	char term,
	unsigned int *numoff,
	unsigned int *numlen)
{
    char *start, *end;

    *numoff = *numlen = 0;

    SPARQ_LOG("%s: pattern = '%s', dlen = %u\n",__FUNCTION__, pattern, dlen);
    if (dlen == 0)
	return 0;

    if (dlen <= plen) {	/* Short packet: try for partial? */
	if (strnicmp(data, pattern, dlen) == 0)
	    return -1;
	else 
	    return 0;
    }

    start = end = (char *)data;
    for ( ; ; start = end+2)
    {
        end = strstr(start, "\r\n");
        if ((NULL == end) || (end == start))
            break;
        if (memcmp(start, pattern, plen))
	    continue;
        *numoff = (start-data)+plen;   //Offset
        *numlen = (end-start)-plen;    //Content-Length

        return 1;
    }

    return 0;
}

static int mangle_http_header(const struct sk_buff *skb, int flags)
{
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = (void *)iph + iph->ihl*4;
    unsigned char *data = (void *)tcph + tcph->doff*4;
    unsigned int datalen = (skb)->len - (iph->ihl*4) - (tcph->doff*4);

    int found, offset, len;
    int ret = 0;
	
    SPARQ_LOG("%s: seq=%u\n", __FUNCTION__, ntohl(tcph->seq));

    /* Basic checking, is it HTTP packet? */
    if (datalen < 10)
	return ret;	/* Not enough length, ignore it */
    if (memcmp(data, "GET ", sizeof("GET ") - 1) != 0 &&
        memcmp(data, "POST ", sizeof("POST ") - 1) != 0 &&
        memcmp(data, "HEAD ", sizeof("HEAD ") - 1) != 0) // For cdrouter_urlfilter_15
	return ret;	/* Pass it */

    /* COOKIE modification */
    if (flags & HTTP_COOKIE) {
	found = find_pattern2(data, datalen, "Cookie: ", 
		sizeof("Cookie: ")-1, '\r', &offset, &len);
	if (found) {
	    char c;
	    offset -= (sizeof("Cookie: ") - 1);
	    /* Swap the 2rd and 4th bit */
	    c = *(data + offset + 2) ;
	    *(data + offset + 2) = *(data + offset + 4) ;
	    *(data + offset + 4) = c ;
	    ret++;
	}
    }

    return ret;
}

// return 0: not get http info,  1: get http info,  2: get http info and match Linksys whitelist
static int get_http_info(const struct sk_buff *skb, int flags, httpinfo_t *info)
{
    const struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = (void *)iph + iph->ihl*4;
    unsigned char *data = (void *)tcph + tcph->doff*4;
    unsigned int datalen = (skb)->len - (iph->ihl*4) - (tcph->doff*4);

    int found, offset;
    int hostlen, pathlen;
    int ret = 0;

    SPARQ_LOG("%s: seq=%u\n", __FUNCTION__, ntohl(tcph->seq));

    /* Basic checking, is it HTTP packet? */
    if (datalen < 10) {
        if ( flags & HTTP_INIT )
            ret = 2;

        return ret;	/* Not enough length, ignore it */
    }
    if (memcmp(data, "GET ", sizeof("GET ") - 1) != 0 &&
        memcmp(data, "POST ", sizeof("POST ") - 1) != 0 &&
        memcmp(data, "HEAD ", sizeof("HEAD ") - 1) != 0)
	return ret;	/* Pass it */

    if (!(flags & (HTTP_HOST | HTTP_URL | HTTP_WLIST)))
	return ret;

    /* find the 'Host: ' value */
    found = find_pattern2(data, datalen, "Host: ", 
	    sizeof("Host: ") - 1, '\r', &offset, &hostlen);
    SPARQ_LOG("Host found=%d\n", found);

    if (!found || !hostlen)
	return ret;

    ret++;	/* Host found, increase the return value */
    hostlen = (hostlen < BUFSIZE) ? hostlen : BUFSIZE;
    strncpy(info->host, data + offset, hostlen);
    *(info->host + hostlen) = 0;		/* null-terminated */
    info->hostlen = hostlen;
    SPARQ_LOG("HOST=%s, hostlen=%d\n", info->host, info->hostlen);

#if HTTP_WLIST_SUPPORT
    if( flags & HTTP_WLIST ) {
		if( checkLinksysWList( info->host, NULL, flags )!=0 )
            ret = 2;

        return ret;
    }
#endif
    if (!(flags & HTTP_URL))
	return ret;

    /* find the 'GET ' or 'POST ' value */
    found = find_pattern2(data, datalen, "GET ",
	    sizeof("GET ") - 1, '\r', &offset, &pathlen);
    if (!found)
	found = find_pattern2(data, datalen, "POST ",
		sizeof("POST ") - 1, '\r', &offset, &pathlen);
    if (!found)
	found = find_pattern2(data, datalen, "HEAD ",
		sizeof("HEAD ") - 1, '\r', &offset, &pathlen);
    SPARQ_LOG("GET/POST/HEAD found=%d\n", found);

    if (!found || (pathlen -= (sizeof(" HTTP/x.x") - 1)) <= 0)/* ignor this field */
	return ret;

//    ret++;	/* GET/POST found, increase the return value */
    pathlen = ((pathlen + hostlen) < BUFSIZE) ? pathlen : BUFSIZE - hostlen;
    strncpy(info->url, info->host, hostlen);
    strncpy(info->url + hostlen, data + offset, pathlen);
    *(info->url + hostlen + pathlen) = 0;	/* null-terminated */
    info->urllen = hostlen + pathlen;
    SPARQ_LOG("URL=%s, urllen=%d\n", info->url, info->urllen);

    return ret;
}

#if HTTP_WLIST_SUPPORT | HTTPS_WLIST_SUPPORT
static int
get_https_ClientHello(const struct sk_buff *skb, int flags, httpinfo_t *info)
{
    const struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = (void *)iph + iph->ihl*4;
    unsigned char *data = (void *)tcph + tcph->doff*4;
    unsigned int datalen = (skb)->len - (iph->ihl*4) - (tcph->doff*4);

    int ret = 0;

    unsigned short length0 = 0; //TLS packet's content length
    unsigned short offset1=0; //Session ID's length
    unsigned short offset2=0; //Cipher suites' length
    unsigned short offset3=0; //Compression Methods' length
    unsigned char  *ppt0, *ppt1, *ppt2, *ppt3;

    /* Basic checking, is it Https ClientHello packet? */
    if (datalen < 50)
    	return ret;	/* Not enough length, ignore it */

    if( (flags & (HTTP_HOST | HTTP_URL))
        || (data[0] != 0x16 /*Handshake*/)
        || (data[5] != 0x01 /*Client Hello*/))
    {
    	/* bypass non-client hello packet... */
    	return ret;
    }

    /* find Extension: server_name field */

    // Content Type:			1 bytes
    // Version:				2
    // Length:				2*
    // Handshake Type:		1
    // Length:				3*
    // Version:				2
    // Random:				32
    // Session ID Length:		1*
    // Session ID (bypass, if Session ID Length = 0)
    // Cipher Suites Length:		2*
    // Cipher Suites:			??
    // Compression Methods Lengt:	1*
    // Compression Methods:	??
    // Extensions Length:		2*
    // Extension: server_name
    //    Type:	server_name (0x0000)
    //    Length:	??
    //    Data:	??
    ppt0 = &data[ 1+2 ];
    length0 = ntohs( *((unsigned short *) ppt0) );

    ppt1 = &data[ 1+2+2+1+3+2+32 ];
    offset1 = *ppt1;

    ppt2 = &ppt1[ 1+offset1 ];
    offset2 = ntohs( *((unsigned short *) ppt2) );

    ppt3 = &ppt2[ 2+offset2 ];
    offset3 = *ppt3;

    if( length0 > (1+3+2+32+1+offset1+2+offset2+1+offset3) )
    {
		unsigned short offset4=0; //Extension's length
		unsigned char *ppt4 = &ppt3[ 1+offset3 ];
		int kk=0;
		offset4 = ntohs( *((unsigned short *) ppt4) );
	
		for( kk=0; kk<offset4; ) {
		    unsigned short offsetN=0; //current Extension's Length
		    unsigned char  *ppt5 = &ppt4[ 2+2 ];

		    /* find server_name field's pattern (0x0000) */
		    if( ppt4[ 2+kk ]==0x00 && ppt4[ 2+kk+1 ]==0x00 ) {
		
			    // ToDo...
			    ret++;
			    strcpy(info->host, &ppt4[ 2+kk+(2+2+5) ]);
			    strcpy(info->url, info->host);
			    info->urllen = strlen( &ppt4[2+kk+2+2+5] );
		
				return ret;
		    }
		    offsetN = ntohs( *((unsigned short *) ppt5) );
		    kk += ( 2+2+offsetN );
		}
    }

    return ret;
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
  short     match;//{ 1:cont., 2:end(partial), 3:partial+PATH, 4:end(full), 5:full+PATH, 6:Block by schedule }
  //unsigned int    checksum;
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
  { "nohold",				-1,-1, 2 },
  { "speedtest",			-1,-1, 2 },
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
  { "linksysbycisco",		-1,-1, 6 },
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
	char	*pHost = NULL;
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
		return(0);//not found
	}
	else
	{
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
					if( pHost-szHost == strlen(curWL[jj].word) && !strncmp(szHost,curWL[jj].word,strlen(curWL[jj].word)) ){
						(*scope) ++;
						(*index) = jj;
						return(curWL[jj].match);//try next scope if necessary
					}
				}
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
	char	*pPath;
	int		cnt = 0;
	int		aa;

	for( pPath=(char *)szPath+1; (*pPath!='/' && *pPath!=0x0); pPath++ ){
		//parse & calculate checksum
		cnt++;
	}

	for( aa=0; aa<1; aa++ ){
		if( (cnt==strlen(WList_PathScope[aa].word))
			&& !strncmp(szPath+1,WList_PathScope[aa].word,cnt) ){
			return(WList_PathScope[aa].match);//found
		}
	}
	return(0);//unexpected case
}

int checkLinksysWList(const char *szHost, const char *szPath, const int flags)
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
			if(flags & SCHE_WLIST)
            	return(0);
        	else
            	return(retMatch);
    	case 6:
        	return(retMatch);
		//also match PATH
		case 3:
		case 5:
			if( szPath!=NULL && strlen(szPath)>0 )
				return(checkWList2(szPath));
			else
				return(retMatch);
	}
	return(0);//unexpected case
}
#define HTTPS_HIGH_PRIORITY_NUM 3
int checkLinksysWListIP(const struct sk_buff *skb, const int flags)
{
	int i=0;
	const struct iphdr *iph = ip_hdr(skb);
	char dest_ip[16];

	struct IP_pair {
    	char *server_name;
		char *ip;
    } WIPLists[] = { \
        // High priority
        {"agile.linksys.com",           "220.130.117.214"},
        {"services.linksys.com",        "66.161.11.6"},
        {"fsx.cisco.com",               "198.133.219.193"},
        // Low priority
        {"www.myciscocommunity.com",    "209.46.39.47"},
        {"linksysrma.moduslink.com",    "202.176.208.143"},
        {"ciscomediahub.com",           "66.161.11.11"},
//      {"ciscomediahub.net",           "66.161.11.11"},
        {"linksyssupport.webex.com",    "66.114.168.182"},
        {"www.web-rebates.com",         "204.10.192.8"},
        {"www.web-rebates.com",         "204.10.192.10"},
        {"trendsecure.com",             "66.35.253.184"},
        {"www.trendsecure.com",         "118.214.227.190"},
        {NULL, NULL} \
    };

	sprintf( dest_ip, "%u.%u.%u.%u", NIPQUAD(iph->daddr));
	for ( i=0 ; WIPLists[i].ip != NULL ; i++ )
	{
		if ( !strncmp(dest_ip, WIPLists[i].ip, sizeof(dest_ip)) )
		{
            if( flags & SCHE_WLIST )
            {
                if( i < HTTPS_HIGH_PRIORITY_NUM )
                    return 1;
                else
                    return 0;
            }
            return 1;
        }
	}
	return 0;
}
#endif

/* Linear string search based on memcmp() */
static char *search_linear (char *needle, char *haystack, int needle_len, int haystack_len) 
{
	char *k = haystack + (haystack_len-needle_len);
	char *t = haystack;
	
	SPARQ_LOG("%s: haystack=%s, needle=%s\n", __FUNCTION__, t, needle);
	for(; t <= k; t++) {
		//SPARQ_LOG("%s: haystack=%s, needle=%s\n", __FUNCTION__, t, needle);
		if (strnicmp(t, needle, needle_len) == 0) return t;
		//if ( memcmp(t, needle, needle_len) == 0 ) return t;
	}

	return NULL;
}
static int
match(const struct sk_buff *skb,
      const struct net_device *in,
      const struct net_device *out,
      const struct xt_match *match,
      const void *matchinfo,
      int offset,
      unsigned int protoff,
      int *hotdrop)
{
	const struct ipt_webstr_info *info = matchinfo;
	//struct iphdr *ip = skb->nh.iph;
    	const struct iphdr *ip = ip_hdr(skb);
	proc_ipt_search search=search_linear;

	char token[] = "<&nbsp;>";
	char *wordlist = (char *)&info->string;
	httpinfo_t htinfo;
	int flags = 0;
	int found = 0;
	long int opt = 0;
	int index;


#if defined(CONFIG_BCM_NAT) || defined(HNDCTF)
	//Zhijian add for fast nat or hndctf  2010-07-06
		force_slow_nat(skb);
#endif
	
	if (!ip || info->len < 1)
	    return 0;

	SPARQ_LOG("\n************************************************\n"
		"%s: type=%s\n", __FUNCTION__, (info->type == IPT_WEBSTR_URL) 
		? "IPT_WEBSTR_URL"  : (info->type == IPT_WEBSTR_HOST) 
		? "IPT_WEBSTR_HOST" : (info->type == IPT_WEBSTR_CONTENT)
		? "IPT_WEBSTR_CONTENT" : (info->type == IPT_WEBSTR_HTTP_WLIST)
		? "IPT_WEBSTR_HTTP_WLIST" : (info->type == IPT_WEBSTR_HTTPS_WLIST)
		? "IPT_WEBSTR_HTTPS_WLIST" : "IPT_WEBSTR_HTTP_INIT" );
	
	/* Determine the flags value for get_http_info(), and mangle packet 
	 * if needed. */
	switch(info->type)
	{
	    case IPT_WEBSTR_URL:	/* fall through */
		flags |= HTTP_URL;

	    case IPT_WEBSTR_HOST:
		flags |= HTTP_HOST;
		break;

	    case IPT_WEBSTR_CONTENT:
		opt = simple_strtol(wordlist, (char **)NULL, 10);
		SPARQ_LOG("%s: string=%s, opt=%#lx\n", __FUNCTION__, wordlist, opt);

		if (opt & (BLK_JAVA | BLK_ACTIVE | BLK_PROXY))
		    flags |= HTTP_URL;
		if (opt & BLK_PROXY)
		    flags |= HTTP_HOST;
		if (opt & BLK_COOKIE)
		    mangle_http_header(skb, HTTP_COOKIE);
		break;

	    case IPT_WEBSTR_HTTP_INIT:
		flags |= HTTP_INIT;
		break;
#if HTTP_WLIST_SUPPORT
	    case IPT_WEBSTR_HTTP_WLIST:
		flags |= HTTP_WLIST;
		break;
#endif
#if HTTPS_WLIST_SUPPORT
	    case IPT_WEBSTR_HTTPS_WLIST:
		flags |= HTTPS_WLIST;
		break;
#endif
	    default:
		printk("%s: Sorry! Cannot find this match option.\n", __FILE__);
		return 0;
	}

#if HTTPS_WLIST_SUPPORT
	if(!strcmp(wordlist, "\'linksys_wlist_sche\'"))  /* If schedule block, 4 URLs should be allow */
		flags |= SCHE_WLIST;

	if( flags & HTTPS_WLIST ) {
	    if( get_https_ClientHello(skb, flags, &htinfo)!=0 ){
		/* Compare https (client hello) packet's server_name */
			if( checkLinksysWList( htinfo.host, NULL, flags )!=0 )
	    	{
	    		found = 1;
	    	}
	    }
	    else { // it's NOT "Client Hello" packet, so...
	    	found = 1;
	    }

	    /* check if server IP match whitelist */
		if( checkLinksysWListIP( skb, flags )!=0 )
	    {
	    	found = 1;
	    }
	    else {
	    	//struct iphdr *iph = (skb)->nh.iph;
    		const struct iphdr *iph = ip_hdr(skb);
	    	SPARQ_LOG("%u.%u.%u.%u is not in Linksys whitelist\n", NIPQUAD(iph->daddr));
	    	found = 0;
	    }

	    return found;
	}
#endif
	/* Get the http header info */
	index = get_http_info(skb, flags, &htinfo);
	if (index < 1)
	    return 0;
	else if ( index == 2 )
	    return 1;

	/* Check if the http header content contains the forbidden keyword */
	if (info->type == IPT_WEBSTR_HOST || info->type == IPT_WEBSTR_URL) {
	    int nlen = 0, hlen = 0;
	    char needle[BUFSIZE], *haystack = NULL;
	    char *next;

	    if (info->type == IPT_WEBSTR_HOST) {
		haystack = htinfo.host;
		hlen = htinfo.hostlen;
	    }
	    else {
		haystack = htinfo.url;
		hlen = htinfo.urllen;
	    }
	    split(needle, wordlist, next, token) {
		nlen = strlen(needle);
		SPARQ_LOG("info->type[%d] keyword=%s, nlen=%d, hlen=%d\n",info->type, needle, nlen, hlen);

	        //Add by Jack for HOST_Match , Need checked(nlen == hlen)length
		if (info->type == IPT_WEBSTR_HOST)
		{ 
			if ( !nlen || !hlen || nlen != hlen )
				continue;
		}
		else if (!nlen || !hlen || nlen > hlen) continue;  //original by Sparq define
	
		if (search(needle, haystack, nlen, hlen) != NULL) {
		    found = 1;
		    break;
		}
	    }
	}
	else {		/* IPT_WEBSTR_CONTENT */
	    int vicelen;

	    if (opt & BLK_JAVA) {
		vicelen = sizeof(".js") - 1;
		if (strnicmp(htinfo.url + htinfo.urllen - vicelen, ".js", vicelen) == 0) {
		    SPARQ_LOG("%s: MATCH....java\n", __FUNCTION__);
		    found = 1;
		    goto match_ret;
		}
		vicelen = sizeof(".class") - 1;
		if (strnicmp(htinfo.url + htinfo.urllen - vicelen, ".class", vicelen) == 0) {
		    SPARQ_LOG("%s: MATCH....java\n", __FUNCTION__);
		    found = 1;
		    goto match_ret;
		}
		vicelen = sizeof(".jar") - 1;
		if (strnicmp(htinfo.url + htinfo.urllen - vicelen, ".jar", vicelen) == 0) {
		    SPARQ_LOG("%s: MATCH....java\n", __FUNCTION__);
		    found = 1;
		    goto match_ret;
		}
	    }
	    if (opt & BLK_ACTIVE){
		vicelen = sizeof(".ocx") - 1;
		if (strnicmp(htinfo.url + htinfo.urllen - vicelen, ".ocx", vicelen) == 0) {
		    SPARQ_LOG("%s: MATCH....activex\n", __FUNCTION__);
		    found = 1;
		    goto match_ret;
		}
		vicelen = sizeof(".cab") - 1;
		if (strnicmp(htinfo.url + htinfo.urllen - vicelen, ".cab", vicelen) == 0) {
		    SPARQ_LOG("%s: MATCH....activex\n", __FUNCTION__);
		    found = 1;
		    goto match_ret;
		}
	    }
	    if (opt & BLK_PROXY){
		if (strnicmp(htinfo.url + htinfo.hostlen, "http://", sizeof("http://") - 1) == 0) {
		    SPARQ_LOG("%s: MATCH....proxy\n", __FUNCTION__);
		    found = 1;
		    goto match_ret;
		}
	    }
	}

match_ret:
	SPARQ_LOG("%s: Verdict =======> %s \n", __FUNCTION__, found ? "HIT" : "MISS");

	return (found ^ info->invert);
}
static int
checkentry(const char *tablename,
           const void *ip,
           const struct xt_match *match,
           void *matchinfo,
           unsigned int hook_mask)
{
       //if (matchsize != IPT_ALIGN(sizeof(struct ipt_webstr_info)))
       //        return 0;

       return 1;
}

static struct xt_match webstr_match = {
	.name		= "webstr",
	.family		= AF_INET,
	.match		= &match,
	.matchsize	= sizeof(struct ipt_webstr_info),
	.checkentry	= &checkentry,
	.me		= THIS_MODULE,
};

static int __init init(void)
{
	return xt_register_match(&webstr_match);
}

static void __exit fini(void)
{
	xt_unregister_match(&webstr_match);
}

module_init(init);
module_exit(fini);
