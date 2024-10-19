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

/* 2010-08-01	Linghong.Tan */

#include <linux/kernel.h> /* export min_t */
#include <linux/ctype.h>
#include <linux/string.h>
//#include <arpa/nameser.h>

#include "decode.h"

#define GETSHORT(s, cp) { \
	(s) = *(cp)++ << 8; \
	(s) |= *(cp)++; \
}

#define GETLONG(l, cp) { \
	(l) = *(cp)++ << 8; \
	(l) |= *(cp)++; (l) <<= 8; \
	(l) |= *(cp)++; (l) <<= 8; \
	(l) |= *(cp)++; \
}

// nMaxPathLen excludes the null-terminated character
// nMaxHostLen excludes the null-terminated character
static int __decode_http(const char *szBuffer, const int nLength, 
        char *szPath, const int nMaxPathLen, 
        char *szHost, const int nMaxHostLen)
{
    unsigned char bURI = 0;
    unsigned char bHost = 0;
    char *pEOF, *pEOL, *pTemp;

    pEOF = (char *)(szBuffer + nLength);

    /* check header length
     *	GET *\r\n
     *	HOST: *\r\n\r\n
     */
    if (nLength < 18)
    {
        /* invalid header */
        return -1;
    }

    /* check start w/ GET */
    if (strncmp("GET ", szBuffer, 4) != 0 && 
		strncmp("PUT ", szBuffer, 4) != 0 && 
		strncmp("HEAD ", szBuffer, 5) != 0 && 
		strncmp("POST ", szBuffer, 5) != 0)
    {
        /* invalid header */
        return -2;
    }

    /* check header end signature */
    if ((pEOF = strstr(szBuffer, "\r\n\r\n")) == NULL)
    {
        /* invalid header */
        return -3;
    }

    pEOF = (char *)(szBuffer + nLength);

    /* retreive path first */

    while (szBuffer < pEOF)
    {
#if 0 /* shouldn't happend */
        if (isspace(Buffer[0]))
        {
            Buffer++;
            continue;
        }
#endif

        pEOL = strchr(szBuffer, '\r');

        if (pEOL == NULL)
        {
            /* touch the end*/
            break;
        }
#if 0
        if (pEOL - Buffer < 4)
        {
            Buffer++;
            continue;
        }
#endif

        /* look for URI */
        if (strncmp("GET ", szBuffer, 4) == 0 || 
			strncmp("PUT ", szBuffer, 4) == 0 || 
			strncmp("HEAD ", szBuffer, 5) == 0 || 
			strncmp("POST ", szBuffer, 5) == 0)
        {
            unsigned int unPathLen = 0;

			if (strncmp("GET ", szBuffer, 4) == 0) {
				szBuffer += 4;
			}
			else if (strncmp("PUT ", szBuffer, 4) == 0) {
				szBuffer += 4;
			}
			else if (strncmp("POST ", szBuffer, 5) == 0) {
				szBuffer += 5;
			}
			else if (strncmp("HEAD ", szBuffer, 5) == 0) {
				szBuffer += 5;
			}
 
            bURI = 1;

            *pEOL = '\0'; /* prevent from buffer-overflow */
            pTemp = strchr(szBuffer, ' ');
            *pEOL = '\r';
            if (pTemp == NULL)
            {
                pTemp = pEOL;
            }
#if 0
            if (pTemp > pEOF)
            {
                continue;
            }
#endif
            unPathLen = min_t(unsigned int, nMaxPathLen, pTemp - szBuffer);
            strncpy(szPath, szBuffer, unPathLen);
            szPath[unPathLen] = '\0';
        }

        /* look for HOST */
        if (strncmp("Host: ", szBuffer, 6)==0)
        {
            unsigned int unHostLen = 0;
            szBuffer += 6;
            bHost = 1;

            unHostLen = min_t(unsigned int, nMaxHostLen, pEOL - szBuffer);
            strncpy(szHost, szBuffer, unHostLen);
            szHost[unHostLen] = '\0';
        }

        szBuffer = pEOL + 2;  /* feed line \r\n */
    }

    if (!bHost)
    {
        szHost[0] = '\0';
    }
    else if (!bURI)
    {
    	szPath[0] = '\0';
    }

    if ((!bHost) || (!bURI))
    {
        return -4;
    }
    return 0;
}

int decode_http(const char *pBuffer,const int nLength, req_info_t *pHead)
{
    return __decode_http(pBuffer, nLength, pHead->path, MAX_URL_SIZE - 1, pHead->host, MAX_HOST_SIZE - 1);
}


/* tlhhh. from rfc1035.c */
static unsigned char *skip_questions(struct dnshdr *header, unsigned int plen)
{
	int q, qdcount = ntohs(header->qdcount);
	unsigned char *ansp = (unsigned char *)(header+1);

	for (q=0; q<qdcount; q++)
	{
		while (1)
		{
			if ((unsigned int)(ansp - (unsigned char *)header) >= plen)
				return NULL;

			if (((*ansp) & 0xc0) == 0xc0) /* pointer for name compression */
			{
				ansp += 2;	
				break;
			}
			else if (*ansp) 
			{	/* another segment */
				ansp += (*ansp) + 1;
			}
			else            /* end */
			{
				ansp++;
				break;
			}
		}
		ansp += 4; /* class and type */
	}

	if ((unsigned int)(ansp - (unsigned char *)header) > plen) 
		return NULL;

	return ansp;
}

static int extract_name(struct dnshdr *header, unsigned int plen, unsigned char **pp, 
			char *name, int isExtract)
{
	char *cp = name;
	unsigned char *p = *pp, *p1 = NULL;
	unsigned int j, l, hops = 0;
	int retvalue = 1;

	while ((l = *p++))
	{
		if ((l & 0xc0) == 0xc0) /* pointer */
		{ 
			if (p - (unsigned char *)header + 1u >= plen)
				return 0;

			/* get offset */
			l = (l&0x3f) << 8;
			l |= *p++;
			if (l >= (unsigned int)plen) 
				return 0;

			if (!p1) /* first jump, save location to go back to */
				p1 = p;

			hops++; /* break malicious infinite loops */
			if (hops > 255)
				return 0;

			p = l + (unsigned char *)header;
		}
		else
		{
			if (cp-name+l+1 >= MAX_HOST_SIZE)
				return 0;
			if (p - (unsigned char *)header + l >= plen)
				return 0;

			for(j=0; j<l; j++, p++) {
				if (isExtract)
					*cp++ = tolower(*p);
				else if (!*cp || *cp++ != tolower(*p))
					retvalue =  2;
			}

			if (isExtract)
				*cp++ = '.';
			else
				if (*cp && *cp++ != '.')
					retvalue = 2;
		}

		if ((unsigned int)(p - (unsigned char *)header) >= plen)
			return 0;
	}

	if (isExtract)
	{
		if (cp == name)	/* bad packet! */
			return 0;
		*--cp = 0; /* terminate: lose final period */
	}

	if (p1) /* we jumped via compression */
		*pp = p1;
	else
		*pp = p;

	return retvalue;
}


/* added by tlhhh 2010-12-29. DNS header check for those malformed packets in throughput test */
inline int is_valid_dns(unsigned char* raw_pkt, int pkt_len, int *dns_type)
{
    struct dnshdr *header = (struct dnshdr *)raw_pkt;
	unsigned int qdcount;
	unsigned int anscount;

	if (!raw_pkt || pkt_len < sizeof(struct dnshdr))
		return 0;

	/* transition id check? */
//	if (ntohs(header->id) == 0)
//		return -1;

	/* opcode check: only support standard query */
	if (header->opcode != QUERY)
		return 0;

	qdcount = ntohs(header->qdcount);
	anscount = ntohs(header->ancount);

	/* query count check: must be exactly one question */
	if (qdcount != 1)
		return 0;

	if (header->qr == 0)	//Question
		*dns_type = 1;
	else if(header->qr == 1)		//Answer
	{
		/* answer count check: limit */
		if (!anscount || anscount >= MAX_DNS_ANSWER) 
			return 0;
		/* response code check: only support NOERROR */
		if (header->rcode != 0)
			return 0;

		*dns_type = 2;
	}
	else
	{
		*dns_type = 0;
		return 0;
	}

	return 1;
}

/* return -1 if we can't decode this packet */
int decode_dns(unsigned char* raw_pkt, int pkt_len, struct dnsrr *tuple)
{
    struct dnshdr *header = (struct dnshdr *)raw_pkt;
	int i, k=0;
	char host[MAX_HOST_SIZE];
	int dns_type = 0;

	unsigned char *ppkt, *ansp, *endrr;
	int qtype, qclass, rdlen;
	unsigned long ttl;

	if ( !is_valid_dns(raw_pkt, pkt_len, &dns_type) )
		return -1;

	memset(host, 0, sizeof(host));
	memset(tuple->domainname, 0, sizeof(tuple->domainname));

	ppkt = (unsigned char *)(header + 1);

	/* now extract name as .-concatenated string into name */
	if (!ppkt || !extract_name(header, pkt_len, &ppkt, host, 1))
		return -1; /* bad packet */
	
	if (!ppkt)	return -1;

	GETSHORT(qtype, ppkt); 
	GETSHORT(qclass, ppkt);
	if (qclass != C_IN)
		return 0; /* we can't answer non-inet queries */

	if( host[0] == '\0' )
		return -1;
	
	memcpy( tuple->domainname, host, MAX_HOST_SIZE-1 );
	tuple->domainname[MAX_HOST_SIZE-1] = '\0';
	
	/*if dns query, no other interest */
	if( dns_type == 1 )
		return 0;
	
	/* skip over questions */
	if (!(ansp = skip_questions(header, pkt_len)))
		return -1; /* bad packet */

	tuple->anscount = ntohs(header->ancount);
	
	/* loop to extract all answers */
	for (i = 0; i<tuple->anscount; i++) {
		struct my_addr_in srvip;

		if (!ansp || !extract_name(header, pkt_len, &ansp, host, 1))
			return -1; /* bad packet */

		if (!ansp)	return -1;

		GETSHORT(qtype, ansp); 
		GETSHORT(qclass, ansp);
		GETLONG(ttl, ansp);
		GETSHORT(rdlen, ansp);

		endrr = ansp + rdlen;
		if ((unsigned int)(endrr - (unsigned char *)header) > pkt_len)
			return -1; /* bad packet */

		if (qclass != C_IN)
		{
			ansp = endrr;
			continue;
		}

		if (qtype == T_A) {
		/* A record (IPv4 support) */
			if ( rdlen == 4 ) {
				memcpy(&srvip.my_s_addr, ansp, rdlen);
				tuple->dnslist[k].my_s_addr = srvip.my_s_addr;
				tuple->dnslist[k].family = AF_INET;
				k++;
			}
		}

		if (qtype == T_AAAA) {
		/* AAAA record (IPv6 support) */
			if ( rdlen == 16 ) {
				memcpy(&tuple->dnslist[k].in_u.in6addr, ansp, sizeof(struct in6_addr));
				tuple->dnslist[k].family = AF_INET6;
				k++;
			}
		}

		// skip PTR record & Canonical name
		ansp = endrr;
	}
	
	//skip the left
	return 0;
}



