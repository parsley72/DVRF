#ifndef HOSTNAMELIST_H
#define HOSTNAMELIST_H
#include <mDNSClientAPI.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct HostNameList 
{
	mDNSIPAddr ip;
	char hostName[128];
	char mac[18];
	struct HostNameList * next;
};

void DeleteList( void);
void InitHostNameList(void);
int WriteHostToList(const char * name, mDNSIPAddr ip);

int GetPeerMac(int sockfd,char * buf);
#endif
