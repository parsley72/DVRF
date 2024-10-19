#ifndef NMBD_NETBIOSNAME_LIST_H
#define NMBD_NETBIOSNAME_LIST_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct NetbiosNameList 
{
	unsigned char ip[4];
	char NetbiosName[128];
	char mac[18];
	struct NetbiosNameList * next;
};

void init_netbios_name_list(void);
void delete_netbios_name_list(void);
int write_netbios_name_to_list(const char * name, char * ip);
int delete_netbios_name_from_list(const char * name, char * ip);
#endif
