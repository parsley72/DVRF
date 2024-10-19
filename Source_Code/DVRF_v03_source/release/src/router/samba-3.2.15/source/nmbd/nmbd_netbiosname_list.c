#include <nmbd_netbiosname_list.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <linux/sockios.h>
#include <net/if_arp.h>
#include <linux/in.h>

#if 0
#define MYDEBUG(fmt, args...) do { \
        FILE *fp = fopen("/dev/console", "w"); \
        if (fp) { \
                fprintf(fp, fmt , ## args); \
                fclose(fp); \
        } \
} while (0)
#else
#define MYDEBUG(fmt, args...) 
#endif

#define NETBIOS_NAME_FILE "/tmp/.netbios_name_list"

struct NetbiosNameList * Head;
struct NetbiosNameList * Tail;

static int add_netbiosname_list(const char * name, char ip[4], char * mac);

/****************************
 *name:init_netbios_name_list()
 *args: void
 *
 *function: Initialize the List;
 *
 * *****************************/
void init_netbios_name_list(void)
{
	FILE * fp = NULL;
	char *netbiosname=NULL,*next = NULL,*ip = NULL;
	char line[256];
	char tmp_buf[256];
	char ip_tmp[4];
	int i;
	char* tmp;
	char * mac_tmp;

	MYDEBUG("Init Netbios Name list......\n");

	fp = fopen(NETBIOS_NAME_FILE,"r");
	if(fp)
	{
		while((fgets(line,sizeof(line),fp)) != NULL)
		{
			line[strlen(line)-1] = '\0';
			if(strlen(line) < 4) continue;

			memset(tmp_buf, 0, sizeof(tmp_buf));
			strcpy(tmp_buf,line);		
	
			next = tmp_buf;
			{
				netbiosname = strsep(&next,"#");
				if(!next || !netbiosname)
					continue;

				mac_tmp = strsep(&next,"&"); //read Mac.

				if(!next || !mac_tmp)
					continue;

				memset(ip_tmp, 0, sizeof(ip_tmp));
				for(ip = next,i = 0;i < 4 && strlen(ip)>=1 && (tmp = strsep(&ip,"."));i++)
				{
					if(tmp)
						ip_tmp[i] = atoi(tmp);
				}
				if(netbiosname && i == 4)
					add_netbiosname_list(netbiosname, ip_tmp, mac_tmp);
			}
		}
		fclose(fp);
	}
	else
	{
		Head = NULL;
		Tail = NULL;
	}
}
/****************************
 *name:add_netbiosname_list();
 *args:
 *    name: Host Name;
 *    ip: Host IP;
 *    mac: MAC address
 *function: put the hostname and IP and MAC into List.
 *
 * ***************************/
static int add_netbiosname_list(const char * name, char ip[4], char *mac)
{
	struct NetbiosNameList * tmp;

	tmp = malloc(sizeof(struct NetbiosNameList));
	if(!tmp)
	{
		MYDEBUG("Can't alloc enough memory!\n");
		return -1;
	}

	strncpy(tmp->NetbiosName, name, sizeof(tmp->NetbiosName) - 1);
	strncpy(tmp->mac, mac, sizeof(tmp->mac)-1);
	memcpy(tmp->ip, ip, sizeof(tmp->ip));
	
	if(!Head)
	{
		Head = tmp;
		tmp->next = NULL;
		Tail = tmp;
	}
	else
	{
		Tail->next = tmp;
		tmp->next = NULL;
		Tail = tmp;
	}
	return 1;	
}
/********************************************
 *name delete_netbios_name_list()
 *args: void
 *
 *function:Delete the List
 *
 * ******************************************/
void delete_netbios_name_list(void)
{
	struct NetbiosNameList * tmp = NULL;

	tmp = Head;
	while(Head)
	{
		Head = tmp->next;
		free(tmp);
		tmp = Head;
	}
	Tail = NULL;

	//delete netbios name file
	//remove(NETBIOS_NAME_FILE);

	return ;
}

/*******************************************************
 *name: get_mac_by_ip
 *args:
 *	IP;
 *
 *Function: Get Mac from remote host by IP;
 * *****************************************************/
#if 0
int get_mac_by_ip(char * ip,char * mac)
{

	int sockfd;
	unsigned char *ptr;
	struct arpreq arp_req;
	struct sockaddr_in *sin;
	
	sockfd=socket(AF_INET,SOCK_DGRAM,0);
	if(sockfd < 0)
	{
		MYDEBUG("socket error\n");
		return -1;
	}

	memset(&arp_req, 0, sizeof(arp_req));
	strcpy(arp_req.arp_dev, "br0");
	arp_req.arp_ha.sa_family = AF_UNSPEC;

	sin = (struct sockaddr_in *) &arp_req.arp_pa;
	sin->sin_family = AF_INET;
	if(inet_pton(AF_INET,ip, &(sin->sin_addr)) <= 0)
	{
		MYDEBUG("inet_aton error ...\n");
		close(sockfd);
		return -1;

	}
	
	if(ioctl(sockfd,SIOCGARP,&arp_req) < 0)
	{
		MYDEBUG("ioctl SIOCGARP: error\n");
		close(sockfd);
		return -1;
	}
	ptr = (unsigned char *) arp_req.arp_ha.sa_data;
	sprintf(mac,"%02x:%02x:%02x:%02x:%02x:%02x",*ptr,*(ptr+1),*(ptr+2),*(ptr+3),*(ptr+4),*(ptr+5));
	
	close(sockfd);
	return 0;
}
#else
int get_mac_by_ip(char * ip,char * mac)
{
	FILE *fp;
	char line[80];
	char ipaddr[50]  =""; // ip address
	char hwa[50] ="";
	char mask[50]="";
	char dev[50] =""; // interface
	int type;
	int flags;
	int count = 0;

	if(!ip) return -1;

	if ((fp = fopen("/proc/net/arp", "r"))) 
	{
		if (fgets(line, sizeof(line), fp) != (char *) NULL) 
		{
			// Read the ARP cache entries.
			// IP address       HW type     Flags       HW address            Mask     Device
			// 192.168.1.1      0x1         0x2         00:90:4C:21:00:2A     *        eth0
			for (; fgets(line, sizeof(line), fp);) 
			{
				if(sscanf(line, "%s 0x%x 0x%x %100s %100s %100s\n", ipaddr, &type, &flags, hwa, mask, dev) != 6)
					continue;
				count++;
				MYDEBUG("%d: Get mac[%s] ip[%s]\n", count, hwa, ipaddr);
				
				if(!strcmp(ip, ipaddr))	
				{
					sprintf(mac, "%s", hwa);
					fclose(fp);
					return 0;
				}
			}
		}
		fclose(fp);
	}
	
	return -1;	
}
#endif

/**********************************
 *name: write_netbios_name_to_file
 *args: void
 *
 *function: save the List data into File;
 *
 * *******************************/
int write_netbios_name_to_file(void)
{
	FILE * fp = NULL;
	struct NetbiosNameList * tmp;
	char buf[256];
	char ip_tmp[32]="";
	char mac_tmp[32]="";
		
	if(Head == NULL)
	{
		//delete netbios name file
		remove(NETBIOS_NAME_FILE);
		 return 0;
	}

	fp = fopen(NETBIOS_NAME_FILE,"w");
	if(!fp) 
	{
		MYDEBUG("Open the file %s error!\n",NETBIOS_NAME_FILE);
		return 0;
	}
	
	tmp = Head;
	fseek(fp,0,SEEK_SET);
	while(tmp)
	{
		memset(buf, 0, sizeof(buf));
		memset(ip_tmp, 0, sizeof(ip_tmp));
		memset(mac_tmp, 0, sizeof(mac_tmp));

		strncpy(buf, tmp->NetbiosName,127);
		strcat(buf, "#");

		strcat(buf, tmp->mac);//for record mac
		strcat(buf, "&");

		sprintf(ip_tmp, "%d.%d.%d.%d", 
				tmp->ip[0],
				tmp->ip[1],
				tmp->ip[2],
				tmp->ip[3]);
		strcat(buf, ip_tmp);
		strcat(buf, "\n");
		fputs(buf, fp);	
		tmp = tmp->next;
	}
	fclose(fp);

	return 0;
}
/*********************************************
 *name: write_netbios_name_to_list
 *args: 
 *	name: Host Name;
 *	ip:  Host Ip;
 *
 *function: Write Host Ip and name into List and File;
 *********************************************/
int write_netbios_name_to_list(const char * name, char * ip)
{
	int ret = 0;
	struct NetbiosNameList * tmp ;
	int found = 0;
	int changed_success = 0;
	char mac[18]="";
	unsigned char ip_int4[4];
	char *ip_tmp, *next, ip_str[32];
	int i;
	int try_mac = 3;
	
	ret = get_mac_by_ip(ip, mac);
	while(try_mac-- && (ret < 0))
	{
		sleep(1);
		ret = get_mac_by_ip(ip, mac);
	}
	if(ret < 0)
	{
		MYDEBUG("%s can't get mac by ip [%s]\n", __FUNCTION__, ip);
		return -1; //failed
	}

	MYDEBUG("Mac = %s ...in nmbd write netbios name %s to list ..\n", mac, name);

	memset(ip_int4, 0, sizeof(ip_int4));
	memset(ip_str, 0, sizeof(ip_str));
	strncpy(ip_str, ip, sizeof(ip_str)-1);

	for(next = ip_str,i = 0; i < 4 && strlen(next)>=1 && (ip_tmp = strsep(&next,".")); i++)
	{
		if(ip_tmp)
			ip_int4[i] = atoi(ip_tmp);
	}

	if(Head == NULL)
	{
		changed_success = add_netbiosname_list(name, ip_int4, mac);
	}
	else //List have data;
	{
		tmp = Head;
		while(tmp)
		{
			if(strcasecmp(tmp->mac, mac) == 0 		&& 
			   tmp->ip[0] == ip_int4[0] && tmp->ip[1] == ip_int4[1] && tmp->ip[2] == ip_int4[2] && tmp->ip[3] == ip_int4[3] && 
			   strcasecmp(tmp->NetbiosName, name) == 0)
			{
				found = 1;
				changed_success = 0;
				break;
			}
			else if(strcasecmp(tmp->mac, mac) == 0)
			{
				memcpy(tmp->ip, ip_int4, sizeof(ip_int4)); //Host update its Ip;
				memset(tmp->NetbiosName, 0, sizeof(tmp->NetbiosName));
				strncpy(tmp->NetbiosName, name, sizeof(tmp->NetbiosName) - 1);//Host update its name;	
				found = 1;
				changed_success = 1;
				break;

			}else if(tmp->ip[0] == ip_int4[0] && tmp->ip[1] == ip_int4[1] && tmp->ip[2] == ip_int4[2] && tmp->ip[3] == ip_int4[3] )
			{
				memset(tmp->mac, 0, sizeof(tmp->mac));	//host update its mac
				strncpy(tmp->mac, mac, sizeof(tmp->mac)-1);
				memset(tmp->NetbiosName, 0, sizeof(tmp->NetbiosName));
				strncpy(tmp->NetbiosName, name, sizeof(tmp->NetbiosName) - 1);//Host update its name;	
				found = 1;
				changed_success = 1;
				break;
			}
				
			tmp = tmp->next;
		}

		if(found == 0)
			changed_success = add_netbiosname_list(name, ip_int4, mac);
	}

	if(changed_success)
	{
		MYDEBUG("need to update the netbios name file!\n");
		ret = write_netbios_name_to_file();
	}
	return ret;	
}

/*********************************************
 *name: delete_netbios_name_from_list
 *args: 
 *	name: Host Name;
 *	ip:  Host Ip;
 *
 *function: remove Host Ip and name from List and File;
 *********************************************/
int delete_netbios_name_from_list(const char * name, char * ip)
{
	int ret = 0;
	struct NetbiosNameList *tmp, *pre_tmp ;
	int found = 0;
	char mac[18]="";
	unsigned char ip_int4[4];
	char *ip_tmp, *next, ip_str[32];
	int i;
	int try_mac = 3;
	
	if(Head == NULL) return ret;

	ret = get_mac_by_ip(ip, mac);
	while(try_mac-- && (ret < 0))
	{
		sleep(1);
		ret = get_mac_by_ip(ip, mac);
	}
	if(ret < 0)
	{
		MYDEBUG("%s can't get mac by ip [%s]\n", __FUNCTION__, ip);
		return -1; //failed
	}

	MYDEBUG("Mac = %s ...in nmbd remove netbios name %s from list ..\n", mac, name);

	memset(ip_int4, 0, sizeof(ip_int4));
	memset(ip_str, 0, sizeof(ip_str));
	strncpy(ip_str, ip, sizeof(ip_str)-1);

	for(next = ip_str,i = 0; i < 4 && strlen(next)>=1 && (ip_tmp = strsep(&next,".")); i++)
	{
		if(ip_tmp)
			ip_int4[i] = atoi(ip_tmp);
	}

	tmp = Head;
	pre_tmp = tmp;
	while(tmp)
	{
		if((strcasecmp(tmp->mac, mac) == 0) || ((tmp->ip[0] == ip_int4[0]) && (tmp->ip[1] == ip_int4[1]) && (tmp->ip[2] == ip_int4[2]) && (tmp->ip[3] == ip_int4[3])))
		{
			found = 1;
			break;
		}
		pre_tmp = tmp;
		tmp = tmp->next;
	}

	if(found)
	{

		if(pre_tmp == tmp) 
		{
			if(!tmp->next){
				Head = NULL; Tail = NULL;
			}else{
				Head = tmp->next;
			}
		}else
		{
			pre_tmp->next = tmp->next;
			if(Tail == tmp) Tail = pre_tmp;
		}

		free(tmp);
		MYDEBUG("need to update the netbios name file!\n");
		ret = write_netbios_name_to_file();
	}

	return ret;	
}
