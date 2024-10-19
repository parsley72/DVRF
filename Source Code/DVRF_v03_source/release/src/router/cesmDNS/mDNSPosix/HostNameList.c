#include <HostNameList.h>
#include <string.h>
#include <mDNSClientAPI.h>
#include <stdlib.h>
#include <stdio.h>
#include <linux/sockios.h>
#include <net/if_arp.h>
#include <linux/in.h>
extern const char *gOutFile;
struct HostNameList * Head;
struct HostNameList * Tail;
int bWrite=0;
/****************************
 *name:InitHostNameList()
 *args: void
 *
 *function: Initialize the List;
 *
 * *****************************/
static int AddList(char * name, mDNSIPAddr ip,char * mac);
void InitHostNameList(void)
{
#if 0
	Head = NULL;
	Tail = NULL;
#endif
	FILE * fp = NULL;
	char * item=NULL, *hostname=NULL,*next = NULL,*ip = NULL;
	char line[256];
	mDNSIPAddr ip_tmp;
	int i;
	char* tmp;
	char * mac_tmp;
	char host_name[128];
	char mac[]="XX:XX:XX:XX:XX:XX";
	fp = fopen(gOutFile,"r");
	if(fp)
	{
		while((fgets(line,sizeof(line),fp)) != NULL)
		{
			char tmp_buf[256];
			line[strlen(line)-1] = '\0';
			if(strlen(line) < 4)
				continue;
			strcpy(tmp_buf,line);			
			next = tmp_buf;
			{
				hostname = strsep(&next,"#");
				if(!next || !hostname)
					continue;

				mac_tmp = strsep(&next,"&"); //read Mac.

				if(mac_tmp)
					strcpy(mac,mac_tmp);
				else
					continue;
				if(!next)
					continue;
				//debugf("hostname(%s)\n",hostname);
				for(ip = next, i = 0; i < 4 && strlen(ip) >= 1 && (tmp = strsep(&ip,".")); i++)
				{
					if(tmp)
						ip_tmp.b[i] = atoi(tmp);
				}
				if(hostname && i == 4)
					bWrite = AddList(hostname,ip_tmp,mac);
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
 *name:AddList();
 *args:
 *    name: Host Name;
 *    ip: Host IP;
 *function: put the hostname and IP into List.
 *
 * ***************************/
static int AddList(char * name, mDNSIPAddr ip,char *mac)
{
	struct HostNameList * tmp;
	tmp = malloc(sizeof(struct HostNameList));
	if(!tmp)
	{
		debugf("Can't alloc enough memory!\n");
		return -1;
	}
//	debugf("mac = %s ....\n",mac);
	strncpy(tmp->hostName,name,sizeof(tmp->hostName) - 1);
	strcpy(tmp->mac,mac);
	tmp->ip = ip;
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
 *name DeleteList()
 *args: void
 *
 *function:Delete the List
 *
 * ******************************************/
void DeleteList( void)
{
	struct HostNameList * tmp = NULL;
	tmp = Head;
	while(Head)
	{
		Head = tmp->next;
		free(tmp);
		tmp = Head;
	}
	Tail = NULL;
	return ;
}

/*******************************************************
 *name: GetMacFromIP
 *args:
 *	IP;
 *
 *Function: Get Mac from remote host by IP;
 * *****************************************************/
char InterfaceName[30]="";
int GetMacFromIP(mDNSIPAddr ip,char * mac)
{

	int sockfd;
	unsigned char *ptr;
	struct arpreq arp_req;
	struct sockaddr_in *sin;
	struct sockaddr_storage ss;
	char addr[50];
	char ip_tmp[32]="";
	int i;	
	memset(addr,0,sizeof(addr));
	memset(&ss,0,sizeof(ss));
//	sin.sin_family = AFINET;
//	debugf("IP = %d.%d.%d.%d ...\n", ip.b[0],ip.b[1],ip.b[2],ip.b[3]);
	sockfd=socket(AF_INET,SOCK_DGRAM,0);
	if(sockfd < 0)
	{
		debugf("socket error\n");
		return -1;
	}
	memset(&arp_req,0,sizeof(arp_req));
	sin = (struct sockaddr_in *) &ss;
	arp_req.arp_pa.sa_family = AF_INET;
	sprintf(ip_tmp,"%d.%d.%d.%d",ip.b[0],ip.b[1],ip.b[2],ip.b[3]);
	sin->sin_family = AF_INET;
	if(inet_pton(AF_INET,ip_tmp,&(sin->sin_addr)) <= 0)
	{
		debugf("inet_aton error ...\n");
		close(sockfd);
		return -1;

	}
	//((struct sockaddr_in *) &(arp_req.arp_pa))->sin_addr.s_addr = inet_addr(ip_tmp);
	
	sin = (struct sockaddr_in *) &arp_req.arp_pa;
	memcpy(sin,&ss,sizeof(struct sockaddr_in));
	if(strlen(InterfaceName) > 2)
		debugf("InterfaceName = %s ...\n",InterfaceName);
	//strcpy(arp_req.arp_dev,"br0");
	strcpy(arp_req.arp_dev,InterfaceName);
	//arp_req.arp_pa.sa_family = AF_INET;
	arp_req.arp_ha.sa_family = AF_UNSPEC;
	
	if(ioctl(sockfd,SIOCGARP,&arp_req) < 0)
	{
		debugf("ioctl SIOCGARP: error\n");
		close(sockfd);
		return -1;
	}
	ptr = (unsigned char *) arp_req.arp_ha.sa_data;

//	debugf("%x:%x:%x:%x:%x:%x\n",*ptr,*(ptr+1),*(ptr+2),*(ptr+3),*(ptr+4),*(ptr+5));
	sprintf(mac,"%02x:%02x:%02x:%02x:%02x:%02x",*ptr,*(ptr+1),*(ptr+2),*(ptr+3),*(ptr+4),*(ptr+5));
	//debugf("Mac = %s ...in GetMacFromIP \n",mac);
	#if 0
	for(i = 0;i < 6; i++)
		mac[i] = *(ptr+i);
	mac[6] ='\0';	
	#endif
	strcpy(InterfaceName,"");
	close(sockfd);
	return 0;
}

/**********************************
 *name: WriteHostNameToFile
 *args: void
 *
 *function: save the List data into File;
 *
 * *******************************/
int WriteHostNameToFile(void)
{
	int fd = -1;
	FILE * fp = NULL;
	struct HostNameList * tmp;
	char buf[256];
	char ip_tmp[32]="";
	char mac_tmp[32]="";
	fp = fopen(gOutFile,"w");
	if(fp)
	{
		if(Head == NULL)
		{
			fclose(fp);
			return 0;
		}
		tmp = Head;
		fseek(fp,0,SEEK_SET);
		while(tmp)
		{
			memset(buf,0,sizeof(buf));
			memset(ip_tmp,0,sizeof(ip_tmp));
			memset(mac_tmp,0,sizeof(mac_tmp));
			strncpy(buf,tmp->hostName,127);
			strcat(buf,"#");

			//sprintf(mac_tmp,"%d:%d:%d:%d:%d:%d",tmp->mac[0],tmp->mac[1],tmp->mac[2],tmp->mac[3],tmp->mac[4],tmp->mac[5]);

			strcat(buf,tmp->mac);//for record mac
			strcat(buf,"&");

			sprintf(ip_tmp,"%d.%d.%d.%d",tmp->ip.b[0],tmp->ip.b[1],tmp->ip.b[2],tmp->ip.b[3]);
			strcat(buf,ip_tmp);
			strcat(buf,"\n");
			fputs(buf,fp);	
			tmp = tmp->next;
		}
		fclose(fp);
		//bWrite = 0;
		
	}
	else
		debugf("Open the file %s error!\n",gOutFile);	
	return 0;
}
/*********************************************
 *name: WriteHostToList
 *args: 
 *	name: Host Name;
 *	ip:  Host Ip;
 *
 *function: Write Host Ip and name into List and File;
 *********************************************/
int WriteHostToList(const char * name, mDNSIPAddr ip)
{
	int ret = 0;
	struct HostNameList * tmp ;
	int found = 0;
	int changed_success = 0;
	char mac[18]="";
	int write_flag = 0;
	
	ret = GetMacFromIP(ip,mac); //get Mac by IP
	if(ret < 0)
		return -1; //failed
	debugf("Mac = %s ...in WriteHostToList ..\n",mac);
	//fprintf(stderr,"find name[%s],mac [%s],ip[%d.%d.%d.%d]\n",name,mac,ip.b[0],ip.b[1],ip.b[2],ip.b[3]);

	if(Head == NULL) //List is still Null
	{
		changed_success = AddList(name,ip,mac);
	//	return 0;
	}
	else //List have data;
	{
		tmp = Head;
		while(tmp)
		{
			if(strcasecmp(tmp->mac,mac) == 0 		&& 
			   tmp->ip.NotAnInteger == ip.NotAnInteger 	&& 
			   strcasecmp(tmp->hostName,name) == 0)
			{
				found = 1;
				changed_success = 0;
				break;
			}
			else if(strcasecmp(tmp->mac,mac) == 0)
			{
				tmp->ip.NotAnInteger = ip.NotAnInteger; //Host update its Ip;
				memset(tmp->hostName,0,sizeof(tmp->hostName));
				strncpy(tmp->hostName,name,sizeof(tmp->hostName) - 1);//Host update its name;	
				found = 1;
				changed_success = 1;
				break;

			}else if(tmp->ip.NotAnInteger == ip.NotAnInteger)
			{
				memset(tmp->mac,0,sizeof(tmp->mac));	//host update its mac
				strcpy(tmp->mac,mac);
				memset(tmp->hostName,0,sizeof(tmp->hostName));
				strncpy(tmp->hostName,name,sizeof(tmp->hostName) - 1);//Host update its name;	
				found = 1;
				changed_success = 1;
				break;
			}
			else
				tmp = tmp->next;
		}

		if(found == 0)
			changed_success = AddList(name,ip,mac);
	}

	if(changed_success)
	{
		bWrite=1;
		fprintf(stderr,"need to update the host file!\n");
		ret = WriteHostNameToFile();
		//ret = 0;
	}
	return ret;	
}
/*******************************************************
 *name: GetPeerMac
 *args:
 *	sockfd:
 *	buf:
 *
 *Function: get peer mac by built socket.
 *
 * ***************************************************/
#if 0
int GetPeerMac(int sockfd,char * buf)
{
	int ret =0;
	struct arpreq arp_req;
	struct sockaddr_in dstaddr_in;
	socklen_t len = sizeof(struct sockaddr_in);
	memset(&arp_req,0,sizeof(struct arpreq));
	memset(&dstaddr_in,0,sizeof(struct sockaddr_in));
	if(getpeername(sockfd,(struct sockaddr *)&dstaddr_in,&len) < 0)
		debugf("getpeername error....\n");
	else
	{
		memcpy(&arp_req.arp_pa,&dstaddr_in,sizeof( struct sockaddr_in));
		strcpy(arp_req.arp_dev,"br0");
		arp_req.arp_pa.sa_family = AF_INET;
		arp_req.arp_ha.sa_family = AF_UNSPEC;
		if(ioctl(sockfd,SIOCGARP,&arp_req) < 0)
			debugf("ioctl SIOCGARP error...\n");
		else
		{
			unsigned char * ptr = (unsigned char *) arp_req.arp_ha.sa_data;
			ret = sprintf(buf,"%02x:%02x:%02x:%02x:%02x:%02x",*ptr,*(ptr+1),*(ptr+2),*(ptr+3),*(ptr +4),*(ptr+5));
			debugf("Peer Mac is %s ....\n",buf);
		
		}
	}
	return ret;
}
#endif
