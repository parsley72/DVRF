/***************************************************************************
 *                         Simple HTTP Tzo Client                          *
 *                         ----------------------                          *
 *   begin                : Tue Feb 6 2007                                 *
 *									   *
 *   modifications	  : (see HISTORY file)				   *
 *						 			   *
 *   copyright            : (C) 2007 by TZO                                *
 *   email                : devsupport@tzo.com                             *
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>
#include "tzoupdate.h"

#define SOCKET_ERROR    -1
#define WSAEWOULDBLOCK	-1
#define TRUE            1
#define FALSE           0
#define INVALID_SOCKET	-1


#define TCP_SOCKET	1
#define UDP_SOCKET	2
#define MAX_MESSAGE_SIZE 6000

#define EXIT_OK			0
#define EXIT_TEMP_BLOCK		1
#define EXIT_EXPIRED		2
#define EXIT_FATAL		3
#define EXIT_CONFIG_ERROR	4
typedef struct
	{
	char * lpMem ;
	long Size ;
	long Ptr ;
	} MEMSTRUCT ;

unsigned char TzoUpdateServerName[64] = {"linksys.rh.tzo.com"} ;
unsigned char TzoEchoServerName[64] = {"linksys.echo.tzo.com"} ;
int DefaultHttpPort = 80 ;

/*
 * The User Agent, This should be modified for corporate usage
 */
#include <cy_conf.h>
#ifdef TZO_WEB_CLIENT2_SUPPORT
	#include <cyutils.h>
	#include <code_pattern.h>
	char TZO_UserAgentString[128] = {MODEL_NAME "-" CYBERTAN_VERSION " build " SERIAL_NUMBER " " MINOR_VERSION} ;

	typedef struct {
		int	http_resp;
		char	description[128];
	} tlb_TZO_t;

	tlb_TZO_t tlb_TZO[ ] = {
                #if 0
		{ERR_MEMCREATE_FAILED		/*100*/	,"Internal error allocating memory"},
		{ERR_FETCHIPADDRESS_FAILED	/*101*/	,"Could not fetch IP address for domain"},
		{ERR_OPENCONNECTION_FAILED	/*102*/	,"Could not connect to server"},
		{ERR_SENDTOSOCKET_FAILED	/*103*/	,"Could not send data to server"},
		{ERR_READFROMSOCKET_FAILED	/*104*/	,"Could not read from server"},
		{ERR_BAD_PACKET_RETURNED	/*105*/	,"Server responed with an invalid packet"},

		{UPDATE_SUCCESS				/*200*/	,"The update was successful, and the hostname is now updated"},
		{HOST_CREATED				/*201*/	,"New Domain Created for Existing TZO Key"},
		{UPDATE_NOCHANGE			/*304*/	,"No Change in the IP Address"},

		{ERR_BAD_AUTH				/*401*/	,"Bad Authentication - Username or Password"},
		{ERR_NOT_AVAIL_CU			/*402*/	,"An option available only to credited users"},
		{ERR_BLOCKED_UPDATES		/*403*/	,"The hostname specified is blocked for update abuse, please wait 1 minute"},
		{ERR_NO_HOST_EXIST			/*404*/	,"The hostname specified does not exist"},
		{ERR_BLOCKED_AGENT			/*405*/	,"The user agent that was sent has been blocked for not following specifications"},
		{ERR_BAD_HOST_NAME			/*406*/	,"The hostname specified is not a fully-qualified domain name"},
		{ERR_HOST_MISMATCH			/*409*/	,"The hostname specified exists, but not under the username specified"},
		{ERR_SYSTEM_TYPE			/*412*/	,"Bad System type"},
		{ERR_HOST_COUNT				/*413*/	,"Too many or too few hosts found"},
		{ERR_ACCOUNT_TEMP_BLOCK	/*414*/	,"Same IP address update in less than a minute"},
		{ERR_ACCOUNT_BLOCKED		/*415*/	,"Blocked from updating"},
		{ERR_ACCOUNT_EXPIRED		/*480*/	,"The TZO account has expired"},

		{ERR_SERVER_DATABASE		/*500*/	,"TZO Server Database"},
		{ERR_DNS_ERROR				/*506*/	,"DNS Error"},
                #endif
		{0, ""}
};

	static int log_to_file( const int param1, const char* param2 )
	{
		int	id=0;
		FILE	*fpTZO=NULL;
                #if 0
		for (id=0; tlb_TZO[id].http_resp != NULL; id++) {
			if (param1 == tlb_TZO[id].http_resp)
				break;
		}

                if (!tlb_TZO[id].http_resp)
                        sprintf(tlb_TZO[id].description, "%d: %s", param1, param2);
                #else
		char infoDisable1[80]="";
		char infoDisable2[80]="";
		char cLog[80]="tzo_error";
		if( param1 == ERR_FETCHIPADDRESS_FAILED ) {
			/* Fix [E1550] CBTS#26123(P2): TZO status is not correct if it is successful or it can not resolve domain name.
			 * --> If it can not resolve domain name, Status field shows "Name resolve fail.DDNS update fail!"
			 * John.Huang 2011.09.13
			 */
			strcpy(cLog,"all_errresolv");
			sprintf(infoDisable1, "%s",
				"Cannot resolve TZO server name. Please try again later.");
		}
		else if( param1 == ERR_OPENCONNECTION_FAILED
		    || param1 == ERR_SENDTOSOCKET_FAILED
		    || param1 == ERR_READFROMSOCKET_FAILED ) {
			sprintf(infoDisable1, "%s",
				"Cannot contact TZO, network seems down.Please try again later.");
		}
		else if( param1 == ERR_BAD_PACKET_RETURNED ) {
			sprintf(infoDisable1, "%s",
				"Unexpected response from update server.Please try again later.");
		}
		else if ((param1 == 200) || (param1 == 304) || (param1 == 414) || (param1 == 500)) {
			system( "nvram set ddns_tzo_permanent_disable=0" );
			system( "nvram set ddns_tzo_retry_time=600" );
			switch(param1)
			{
			case 200:
				strcpy(cLog,"tzo_good");
				break;
			case 304:
				strcpy(cLog,"tzo_noupdate");
				break;
			case 414:
				system( "nvram set ddns_tzo_retry_time=60" );
				break;
			}
		}
		else {
			sprintf(infoDisable1, "%s", "DDNS has been disabled");
			if ((param1 == 401) || (param1 == 403)) {
				strcat(infoDisable2, " - check settings and try again");
			}
			else if ((param1 == 405) || (param1 == 415) || (param1 == 480)) {
				strcat(infoDisable2, " - please contact TZO");
			}
			system( "nvram set ddns_tzo_permanent_disable=1" );
			switch(param1)
			{
			case 401:
				strcpy(cLog,"tzo_notkey");
				break;
			}
		}
		if( param2 != NULL && strlen(param2) != 0 ) {
			char *pp1 = strstr(param2, "\r\n");
			if (pp1 != NULL)
				*pp1 = '\0';
		}
                //sprintf(tlb_TZO[id].description, "%s%s%s", infoDisable1, (param2!=NULL? param2: ""), infoDisable2);
                #endif
	        if ( (fpTZO = fopen("/tmp/ddns_msg", "w")) != NULL )
		{
			//fprintf(fpTZO, "%s", tlb_TZO[id].description);
			fprintf(fpTZO, "%s", cLog);
			fflush(fpTZO);
			fclose(fpTZO);
			return 1;
		}
		else	return 0;
	}
#else
char TZO_UserAgentString[128] = {"Model-Firmare"} ;
#endif /*TZO_WEB_CLIENT2_SUPPORT*/

/*
 *  This is the version of the release controlled by TZO
 */
/* SGP - changed version to MAJOR.MINOR to
   better comply with Linux package managers */
char TZO_VERSION[32] = {"1.11"} ;

/*
 * These must be filled in with valid information
 */
char szGlobalTZOKey[64] = {""} ;
char szGlobalEmailAddress[64] = {""} ;
char szGlobalDomainName[64] = {""} ;
char szGlobalPort[10] = {"80"} ;
char szGlobalIPaddressFile[200] = {""} ;
char szGlobalConfigFile[200] = {""} ;
int Verbose = 0 ;

#define SIZEOF_IP_ADDR 32

int MemRelease(MEMSTRUCT * lpMemBlock) {
	if (lpMemBlock->lpMem)
		free(lpMemBlock->lpMem) ;
	lpMemBlock->lpMem = 0 ;
	lpMemBlock->Size = 0 ;
	lpMemBlock->Ptr = 0 ;

	return 1 ;
}


int MemCreate(MEMSTRUCT * lpMemBlock, long Size) {
	lpMemBlock->lpMem = malloc(Size) ;
	if (lpMemBlock->lpMem == 0)
		return 0 ;
	memset(lpMemBlock->lpMem,0,Size) ;
	lpMemBlock->Size = Size ;
	lpMemBlock->Ptr = 0 ;
	lpMemBlock->lpMem[0] = 0 ;

	return 1 ;
}


int EvalInt(char * lpMem, int * p, int Count) {
	int val = 0 ;

	while (*p < Count) {
		if (lpMem[*p] != ' ')
			break ;
		(*p) ++ ;
	}

	while (*p < Count) {
		if ((lpMem[*p] < '0') || (lpMem[*p] > '9'))
			break ;
		val = val * 10 + (lpMem[*p] - '0') ;
		(*p) ++ ;
	}

	(*p) ++ ;
	return val ;
}


int OpenConnectionByAddr(unsigned int IPAddress, unsigned short Port, int SocketType)	{
	struct sockaddr_in sin ;
	int err ;
	int RcvBufSize = MAX_MESSAGE_SIZE ;
	int NewSocket = 0 ;


	switch (SocketType)	{
		case UDP_SOCKET : {
			if ((NewSocket = socket(PF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
				return 0 ;
			break ;
		}

		case TCP_SOCKET : {
			if ((NewSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
				return 0 ;

			if ((err = setsockopt(NewSocket, SOL_SOCKET, SO_RCVBUF, (char *)&RcvBufSize, sizeof(int))) != 0) {
				close(NewSocket) ;
				return 0 ;
			}

			sin.sin_family = AF_INET ;
			sin.sin_addr.s_addr = 0 ;
			sin.sin_port = 0 ;
			if ((err = bind(NewSocket, (struct sockaddr *) &sin, sizeof(sin))) != 0) {
				close(NewSocket) ;
				return 0 ;
			}

			sin.sin_family = AF_INET ;
			sin.sin_addr.s_addr = IPAddress ;
			sin.sin_port = htons(Port) ;
			if ((err = connect(NewSocket, (struct sockaddr *) &sin, sizeof(sin))) != 0) {
				err = errno ;
				if (err == WSAEWOULDBLOCK)
					return NewSocket ;
				close(NewSocket) ;
				return 0 ;
			}

			break ;
		}
	}
	return NewSocket ;
}

#ifdef TZO_WEB_CLIENT2_SUPPORT
/* The gethostbyname() use connect() to communicate with DNS server.
   Sometime the function will be blocked for serval minutes.
   So we use alarm()/setjmp()/longjmp() to implement a nonblock gethostbyname().
*/
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
static jmp_buf time_to_wakeup;
static void
dcc_alarm_handler()
{
		longjmp(time_to_wakeup, 1);
}
static struct hostent *
mygethostbyname(char *HostName, int timeout)
{
	void *prev_signal;
	struct hostent *lpHostEnt ;

	prev_signal = signal(SIGALRM, dcc_alarm_handler);

	if(!setjmp(time_to_wakeup)) {
		if( 1 ) fprintf(stderr, "Set ALARM for %d seconds\n", timeout);
		alarm(timeout);	// Enable the alarm

		if( 1 ) fprintf(stderr, "Resolving %s\n", HostName);
		lpHostEnt = gethostbyname(HostName);

		alarm(0);	// disconnect the alarm
		signal(SIGALRM, prev_signal);	// Restore previous behavior

		return lpHostEnt;
	}
	else {
			fprintf(stderr, "Timeout looking for host: %s\n", HostName);
			signal(SIGALRM, prev_signal);
			return NULL;
	}
}
#endif //TZO_WEB_CLIENT2_SUPPORT

unsigned int FetchIPAddress(unsigned char * HostName) {
	struct hostent * lpHostEnt ;
	unsigned int IPAddress = 0 ;
	unsigned char * lpIPAddress = (unsigned char *)&IPAddress ;
	int i ;

	if ((IPAddress = inet_addr((char *)HostName)) != INADDR_NONE)
		return IPAddress ;

#ifdef TZO_WEB_CLIENT2_SUPPORT
	/*[FIX] 2008.10.28
	   If a) unplug the router WAN or b) override local DNS and spoof "linksys.rh.tzo.com" to "echo.tzo.com"
	   Use ALRM signal (3 seconds) to notify WAN unplug.*/
	if( (lpHostEnt = mygethostbyname((char *)HostName, 3)) == NULL ) {
		printf("FetchIPAddress() : Check internet connection\n") ;
		return 0;
	}
#else
	if ((lpHostEnt = gethostbyname((char *)HostName)) == 0)	{
		if ((lpHostEnt = gethostbyname((char *)HostName)) == 0) {
			printf("FetchIPAddress() : Check internet connection\n") ;
			return 0 ;
		}
	}
#endif //TZO_WEB_CLIENT2_SUPPORT

	for (i=0; i<4; i++)
		lpIPAddress[i] = lpHostEnt->h_addr[i] ;

	return IPAddress ;
}


int SendToSocket(int Socket, char * lpRecord, int RecordSize) {
	int BytesSent ;
	int p = 0 ;

	while(p < RecordSize) {
		BytesSent = send(Socket, &lpRecord[p], RecordSize - p, 0) ;
		if (BytesSent == SOCKET_ERROR)
			return FALSE ;
		p += BytesSent ;
	}

	return TRUE ;
}


int FindStringInMem(char * str, char * lpMem, int Offset, int Count) {
	int len = strlen(str) ;
	int last = Count - len + 1 ;
	int i, j ;

	for (i=Offset; i<last; i++) {
		for (j=0; j<len; j++)
			if (lpMem[i + j] != str[j])
				break ;
		if (j == len)
			return i ;
	}

	return -1 ;
}


int ReadFromSocket(int Socket, MEMSTRUCT *lpMemStruct, unsigned int TimeOut)	{
	int p = 0 ;
	int BytesRead ;
	int ContentLength ;
	int mp ;
	time_t WaitTimer = time(NULL) + TimeOut ;
	unsigned short Result ;
	fd_set fSocketArray ;

	memset(&lpMemStruct->lpMem[0], 0, lpMemStruct->Size) ;
	lpMemStruct->Ptr = 0 ;

	while(time(NULL) < WaitTimer)	{
		struct timeval tv = {0,5} ;
		FD_ZERO(&fSocketArray) ;
		FD_SET(Socket, &fSocketArray) ;
		tv.tv_sec = 0 ;
		tv.tv_usec = 5 ;
		Result = select(Socket+1, &fSocketArray, NULL, NULL, &tv) ;

		if (Result == 0) {
			usleep(100) ;
			continue ;
		}

		if ((BytesRead = recv(Socket, &lpMemStruct->lpMem[p], lpMemStruct->Size-10, 0)) == SOCKET_ERROR)
			return 0 ;

		if (BytesRead == 0)
			return 1 ;

		lpMemStruct->lpMem[p + BytesRead] = 0 ;

		p += BytesRead ;

		lpMemStruct->Ptr = p ;

		if ((mp = FindStringInMem("Content-length: ", lpMemStruct->lpMem, 0, p)) < 0)
			if ((mp = FindStringInMem("Content-Length: ", lpMemStruct->lpMem, 0, p)) < 0)
				continue ;

		mp += strlen("Content-length: ") ;

		ContentLength = EvalInt(lpMemStruct->lpMem, &mp, p) ;

		if ((mp = FindStringInMem("\r\n\r\n", lpMemStruct->lpMem, 0, p)) < 0)
			continue ;

		mp += strlen("\r\n\r\n") ;

		if (p >= (ContentLength + mp))
			return 1 ;
	}

	return 0 ;
}


int AppendMem(int op, char * lpMem, char * str) {
	int l = strlen((char *)str) ;
	int i ;

	for (i=0; i<l; i++)
		lpMem[op++] = str[i] ;

	lpMem[op] = 0 ;
	return op ;
}


int FormHTTPRequest(unsigned char * WebHostName, char * FileName, char * lpMem, char * lpArgs) {
	int op = 0 ;
	char ts[512] ;

	sprintf(ts, "%s %s HTTP/1.0\r\n", (lpArgs[0] == 0) ? "GET" : "POST", FileName) ;
	op = AppendMem(op, lpMem, ts) ;

	sprintf(ts, "Host: %s\r\n", WebHostName) ;
	op = AppendMem(op, lpMem, ts) ;

	sprintf(ts, "User-Agent: TZO HTTP Update / Version %s [%s]\r\n", TZO_VERSION, TZO_UserAgentString) ;
	op = AppendMem(op, lpMem, ts) ;

	if (lpArgs[0]) {
		sprintf(ts, "Content-type: application/x-www-form-urlencoded\r\n") ;
		op = AppendMem(op, lpMem, ts) ;

		sprintf(ts, "Content-length: %d\r\n\r\n", (int)strlen((char *)lpArgs)) ;
		op = AppendMem(op, lpMem, ts) ;

		op = AppendMem(op, lpMem, (char *)lpArgs) ;
	} else {
		sprintf(ts, "\r\n") ;
		op = AppendMem(op, lpMem, ts) ;
	}

	return op ;
}

int ShowDataBuf(char * Direction, char *szDataBuf) {
	int i ;
	printf("%s ", Direction) ;
	for (i = 0 ; i < strlen(szDataBuf) ; i++) {
		if (szDataBuf[i] == '\n')
			printf("\n%s ", Direction) ;
		else
			printf("%c", szDataBuf[i]) ;
	}
	printf("\n") ;
	return 1 ;
}


int TzoGetCurrentIP(unsigned char * szCurrentIPAddress) {
	int ServerSocket ;
	MEMSTRUCT DataBuf ;
	unsigned int ServerIPAddress ;
	char szMsg[1024] ;
	int Loc = 0 ;

	szCurrentIPAddress[0] = 0 ;

	if ((MemCreate(&DataBuf, MAX_MESSAGE_SIZE)) == FALSE)  {
		return(ERR_MEMCREATE_FAILED) ;
	}

	if ((ServerIPAddress = FetchIPAddress(TzoEchoServerName)) == 0) {
		if (Verbose)
			printf("* Unable to fetch address to <%s>\n", TzoEchoServerName) ;
		return(ERR_FETCHIPADDRESS_FAILED) ;
	}

	if ((ServerSocket = OpenConnectionByAddr(ServerIPAddress, DefaultHttpPort, TCP_SOCKET)) == INVALID_SOCKET) {
		if (Verbose)
			printf("* Unable to Open connection to <%s>\n", TzoEchoServerName) ;
		return(ERR_OPENCONNECTION_FAILED) ;
	}

	sprintf(szMsg, "/ip.shtml") ;

	DataBuf.Ptr = FormHTTPRequest(TzoEchoServerName, szMsg, DataBuf.lpMem, "") ;

	if (Verbose) {
		printf ("* Data sent to %s on %d\n", TzoEchoServerName, DefaultHttpPort) ;
		ShowDataBuf(">", DataBuf.lpMem) ;
	}

	if ((SendToSocket(ServerSocket, DataBuf.lpMem, DataBuf.Ptr)) == 0) {
		close(ServerSocket) ;
		if (Verbose)
			printf("* Unable to send data to <%s>\n", TzoEchoServerName) ;
		return(ERR_SENDTOSOCKET_FAILED) ;
	}

	if ((ReadFromSocket(ServerSocket, &DataBuf,  15)) == 0) {
		close(ServerSocket) ;
		if (Verbose)
			printf("* Unable to recieve data from <%s>\n", TzoEchoServerName) ;
		return(ERR_READFROMSOCKET_FAILED) ;
	}
	close(ServerSocket) ;

	if (Verbose) {
		printf("* Data read from Echo Server \n") ;
		ShowDataBuf("<", DataBuf.lpMem) ;
	}

	if ((Loc = FindStringInMem("IPAddress:", DataBuf.lpMem, 0, DataBuf.Ptr)) >= 0) {
		int StartLoc = Loc + strlen("IPAddress:") ;
		int i, ii ;
		for (i = StartLoc, ii = 0 ; i < DataBuf.Ptr ; i++)
			szCurrentIPAddress[ii++] = DataBuf.lpMem[i] ;
		szCurrentIPAddress[ii] = 0 ;
	} else {
		if (Verbose)
			printf("* Bad packet data from <%s>\n", TzoEchoServerName) ;
		return(ERR_BAD_PACKET_RETURNED);
	}
	MemRelease(&DataBuf) ;

	return(TRUE) ;
}


int TZOLogon(unsigned char * szCurrentIPAddress, char *szReturnBuffer) {
	int ServerSocket ;
	MEMSTRUCT DataBuf ;
	unsigned int ServerIPAddress ;
	char szMsg[1024], szServerReturnData[200] ;
	int Loc ;

	if ((MemCreate(&DataBuf, MAX_MESSAGE_SIZE)) == FALSE)  {
		return(ERR_MEMCREATE_FAILED) ;	}

	if ((ServerIPAddress = FetchIPAddress(TzoUpdateServerName)) == 0) {
		if (Verbose)
			printf("** Unable to fetch address to <%s>\n", TzoUpdateServerName) ;
		return(ERR_FETCHIPADDRESS_FAILED) ;
	}

	if ((ServerSocket = OpenConnectionByAddr(ServerIPAddress, DefaultHttpPort, TCP_SOCKET)) == INVALID_SOCKET) {
		if (Verbose)
			printf("** Unable to Open connection to <%s>\n", TzoUpdateServerName) ;
		return(ERR_OPENCONNECTION_FAILED) ;
	}

	sprintf(szMsg, "/webclient/tzoperl.html?TZOName=%s&Email=%s&TZOKey=%s&IPAddress=%s&system=tzodns&info=1", szGlobalDomainName, szGlobalEmailAddress, szGlobalTZOKey, szCurrentIPAddress) ;

	DataBuf.Ptr = FormHTTPRequest(TzoUpdateServerName, szMsg, DataBuf.lpMem, "") ;

    if (Verbose) {
		printf("** Data Sent to %s on %d\n", TzoUpdateServerName, DefaultHttpPort) ;
		ShowDataBuf(">>", DataBuf.lpMem) ;
	}

	if ((SendToSocket(ServerSocket, DataBuf.lpMem, DataBuf.Ptr)) == 0) {
		close(ServerSocket) ;
		if (Verbose)
			printf("** Unable to send data to <%s>\n", TzoUpdateServerName) ;
		return(ERR_SENDTOSOCKET_FAILED) ;
	}

	if ((ReadFromSocket(ServerSocket, &DataBuf,  15)) == 0) {
		close(ServerSocket) ;
		if (Verbose)
			printf("** Unable to read data from <%s>\n", TzoUpdateServerName) ;
		return(ERR_READFROMSOCKET_FAILED) ;
	}

	if (Verbose) {
		printf("** Data read from Update Server \n") ;
		ShowDataBuf("<<", DataBuf.lpMem) ;
	}

	if ((Loc = FindStringInMem("\r\n\r\n", DataBuf.lpMem, 0, DataBuf.Ptr)) >= 0) {
		int StartLoc = Loc + strlen("\r\n\r\n") ;
		int i, ii ;
		for (i = StartLoc, ii = 0 ; i < DataBuf.Ptr ; i++)
			szServerReturnData[ii++] = DataBuf.lpMem[i] ;
		szServerReturnData[ii] = 0 ;
		if ((Loc = FindStringInMem("\r\n", szServerReturnData, 0, strlen(szServerReturnData))) >= 0) {
			StartLoc = Loc + strlen("\r\n") ;
			for (i = StartLoc, ii = 0 ; i < strlen(szServerReturnData) ; i++)
				szReturnBuffer[ii++] = szServerReturnData[i] ;
			szReturnBuffer[ii] = 0 ;
		}
	} else {
		close(ServerSocket) ;
		if (Verbose)
			printf("** Bad packet data from <%s>\n", TzoUpdateServerName) ;
		return(ERR_BAD_PACKET_RETURNED);
	}

	close(ServerSocket) ;
	return atoi(szServerReturnData) ;
}

void Usage(unsigned char *szExeName) {
 char szUsageTxt1[500] = {"Usage: %s  [options...]\n\
Tzo Version : %s - Copyright 2007 Tzolkin Corporation\n\
License - GNU GPL v2\n\
\n\
Maintains a TZO Dynamic DNS account. Each time this command is run it\n\
will intelligently determine if the WAN IP has changed, and if so it will\n\
update TZO DNS. After this, the command exits completely.\n\n"} ;

	char szUsageTxt2[500] = {"All installations should consult INSTALL/README docs, however\n\
users of 'TZO Perl' should note changes and migration path. \n\
\n"} ;

	char szUsageTxt3[500] = {" -d Required(*): The TZO Domain Name\n\
 -e Required(*): The email address associated with the TZO DNS Record\n\
 -k Required(*): The assigned TZO Key\n\
 -l Required(*): Log file to store the current IP address\n\
 -u Optional: Supplies extra info for tzoupdate's HTTP USER AGENT\n\
 -f Optional: Specify an alternate .conf file (instead of using args)\n\
 -p Optional: Port used for communication (80|21333) Default is 80\n\
 -v Optional: Verbose information displayed to standard output.\n\n"} ;

	char szUsageTxt4[500] = {"You can use 'tzoupdate' without any arguments at all -- this will\n\
instruct tzoupdate to look for 'tzoupdate.conf' in the current directory.\n\
When -f is used, you must specify the path to the alternate .conf file, \n\
and you may not use -d -e -k -l -p arguments as this would be a conflict.\n\
\n"} ;

	char szUsageTxt5[500] = {"USAGE -- Example #1 using full CLI args (no config file)\n\
%s -d example.tzo.com -e email@email.com -k K123123123123123\n\
-l /tmp/tzoip.log -p 21333\n\n"} ;

	char szUsageTxt6[500] = {"USAGE -- Example #2 specifying a .conf settings file\n\
%s -f ~/etc/tzoupdate.conf\n\
\n\
Exit Codes (for custom wrapper scripts):\n\
0 - Success	(example: DNS update success [or no change])\n\
1 - Minor Error (example: server abuse, > 1 connect within 60 seconds)\n\
2 - Major Error (example: TZO Account expiration)\n\
3 - Fatal Error (example: bad account or bad account info)\n\
4 - Usage Error (example: Conflict arguments vs config file)\n\n"} ;

	char szUsageTxt7[500] = {"Sample Configuration File (one is provided in the download):\n\
 KEY=K123123123123123 {required}\n\
 DOMAIN=yourdomain.tzo.com {required}\n\
 EMAIL=you@email.com {required}\n\
 IPFILE=/tmp/tzoip.tmp {required, user must have write access}\n\
 PORT=80|21333 {optional, defaults to 80}\n"} ;

	printf(szUsageTxt1, (char *)szExeName, TZO_VERSION) ;
	printf(szUsageTxt2) ;
	printf(szUsageTxt3) ;
	printf(szUsageTxt4, (char *)szExeName) ;
	printf(szUsageTxt5, (char *)szExeName) ;
	printf(szUsageTxt6, (char *)szExeName) ;
	printf(szUsageTxt7) ;

	return ;
}


int MemGetData(char *lpMemData, char * lpLineBuf, unsigned int LineBufSize, int * lpInputPtr) {
	unsigned int i ;
	unsigned char NextChar ;

	for (i=0; i<(LineBufSize - 1); i++) {
		NextChar = (unsigned char)lpMemData[*lpInputPtr] ;

		if ((NextChar == 0xd) || (NextChar == 0xa)) {
			lpLineBuf[i] = 0 ;
			if (NextChar == '\r')
				(*lpInputPtr) ++ ;
			(*lpInputPtr) ++ ;
			return 1 ;
		}
		lpLineBuf[i] = NextChar ;
		(*lpInputPtr) ++ ;
	}

	lpLineBuf[i] = 0 ;
	return 0 ;
}


int ReadIPAddressFromFile(char *filename, char *szIpAddress) {
	int hFile ;
	szIpAddress[0] = 0 ;

	if ((hFile = open(filename, O_RDWR, 0640)) < 0)
    	return 0 ;

	read(hFile, szIpAddress, SIZEOF_IP_ADDR) ;

	close(hFile) ;
	return (1) ;
}


int WriteIPAddressFromFile(char *filename, unsigned char *szIpAddress) {
	int hFile ;

	if ((hFile = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0640)) < 0)
    	return 0 ;

	write(hFile, szIpAddress, strlen((char *)szIpAddress)) ;

	close(hFile) ;
	return (1) ;
}


int ParseOptionsFromFile(char *filename) {
	int hFile, start, nCnt ;
	char ConfigFileData[MAX_MESSAGE_SIZE] ;
	char ts[200] ;


/*	if ((hFile = open(filename, O_RDWR, 0640)) < 0) { */
/* sgp 7/17, make open read-only */
	 if ((hFile = open(filename, O_RDONLY, 0640)) < 0) {
		printf("TZO ERROR : Cannot open %s\n\n", filename) ;
		return EXIT_FATAL ;
	}

	if ((nCnt = read(hFile, ConfigFileData, MAX_MESSAGE_SIZE)) <= 0) {
		printf("TZO ERROR : Cannot read %s\n\n", filename) ;
		close (hFile) ;
		return EXIT_FATAL ;
	}

	close(hFile) ;

	if ((start = FindStringInMem("KEY=", ConfigFileData, 0, nCnt)) >= 0) {
		int loc = start + strlen("KEY=") ;
		MemGetData(ConfigFileData, ts, sizeof(ts), &loc) ;
		if (strlen(ts) > sizeof(szGlobalTZOKey)) {
			printf("TZO ERROR : TZO Key is limited to %d bytes\n\n", (int)sizeof(szGlobalTZOKey)) ;
			return EXIT_FATAL ;
		}
		strcpy(szGlobalTZOKey, ts) ;
	}
	if ((start = FindStringInMem("DOMAIN=", ConfigFileData, 0, nCnt)) >= 0) {
		int loc = start + strlen("DOMAIN=") ;
		MemGetData(ConfigFileData, ts, sizeof(ts), &loc) ;
		if (strlen(ts) > sizeof(szGlobalDomainName)) {
			printf("TZO ERROR : Domain Name is limited to %d bytes\n\n", (int)sizeof(szGlobalDomainName)) ;
			return EXIT_FATAL ;
		}
		strcpy(szGlobalDomainName, ts) ;
	}
	if ((start = FindStringInMem("EMAIL=", ConfigFileData, 0, nCnt)) >= 0) {
		int loc = start + strlen("EMAIL=") ;
		MemGetData(ConfigFileData, ts, sizeof(ts), &loc) ;
		if (strlen(ts) > sizeof(szGlobalEmailAddress)) {
			printf("TZO ERROR : Email is limited to %d bytes\n\n", (int)sizeof(szGlobalEmailAddress)) ;
			return EXIT_FATAL ;
		}
		strcpy(szGlobalEmailAddress, ts) ;
	}
	if ((start = FindStringInMem("PORT=", ConfigFileData, 0, nCnt)) >= 0) {
		int loc = start + strlen("PORT=") ;
		MemGetData(ConfigFileData, ts, sizeof(ts), &loc) ;
		if (strlen(ts) > sizeof(szGlobalPort)) {
			printf("TZO ERROR : Port is limited to %d bytes\n\n", (int)sizeof(szGlobalPort)) ;
			return EXIT_FATAL ;
		}
		strcpy(szGlobalPort, ts) ;
	}
	if ((start = FindStringInMem("IPFILE=", ConfigFileData, 0, nCnt)) >= 0) {
		int loc = start + strlen("IPFILE=") ;
		MemGetData(ConfigFileData, ts, sizeof(ts), &loc) ;
		if (strlen(ts) > sizeof(szGlobalIPaddressFile)) {
			printf("TZO ERROR : IP File  is limited to %d bytes\n\n", (int)sizeof(szGlobalIPaddressFile)) ;
			return EXIT_FATAL ;
		}
		strcpy(szGlobalIPaddressFile, ts) ;
	}
	if ((start = FindStringInMem("AGENT=", ConfigFileData, 0, nCnt)) >= 0) {
		int loc = start + strlen("AGENT=") ;
		MemGetData(ConfigFileData, ts, sizeof(ts), &loc) ;
		if (strlen(ts) > sizeof(TZO_UserAgentString)) {
			printf("TZO ERROR : User Agent is limited to %d bytes\n\n", (int)sizeof(TZO_UserAgentString)) ;
			return EXIT_FATAL ;
		}
		if (strcmp(TZO_UserAgentString, "Default") == 0)
			strcpy(TZO_UserAgentString, ts) ;
	}

	return EXIT_OK ;
}


int IsTheFileOld(char * szFilename) {
	struct stat fInfo ;
	time_t ModTime ;
	time_t CurrentTime ;
	#define REFRESH_DAYS (28*24*60*60)

	stat(szFilename, &fInfo) ;

	ModTime = fInfo.st_mtime ;

	CurrentTime = time(NULL) ;

	if ((ModTime + REFRESH_DAYS) > CurrentTime) {
		if (Verbose)
			printf("* The file <%s> is up to date, do not force update...\n", szFilename) ;
		return (0) ;
	}

	if (Verbose)
		printf("* The file <%s> exist (but is older than 28 days); forcing update...\n", szFilename) ;
	return (1) ;
}

void ParseExeName(char *szArgName, unsigned char *szExeName) {
	int i, ii ;
	char szTemp[200] ;

	strcpy(szTemp, szArgName) ;
	for (i = strlen(szTemp) ; i >= 0 ; i--) {
		if (szTemp[i] == '/') {
			i++ ;
			for (ii = 0 ; i+ii < strlen(szTemp) ; ii++)
				szExeName[ii] =  szTemp[ii+i] ;
			szExeName[ii] = 0 ;
			break ;
		}
	}

	if (strlen((char *)szExeName) == 0)
		strcpy((char *)szExeName, szArgName) ;
}


int main(int argc, char *argv[]) {
	unsigned char szCurrrentIpAddress[SIZEOF_IP_ADDR] ;
	unsigned char szLastIpAddress[SIZEOF_IP_ADDR] ;
	unsigned char szReturnBuffer[200] ;
	unsigned char szExeName[100] = {""} ;
	int ReturnVal ;
	int opt ;
	int ForceUpdate = 0 ;
	int FromConfig = 0 ;
	int CmdLineArgs = 0 ;
#ifdef TZO_WEB_CLIENT2_SUPPORT
        int TzoCheckIP = 0;
#endif /*TZO_WEB_CLIENT2_SUPPORT*/

	memset(szCurrrentIpAddress,0,SIZEOF_IP_ADDR) ;
	memset(szLastIpAddress,0,SIZEOF_IP_ADDR) ;

	ParseExeName(argv[0], szExeName) ;

	if (argv[1] != NULL) {
		if (strcmp(argv[1],"--help") == 0) {
			Usage(szExeName) ;
			return (EXIT_OK) ;
		}
	}

    /*
     *  Parse out the command line options.
     */
#ifdef TZO_WEB_CLIENT2_SUPPORT
        while ((opt = getopt(argc, argv, "t:u:f:d:e:k:p:l:hv")) != -1) {
#else
	while ((opt = getopt(argc, argv, "u:f:d:e:k:p:l:hv")) != -1) {
#endif /*TZO_WEB_CLIENT2_SUPPORT*/
		switch (opt) {
			case 'h' :
				Usage(szExeName) ;
				return EXIT_OK ;
#ifdef TZO_WEB_CLIENT2_SUPPORT
                        case 't' :
                                if (strcmp(optarg, "tzo-echo")) {
                                        printf("TZO ERROR : -t only accept tzo-echo\n\n") ;
                                        return EXIT_FATAL ;
                                }
                                TzoCheckIP = 1 ;
                                goto TZO_ECHO;
                                break ;
#endif /*TZO_WEB_CLIENT2_SUPPORT*/
			case 'u' :
				if (strlen(optarg) > sizeof(TZO_UserAgentString)) {
					printf("TZO ERROR : User Agent is limited to %d bytes\n\n", (int)sizeof(TZO_UserAgentString)) ;
					return EXIT_FATAL ;
				}
				strcpy(TZO_UserAgentString, optarg) ;
				break ;
			case 'f' :
				if (strlen(optarg) > sizeof(szGlobalConfigFile)) {
					printf("TZO ERROR : Config file is limited to %d bytes\n\n", (int)sizeof(szGlobalConfigFile)) ;
					return EXIT_FATAL ;
				}
				FromConfig = 1 ;
				strcpy(szGlobalConfigFile, optarg) ;
				break ;
			case 'd' :
				if (strlen(optarg) > sizeof(szGlobalDomainName)) {
					printf("TZO ERROR : Domain Name is limited to %d bytes\n\n", (int)sizeof(szGlobalDomainName)) ;
					return EXIT_FATAL ;
				}
				CmdLineArgs = 1 ;
				strcpy(szGlobalDomainName, optarg) ;
				break ;
			case 'e' :
				if (strlen(optarg) > sizeof(szGlobalEmailAddress)) {
					printf("TZO ERROR : Email is limited to %d bytes\n\n", (int)sizeof(szGlobalEmailAddress)) ;
					return EXIT_FATAL ;
				}
				CmdLineArgs = 1 ;
				strcpy(szGlobalEmailAddress, optarg) ;
				break ;
			case 'k' :
				if (strlen(optarg) > sizeof(szGlobalTZOKey)) {
					printf("TZO ERROR : TZO Key is limited to %d bytes\n\n", (int)sizeof(szGlobalTZOKey)) ;
					return EXIT_FATAL ;
				}
				CmdLineArgs = 1 ;
				strcpy(szGlobalTZOKey, optarg) ;
				break ;
			case 'p' :
				CmdLineArgs = 1 ;
				strcpy(szGlobalPort, optarg) ;
				break ;
			case 'l' :
				if (strlen(optarg) > sizeof(szGlobalIPaddressFile)) {
					printf("TZO ERROR : IP Address file is limited to %d bytes\n\n", (int)sizeof(szGlobalIPaddressFile)) ;
					return EXIT_FATAL ;
				}
				CmdLineArgs = 1 ;
				strcpy(szGlobalIPaddressFile, optarg) ;
				break ;
			case 'v' :
				Verbose = 1 ;
				break ;
		}
	}

	if ((CmdLineArgs) && (FromConfig)) {
		printf("TZO ERROR : Unable to use Config File with specified command line arguments\n") ;
		return EXIT_CONFIG_ERROR ;
	}

	/*
	 * If no command line arguments assume that the user wants to use the config file.
	 */
	if ((CmdLineArgs == 0) && (FromConfig == 0)) {
/*		strcpy(szGlobalConfigFile, "tzoupdate.conf") ; */
/* SGP: assume config is in /etc */
		strcpy(szGlobalConfigFile, "/etc/tzoupdate.conf") ;
		FromConfig = 1 ;
	}

	if (strlen(szGlobalConfigFile)) {
		if ((ParseOptionsFromFile(szGlobalConfigFile)) != EXIT_OK)
			return EXIT_FATAL ;
	}


	if (strlen(szGlobalTZOKey) == 0) {
		printf("TZO ERROR : You must enter a TZO key\n") ;
		printf("type `%s -h` for Help and Usage info.\n", szExeName) ;
		return EXIT_FATAL ;
	}

	if (strlen(szGlobalEmailAddress) == 0) {
		printf("TZO ERROR : You must enter an email address\n") ;
		printf("type `%s -h` for Help and Usage info.\n", szExeName) ;
		return EXIT_FATAL ;
	}

	if (strlen(szGlobalDomainName) == 0) {
		printf("TZO ERROR : You must enter a domain name\n") ;
		printf("type `%s -h` for Help and Usage info.\n", szExeName) ;
		return EXIT_FATAL ;
	}

	if (strlen(szGlobalIPaddressFile) == 0) {
		printf("TZO ERROR : You must enter a filename to store the IP address\n") ;
		printf("type `%s -h` for Help and Usage info.\n", szExeName) ;
		return EXIT_FATAL ;
	}

#ifdef TZO_WEB_CLIENT2_SUPPORT
TZO_ECHO:
#endif /*TZO_WEB_CLIENT2_SUPPORT*/

	DefaultHttpPort = atoi(szGlobalPort) ;
	if ((DefaultHttpPort != 80) && (DefaultHttpPort != 21333)) {
		printf("TZO ERROR : Port <%d> is invalid, port 80 and 21333 supported\n", (int)DefaultHttpPort) ;
		return EXIT_FATAL ;
	}

	if (Verbose)
		printf("* TZO Client Version : <%s>\n", TZO_VERSION) ;

	/*
	 * Get the current external WAN IP address.
	 */
	if ((ReturnVal = TzoGetCurrentIP(szCurrrentIpAddress)) != TRUE) {
		/*[FIX] 2008.10.28
		   If a) unplug the router WAN or b) override local DNS and spoof "linksys.rh.tzo.com" to "echo.tzo.com"
		   It should wipe clean any cached previous status message.*/
		log_to_file(ReturnVal, NULL);
		printf("TZO ERROR : There was a problem getting your current WAN IP address\n") ;
		return EXIT_FATAL ;
	}

	if (Verbose)
		printf("* Your Current Wan IP Address is <%s>\n", szCurrrentIpAddress) ;

#ifdef TZO_WEB_CLIENT2_SUPPORT
        FILE *fpTzoCheckIP = fopen("/tmp/tzo_checkip.txt","w");

        fprintf(fpTzoCheckIP, "%s", szCurrrentIpAddress);
        fclose(fpTzoCheckIP);
        if (TzoCheckIP) {
                return EXIT_OK;
        }
#endif /*TZO_WEB_CLIENT2_SUPPORT*/

	ReadIPAddressFromFile(szGlobalIPaddressFile, (char *)szLastIpAddress) ;

	/*
	 * Check to see if retrieved an IP address from the file.  If we did not
	 * then lets make sure we can write to the file
	 */
	if (strlen((char *)szLastIpAddress) == 0) {
		if ((WriteIPAddressFromFile(szGlobalIPaddressFile, (unsigned char *)"testWrite")) == 0) {
			printf("TZO Error : Unable to access file <%s>\n", szGlobalIPaddressFile) ;
			return EXIT_FATAL ;
		} else {
			printf("* The file <%s> did not exist (looks like a fresh install); forcing update...\n", szGlobalIPaddressFile) ;
		}
	} else {
		/*
		 * Check the timestamp of the file and see if we should force an update, do this
		 * every 28 days as we are just trying to see if we expired...
		 */
		if (IsTheFileOld(szGlobalIPaddressFile) == TRUE)
			ForceUpdate = TRUE ;
	}


	/*
	 * If we have not updated in over 28 days force an update to get expiration.
	 */
	if (!ForceUpdate) {
		/*
		 * If the IP address returned from teh Echo Servers is the same IP Address that is in the
		 * the file, then we can assume that the IP addresses are the same.
		 */
		if (strcmp((char *)szCurrrentIpAddress, (char *)szLastIpAddress) == 0) {
			log_to_file(304,NULL);
			if (Verbose)
				printf("* Your IP address %s has not changed\n",  szLastIpAddress) ;
			return EXIT_OK ;
		}
	}


	/*
	 * Need to update the IP Address on the servers.
	 */
	ReturnVal = TZOLogon(szCurrrentIpAddress, (char *)szReturnBuffer);
	log_to_file( ReturnVal, szReturnBuffer );
	switch (ReturnVal) {
		case UPDATE_SUCCESS :
		case UPDATE_NOCHANGE :
			/*
			 * Do nothing no need to pdate the IP Address
			 */
			if ((WriteIPAddressFromFile(szGlobalIPaddressFile, szCurrrentIpAddress)) == 0) {
				printf("TZO Error : Cannot write to file <%s>\n", szGlobalIPaddressFile) ;
				return EXIT_FATAL ;
			}
			if (Verbose)
				printf("* TzoLogon() : Success\n") ;
			break ;
		case ERR_ACCOUNT_TEMP_BLOCK :
			printf("TZO Warning : \n %s", szReturnBuffer) ;
			return EXIT_TEMP_BLOCK ;
		case ERR_ACCOUNT_EXPIRED :
			printf("TZO Error : \n %s", szReturnBuffer) ;
			return EXIT_EXPIRED ;
		default :
			/*
			 * Fatal error
			 */
			printf("TZO FATAL : \n %s", szReturnBuffer) ;
			return EXIT_FATAL ;
		}

	return EXIT_OK ;
}

