#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#ifdef _PRECISION_SIOCGSTAMP
#include <sys/ioctl.h>
#endif
#include <bcmnvram.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define ENABLE_DEBUG

extern char *optarg;

#ifdef linux
#include <sys/utsname.h>
#include <sys/time.h>
typedef u_int32_t __u32;
#include <sys/timex.h>
#else
#define main ntpclient
extern struct hostent *gethostbyname(const char *name);
extern int h_errno;
#define herror(hostname) \
	fprintf(stderr,"Error %d looking up hostname %s\n", h_errno,hostname)
typedef uint32_t __u32;
#endif

#define JAN_1970        0x83aa7e80      /* 2208988800 1970 - 1900 in seconds */
#define NTP_PORT (123)

/* How to multiply by 4294.967296 quickly (and not quite exactly)
 * without using floating point or greater than 32-bit integers.
 * If you want to fix the last 12 microseconds of error, add in
 * (2911*(x))>>28)
 */
#define NTPFRAC(x) ( 4294*(x) + ( (1981*(x))>>11 ) )

/* The reverse of the above, needed if we want to set our microsecond
 * clock (via settimeofday) based on the incoming time in NTP format.
 * Basically exact.
 */
#define USEC(x) ( ( (x) >> 12 ) - 759 * ( ( ( (x) >> 10 ) + 32768 ) >> 16 ) )

/* Converts NTP delay and dispersion, apparently in seconds scaled
 * by 65536, to microseconds.  RFC1305 states this time is in seconds,
 * doesn't mention the scaling.
 * Should somehow be the same as 1000000 * x / 65536
 */
#define sec2u(x) ( (x) * 15.2587890625 )

struct ntptime {
	unsigned int coarse;
	unsigned int fine;
};

void send_packet(int usd);
void rfc1305print(char *data, struct ntptime *arrival);
void udp_handle(int usd, char *data, int data_len, struct sockaddr *sa_source, int sa_len);

/* global variables (I know, bad form, but this is a short program) */
char incoming[1500];
struct timeval time_of_send;
int live=0;
int set_clock=0;   /* non-zero presumably needs root privs */

#ifdef ENABLE_DEBUG
int debug=0;
#define DEBUG_OPTION "d"
#else
#define debug 0
#define DEBUG_OPTION
#endif

#define BACKOFF_MIN	(60 * 1)	/* 1 minute */
#define BACKOFF_MAX	(60 * 60 * 72)	/* 72 hours */

time_t bkf_start, bkf_current, bkf_interval;

int contemplate_data(unsigned int absolute, double skew, double errorbar, int freq);

int get_current_freq()
{
	/* OS dependent routine to get the current value of clock frequency.
	 */
#ifdef linux
	struct timex txc;
	txc.modes=0;
	if (__adjtimex(&txc) < 0) {
		perror("adjtimex"); exit(1);
	}
	return txc.freq;
#else
	return 0;
#endif
}

int set_freq(int new_freq)
{
	/* OS dependent routine to set a new value of clock frequency.
	 */
#ifdef linux
	struct timex txc;
	txc.modes = ADJ_FREQUENCY;
	txc.freq = new_freq;
	if (__adjtimex(&txc) < 0) {
		perror("adjtimex"); exit(1);
	}
	return txc.freq;
#else
	return 0;
#endif
}

void send_packet(int usd)
{
	__u32 data[12];
	struct timeval now;
#define LI 0
#define VN 3
#define MODE 3
#define STRATUM 0
#define POLL 4 
#define PREC -6

	if (debug) fprintf(stderr,"Sending ...\n");
	if (sizeof(data) != 48) {
		fprintf(stderr,"size error\n");
		return;
	}
	bzero((char*)data,sizeof(data));
	data[0] = htonl (
		( LI << 30 ) | ( VN << 27 ) | ( MODE << 24 ) |
		( STRATUM << 16) | ( POLL << 8 ) | ( PREC & 0xff ) );
	data[1] = htonl(1<<16);  /* Root Delay (seconds) */
	data[2] = htonl(1<<16);  /* Root Dispersion (seconds) */
	gettimeofday(&now,NULL);
	data[10] = htonl(now.tv_sec + JAN_1970); /* Transmit Timestamp coarse */
	data[11] = htonl(NTPFRAC(now.tv_usec));  /* Transmit Timestamp fine   */
	send(usd,data,48,0);
	time_of_send=now;
}


void udp_handle(int usd, char *data, int data_len, struct sockaddr *sa_source, int sa_len)
{
	struct timeval udp_arrival;
	struct ntptime udp_arrival_ntp;

#ifdef _PRECISION_SIOCGSTAMP
	if ( ioctl(usd, SIOCGSTAMP, &udp_arrival) < 0 ) {
		perror("ioctl-SIOCGSTAMP");
		gettimeofday(&udp_arrival,NULL);
	}
#else
	gettimeofday(&udp_arrival,NULL);
#endif
	udp_arrival_ntp.coarse = udp_arrival.tv_sec + JAN_1970;
	udp_arrival_ntp.fine   = NTPFRAC(udp_arrival.tv_usec);

	if (debug) {
		struct sockaddr_in *sa_in=(struct sockaddr_in *)sa_source;
		printf("packet of length %d received\n",data_len);
		if (sa_source->sa_family==AF_INET) {
			printf("Source: INET Port %d host %s\n",
				ntohs(sa_in->sin_port),inet_ntoa(sa_in->sin_addr));
		} else {
			printf("Source: Address family %d\n",sa_source->sa_family);
		}
	}
	rfc1305print(data,&udp_arrival_ntp);
}

double ntpdiff( struct ntptime *start, struct ntptime *stop)
{
	int a;
	unsigned int b;
	a = stop->coarse - start->coarse;
	if (stop->fine >= start->fine) {
		b = stop->fine - start->fine;
	} else {
		b = start->fine - stop->fine;
		b = ~b;
		a -= 1;
	}
	
	return a*1.e6 + b * (1.e6/4294967296.0);
}

char * rfctime(const struct tm *tm)
{
	static char s[201];
	char format[20];

	setenv("TZ", nvram_get("time_zone"), 1);
	memset(format, 0, 20);
	if(nvram_match("date_format", "0"))
		strcat(format, "%d.%m.%Y, ");
	else // date_format == 1
		strcat(format, "%m/%d/%Y, ");

	if(nvram_match("time_format", "0"))
		strcat(format, "%H:%M:%S");
	else // time_format == 1
		strcat(format, "%r");
	strftime(s, 200, format, tm);

	return s;
}

void rfc1305print(char *data, struct ntptime *arrival)
{
/* straight out of RFC-1305 Appendix A */
	int li, vn, mode, stratum, poll, prec;
	int delay, disp, refid;
	struct ntptime reftime, orgtime, rectime, xmttime;
	double etime,stime,skew1,skew2;
	int freq;

#define Data(i) ntohl(((unsigned int *)data)[i])
	li      = Data(0) >> 30 & 0x03;
	vn      = Data(0) >> 27 & 0x07;
	mode    = Data(0) >> 24 & 0x07;
	stratum = Data(0) >> 16 & 0xff;
	poll    = Data(0) >>  8 & 0xff;
	prec    = Data(0)       & 0xff;
	if (prec & 0x80) prec|=0xffffff00;
	delay   = Data(1);
	disp    = Data(2);
	refid   = Data(3);
	reftime.coarse = Data(4);
	reftime.fine   = Data(5);
	orgtime.coarse = Data(6);
	orgtime.fine   = Data(7);
	rectime.coarse = Data(8);
	rectime.fine   = Data(9);
	xmttime.coarse = Data(10);
	xmttime.fine   = Data(11);
#undef Data

       /*John@2008.05.21,validate LI ,VN etc*/
        if((li > 2 || li < 0) //li must be in 0, 1, 2
                || (vn <= 0 || vn >= 4) //vn must be in 1, 2, 3
                || (xmttime.coarse == 0 && xmttime.fine == 0)) //Transmit Time Stamp must not be zero
        {//FIXME: Need check other fields???
                fprintf(stderr, "Receive an invalid NTP packet, fail to update, current time is not available.");
                return -1;
        }

	if (set_clock) {   /* you'd better be root, or ntpclient will crash! */
		struct timeval tv_set;
		struct tm tm;
		char buf[64];
		/* it would be even better to subtract half the slop */
		tv_set.tv_sec  = xmttime.coarse - JAN_1970;
		/* divide xmttime.fine by 4294.967296 */
		tv_set.tv_usec = USEC(xmttime.fine);
		if (settimeofday(&tv_set,NULL)<0) {
			perror("settimeofday");
			exit(1);
		}
		memcpy(&tm, localtime(&tv_set.tv_sec), sizeof(struct tm));
		sprintf(buf, "%ld", tv_set.tv_sec);
		nvram_set("ntp_last_sync", buf);
		if (debug) {
			printf("set time to %lu.%.6lu\n", tv_set.tv_sec, tv_set.tv_usec);
		}
	}

	if (debug) {
	printf("LI=%d  VN=%d  Mode=%d  Stratum=%d  Poll=%d  Precision=%d\n",
		li, vn, mode, stratum, poll, prec);
	printf("Delay=%.1f  Dispersion=%.1f  Refid=%u.%u.%u.%u\n",
		sec2u(delay),sec2u(disp),
		refid>>24&0xff, refid>>16&0xff, refid>>8&0xff, refid&0xff);
	printf("Reference %u.%.10u\n", reftime.coarse, reftime.fine);
	printf("Originate %u.%.10u\n", orgtime.coarse, orgtime.fine);
	printf("Receive   %u.%.10u\n", rectime.coarse, rectime.fine);
	printf("Transmit  %u.%.10u\n", xmttime.coarse, xmttime.fine);
	printf("Our recv  %u.%.10u\n", arrival->coarse, arrival->fine);
	}
	etime=ntpdiff(&orgtime,arrival);
	stime=ntpdiff(&rectime,&xmttime);
	skew1=ntpdiff(&orgtime,&rectime);
	skew2=ntpdiff(&xmttime,arrival);
	freq=get_current_freq();
	if (debug) {
	printf("Total elapsed: %9.2f\n"
	       "Server stall:  %9.2f\n"
	       "Slop:          %9.2f\n",
		etime, stime, etime-stime);
	printf("Skew:          %9.2f\n"
	       "Frequency:     %9d\n"
	       " day   second     elapsed    stall     skew  dispersion  freq\n",
		(skew1-skew2)/2, freq);
	}
	if (debug) {
	printf("%d %5d.%.3d  %8.1f %8.1f  %8.1f %8.1f %9d\n",
		arrival->coarse/86400+15020, arrival->coarse%86400,
		arrival->fine/4294967, etime, stime,
		(skew1-skew2)/2, sec2u(disp), freq);
	fflush(stdout);
	}
	if (live) {
		int new_freq;
		new_freq = contemplate_data(arrival->coarse, (skew1-skew2)/2,
			etime+sec2u(disp), freq);
		if (!debug && new_freq != freq) set_freq(new_freq);
	}
}

// LEO: When host is unknown, just return result but not to exit.
// void stuff_net_addr(struct in_addr *p, char *hostname)
int stuff_net_addr(struct in_addr *p, char *hostname, int ver)
{
	struct hostent *ntpserver;
	ntpserver=gethostbyname(hostname);
	if (ntpserver == NULL) {
		herror(hostname);
		return 1;
	}
	if (ntpserver->h_length != 4) {
		fprintf(stderr,"oops %d\n",ntpserver->h_length);
		return 1;
	}
	memcpy(&(p->s_addr),ntpserver->h_addr_list[0],4);
	return 0;
}

int stuff_net_addr6(struct in6_addr *p, char *hostname, int ver)
{
	struct hostent *ntpserver;
	ntpserver = gethostbyname2(hostname, AF_INET6);
	if (ntpserver == NULL) {
		herror(hostname);
		return 1;
	}

	memcpy(&(p->s6_addr), ntpserver->h_addr_list[0], 16);
	
	return 0;
}

void setup_receive(int usd, unsigned int interface, short port, int ver)
{
	struct sockaddr_in sa_rcvr;
	struct sockaddr_in6 sa_rcvr6;
	bzero((char *) &sa_rcvr, sizeof(sa_rcvr));

	if (ver == 4){
	sa_rcvr.sin_family=AF_INET;
	sa_rcvr.sin_addr.s_addr=htonl(interface);
	sa_rcvr.sin_port=htons(port);
	if(bind(usd,(struct sockaddr *) &sa_rcvr,sizeof(sa_rcvr)) == -1) {
		fprintf(stderr,"could not bind to udp port %d\n",port);
		perror("bind");
		exit(1);
	}
	}else{
		sa_rcvr6.sin6_family=AF_INET6;
		inet_pton(AF_INET6, "::", &sa_rcvr6.sin6_addr);
		sa_rcvr6.sin6_port = htons(port);
		if(bind(usd, (struct sockaddr *) &sa_rcvr6, sizeof(sa_rcvr6)) == -1) {
			fprintf(stderr, "could not bind to udp port %d\n", port);
			perror("bind");
			exit(1);
		}
	}
	listen(usd,3);
}

// LEO: When host is unknown, just return result but not to exit.
// void setup_transmit(int usd, char *host, short port)
int setup_transmit(int usd, char *host, short port, int ver)
{
	struct sockaddr_in sa_dest;
	struct sockaddr_in6 sa_dest6;
	int result;
	bzero((char *) &sa_dest, sizeof(sa_dest));
	bzero((char *) &sa_dest6, sizeof(sa_dest6));
	
	if (ver == 4){
	sa_dest.sin_family=AF_INET;
		result=stuff_net_addr(&(sa_dest.sin_addr), host, ver);
		if(result) {
			return 1;
		}
	sa_dest.sin_port=htons(port);
	if (connect(usd,(struct sockaddr *)&sa_dest,sizeof(sa_dest))==-1)
		{
			perror("(ntpclient) connect");
			return 1;
		}
	}else{
		sa_dest6.sin6_family=AF_INET6;
		result = stuff_net_addr6(&(sa_dest6.sin6_addr), host, ver);
		if(result) {
			return 1;
		}
		sa_dest6.sin6_port = htons(port);
		if (connect(usd, (struct sockaddr *)&sa_dest6, sizeof(sa_dest6))==-1)
		{
			perror("(ntpclient) connect");
			return 1;
		}
	}
	
	return 0;
}

int primary_loop(int usd, int num_probes, int cycle_time)
{
	fd_set fds;
	struct sockaddr sa_xmit;
	int i, pack_len, sa_xmit_len, probes_sent;
	struct timeval to;
	int is_sent = 0; /* 1: ntp request is sent. 0: ntp response is received. */

	if (debug) fprintf(stderr, "Listening...\n");

	probes_sent=0;
	sa_xmit_len=sizeof(sa_xmit);
	/* Don't send when sending first packet */
	to.tv_sec=0;
	to.tv_usec=0;

	for (;;) {
		FD_ZERO(&fds);
		FD_SET(usd,&fds);

		i=select(usd+1,&fds,NULL,NULL,&to);  /* Wait on read or error */
		if(i==0 && to.tv_sec == 0 && !FD_ISSET(usd, &fds)) {
			if(is_sent == 0) {
				send_packet(usd);
				++probes_sent;
//				to.tv_sec=5; /* timeout for ntp response */
				to.tv_sec=cycle_time;
				to.tv_usec=0;
				is_sent=1;
			continue;
		}
			else {
				/* timeout but no response (NTP server)... */
				return -1;
			}
		}

		pack_len=recvfrom(usd,incoming,sizeof(incoming),0,
				&sa_xmit, (socklen_t *)&sa_xmit_len);
		if (pack_len<0) {
			perror("recvfrom");
			return -1;
		} else if (pack_len>0 && pack_len<sizeof(incoming)){
			int stratum;
#define Incoming(i) ntohl(((unsigned int *)incoming)[i])
			stratum = Incoming(0) >> 16 & 0xff;
			if(stratum == 0) {
				fprintf(stderr, "KoD packet. try alternate server or exponential backoff.\n");
				return -1;
			}
			udp_handle(usd,incoming,pack_len,&sa_xmit,sa_xmit_len);
//			bkf_start = time(0);		/* save backoff start time */
//			bkf_interval = BACKOFF_MIN;	/* reset interval to default */
			/* update success, wait cycle_time */
			to.tv_sec = cycle_time; /* ntp update interval */
			to.tv_usec = 0;
			is_sent = 0;
		} else {
			fprintf(stderr, "Ooops.  pack_len=%d\n",pack_len);
			fflush(stderr);
			return -1;
		}

		if ((num_probes != 0) && (probes_sent >= num_probes))
			break;
	}
	return 0;
}

void do_replay(void)
{
	char line[100];
	int n, day, freq, absolute;
	float sec, etime, stime, disp;
	double skew, errorbar;
	int simulated_freq = 0;
	unsigned int last_fake_time = 0;
	double fake_delta_time = 0.0;

	while (fgets(line,sizeof(line),stdin)) {
		n=sscanf(line,"%d %f %f %f %lf %f %d",
			&day, &sec, &etime, &stime, &skew, &disp, &freq);
		if (n==7) {
			fputs(line,stdout);
			absolute=(day-15020)*86400+(int)sec;
			errorbar=etime+disp;
			if (debug) printf("contemplate %u %.1f %.1f %d\n",
				absolute,skew,errorbar,freq);
			if (last_fake_time==0) simulated_freq=freq;
			fake_delta_time += (absolute-last_fake_time)*((double)(freq-simulated_freq))/65536;
			if (debug) printf("fake %f %d \n", fake_delta_time, simulated_freq);
			skew += fake_delta_time;
			freq = simulated_freq;
			last_fake_time=absolute;
			simulated_freq = contemplate_data(absolute, skew, errorbar, freq);
		} else {
			fprintf(stderr,"Replay input error\n");
			exit(2);
		}
	}
}

void usage(char *argv0)
{
	fprintf(stderr,
	"Usage: %s [-c count] [-d] -h hostname [-i interval] [-l]\n"
	"\t[-p port] [-r] [-s] [-v version] \n",
	argv0);
}

/* Copy each token in wordlist delimited by space into word */
#define foreach(word, wordlist, next) \
	for (next = &wordlist[strspn(wordlist, " ")], \
	     strncpy(word, next, sizeof(word)), \
	     word[strcspn(word, " ")] = '\0', \
	     word[sizeof(word) - 1] = '\0', \
	     next = strchr(next, ' '); \
	     strlen(word); \
	     next = next ? &next[strspn(next, " ")] : "", \
	     strncpy(word, next, sizeof(word)), \
	     word[strcspn(word, " ")] = '\0', \
	     word[sizeof(word) - 1] = '\0', \
	     next = strchr(next, ' '))

int main(int argc, char *argv[])
{
	int usd;  /* socket */
	int c;
	/* These parameters are settable from the command line
	   the initializations here provide default behavior */
	short int udp_local_port=0;   /* default of 0 means kernel chooses */
	int cycle_time=3;          /* request timeout in seconds */
	int probe_count=0;            /* default of 0 means loop forever */
	/* int debug=0; is a global above */
	char hostnames[256]="";
	int replay=0;                 /* replay mode overrides everything */
	/* The variable(ntps) maybe used to store IPv6 address, so its length should be greater than 39 bytes */
	char ntps[64]="";
	char *next=NULL;
	int res=1; //barry add 20031009 BCM
	int unknown_host=0;
	int ntpclient_ver=4;
	struct addrinfo *hres;
	int errorhost;

	FILE *fb_fp; /* file for first boot check */
	int first_boot=0;
	time_t seed_time;
	long int seed_mac=atoi(nvram_safe_get("wan_mac"));
	long int rand_delay=0;
	int lock_fd; /* file for checking only one process execute in background */

	if((fb_fp = fopen("/tmp/ntp_firstboot", "r")) == NULL) {
		first_boot = 1;
		fprintf(stderr, "File /tmp/ntp_firstboot not exist!, First boot!!\n");
		if((fb_fp = fopen("/tmp/ntp_firstboot", "w")) == NULL ) {
			fprintf(stderr, "Open file /tmp/ntp_firstboot failed.\n");
			return -1;
		}
		fputs("first booted!\n", fb_fp);
		fclose(fb_fp);
	}

//	/* daemonize first then checking lock file */
//	daemon(1, 1);
 
	lock_fd = open("/var/lock/ntpclient", O_CREAT|O_TRUNC|O_WRONLY);
	if(-1 == lock_fd) {
		fprintf(stderr, "Create /var/lock/ntpclient file FAIL.");
		return -1;
	}
	if(-1 == lockf(lock_fd, F_TLOCK, 0)) {
		if(-1 == close(lock_fd)) {
			fprintf(stderr, "Close /var/lock/ntpclient file FAIL.");
		}
		return -1;
	}

	if(first_boot) {
		time(&seed_time);
		srandom(seed_time + seed_mac);
		rand_delay = 60 + (random() % 240); /* between 1 to 5 minutes */
	}
	
	for (;;) {
		c = getopt( argc, argv, "c:" DEBUG_OPTION "h:i:p:lrs");
		if (c == EOF) break;
		switch (c) {
			case 'c':
				probe_count = atoi(optarg);
				break;
#ifdef ENABLE_DEBUG
			case 'd':
				++debug;
				break;
#endif
			case 'h':
			  {
				int ii, aa=0;
				for(ii=0;ii<argc;ii++)
					if(!strcmp(argv[ii],"-h"))  { break; }

				for(aa=(ii+1); aa < argc; aa++) {
					if(argv[aa][0] != '-') {
						strncat(hostnames, argv[aa], sizeof(hostnames));
						strcat(hostnames, " ");
					}
					else { break;  /* reach next option (-?) */ }
				}
//				fprintf(stderr, "%s\n", hostnames);
//				fflush(stderr);
			  }
				break;
			case 'i':
				cycle_time = atoi(optarg);
				break;
			case 'l':
				live++;
				break;
			case 'p':
				udp_local_port = atoi(optarg);
				break;
			case 'r':
				replay++;
				break;
			case 's':
				set_clock = 1;
				probe_count = 1;
				break;
			default:
				usage(argv[0]);
				exit(1);
		}
	}

//	if(first_boot) {
//		fprintf(stderr, "Random delay %d seconds for ntpclient\n", rand_delay);
//		//sleep(rand_delay);
//	}

	if (replay) {
		do_replay();
		exit(0);
	}

//	if (hostname == NULL) {
//		usage(argv[0]);
//		exit(1);
//	}

	if (debug) {
		fprintf(stderr, 
			"Configuration:\n"
		"  -c probe_count %d\n"
		"  -d (debug)     %d\n"
		"  -h hostname    %s\n"
		"  -i interval    %d\n"
		"  -l live        %d\n"
		"  -p local_port  %d\n"
		"  -s set_clock   %d\n",
			probe_count, debug, hostnames, cycle_time,
		live, udp_local_port, set_clock);
		fflush(stderr);
	}

	bkf_start = time(0); /* save backoff start time */
	bkf_current = time(0);
	bkf_interval = BACKOFF_MIN;

	struct addrinfo hints;

	memset(&hints, 0, sizeof(struct addrinfo));
	//hints.ai_family = AF_UNSPEC;  /* allow both IPv6 and IPv4 by default */
	hints.ai_family = AF_INET;
	//hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

//	while (bkf_current - bkf_start < /*BACKOFF_MAX*/ cycle_time) {
	foreach(ntps, hostnames, next) {
		if( !strcmp(ntps, "6")) {
			memset(&hints, 0, sizeof(struct addrinfo));
			//hints.ai_family = AF_UNSPEC;
			//hints.ai_family = AF_INET;
			hints.ai_family = AF_INET6;  /* allow IPv6 */
			hints.ai_socktype = SOCK_DGRAM;
			hints.ai_flags = 0;
			hints.ai_protocol = 0;
			continue;
		}
		else if( !strcmp(ntps, "4")) {
			memset(&hints, 0, sizeof(struct addrinfo));
			//hints.ai_family = AF_UNSPEC;
			hints.ai_family = AF_INET;  /* allow IPv4 */
			//hints.ai_family = AF_INET6;
			hints.ai_socktype = SOCK_DGRAM;
			hints.ai_flags = 0;
			hints.ai_protocol = 0;
			continue;
		}

		/* Startup sequence */
		errorhost = getaddrinfo(ntps, NULL, &hints, &hres);
		if (errorhost != 0)
			exit(1);

		ntpclient_ver = (hres->ai_family == AF_INET) ? 4 : 6;
		if ((usd = socket(hres->ai_family, SOCK_DGRAM, IPPROTO_UDP)) == (-1))
		{
			perror ("socket");
			exit(1);
		}

		setup_receive(usd, INADDR_ANY, udp_local_port, ntpclient_ver);

		unknown_host = setup_transmit(usd, ntps, NTP_PORT, ntpclient_ver);
		if(unknown_host)
		{
			close(usd);
			continue;
		}

		if (!primary_loop(usd, probe_count, cycle_time)) {
			close(usd);
			res=0; //barry add 20031009 BCM
			break;
		} else {
			/* no any response (NTP server) from this host... */
			close(usd);
			continue;
		}

		close(usd);
	}
	
	if(unknown_host)  { res=1; }

//		sleep(bkf_interval);
//		bkf_interval *= 2;
//		bkf_current = time(0);
//	}
	return res;
}
