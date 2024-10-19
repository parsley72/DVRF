/* dnsmasq is Copyright (c) 2000 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
*/

/* See RFC1035 for details of the protocol this code talks. */

/* Author's email: simon@thekelleys.org.uk */

#include "dnsmasq.h"

#ifdef HAVE_IPV6
static int bind_wanport6(int peerfd);
#endif
static int sighup, sigusr1;

/* ******* zg porting DWG814I Source code on 2006.11.06 ******* */
/* ******* To fixed cdrouterv3.3 item 333(dna_45) item 334(dns_45) failed bug ******* */
struct DNS_MSG_BUF dnsMsgBuf[DNS_MSG_BUF_NUM];
                                                                                
static void rand_port(int *port);
static int bind_wanport(int peerfd);
                                                                                
void init_dns_msg_buf(void)
{
        int i;
                                                                                
                                                                                
        for(i = 0; i < DNS_MSG_BUF_NUM; i++)
        {
                dnsMsgBuf[i].usedflag = 0;
        }
}
struct DNS_MSG_BUF * get_dns_msg_buf(void)
{
        static int i;
        int ii;
                                                                                
                                                                                
        for(ii = i++; i != ii; i++)
        {
                i %= DNS_MSG_BUF_NUM;
                if(dnsMsgBuf[i].usedflag == 0)
                {
                        dnsMsgBuf[i].usedflag = 1;
                        //DBG_printf("get dnsMsgBuf\n");
                        return &dnsMsgBuf[i];
                }
        }
                                                                                
                                                                                
        //DBG_printf("dnsMsgBuf is full\n");
        return NULL;
}
void free_dns_msg_buf(struct DNS_MSG_BUF * dnsMsgBufPtr)
{
        if(dnsMsgBufPtr != NULL)
        {
                dnsMsgBufPtr->usedflag = 0;
                //DBG_printf("free dnsMsgBuf\n");
        }
}
                                                                                
                                                                                
extern struct frec *ftab;
#define WAIT_TIMEOUT 5
                                                                                
#define DNS_TIMER 1
//junzhao 2004.5.31
void check_servers_response(int peerfd, int peerfd6, int strict_order, char *dnamebuff)
{
        time_t now = time(NULL);
        int i;
        struct frec *f;
        static char packet[sizeof(HEADER) + 1];
        static HEADER *header = (HEADER *)packet;
                                                                                
                                                                                
        for(i=0; i<FTABSIZ; i++)
        {
                f = &ftab[i];
                                                                                
                                                                                
                 if(f->new_id == 0)
                {
                        continue;
                }
                if(f->dnsMsgBufPtr != NULL)
                {
                        if(now - (f->time) >= DNS_TIMER)
                        {
                                                                                
                                                                                
                                //DBG_printf("Wait for dns response time out and forward query to next server ...\n");
                                if(reforward_query(f, peerfd, peerfd6, strict_order, dnamebuff) == 0)
                                {
                                        f->time = now;
                                        continue;
                                }
                                else
                                {
                                        //DBG_printf("we tried all without success and time out, delete dnsMsgBuf\n");
                                        free_dns_msg_buf(f ->dnsMsgBufPtr);
                                        f ->dnsMsgBufPtr = NULL;
                                }
                        }
                }
                else if(now - (f->time) >= WAIT_TIMEOUT)
                {
                        memset(packet, 0, sizeof(packet));
                        /* could not send on, return empty answer */
                        header->id = htons(f->orig_id);
                        header->qr = 1; /* response */
                        header->aa = 0; /* authoritive - never */
                        header->ra = 1; /* recursion if available */
                        header->tc = 0; /* not truncated */
                        header->rcode = NOERROR; /* no error */
                        header->ancount = htons(0); /* no answers */
                        header->nscount = htons(0);
                        header->arcount = htons(0);
                        sendto(f->fd, packet, sizeof(packet), 0, &f->source.sa, sa_len(&f->source));
                        f->new_id = 0; /* cancel */
                }
        }
        return;
}
/* ******* end by zg porting DWG814I Source code on 2006.11.06 ******* */

static void sig_handler(int sig)
{
  if (sig == SIGHUP)
    sighup = 1;
  else if (sig == SIGUSR1)
    sigusr1 = 1;
}


#ifdef CUSTOM404_SUPPORT
extern int ctm404_enable ;
extern int wan_link;
extern char domain_name[MAXDNAME+1];
#endif
extern char lan_ipaddr[20];
#ifdef ROUTER_URL_SUPPORT
extern char router_url_address[60];
#endif

int main (int argc, char **argv)
{
  int i;
  int cachesize = CACHESIZ;
  int port = NAMESERVER_PORT;
  unsigned int options;
  int first_loop = 1;
#if 1 //def MPPPOE_SUPPORT
  unsigned long time_to_live = 0;
#endif
#ifdef HAVE_FILE_SYSTEM
  int logged_resolv = 0, logged_lease = 0; 
  char *resolv = RESOLVFILE;
  char *runfile = RUNFILE;
  time_t resolv_changed = 0;
  char *lease_file = NULL;
  off_t lease_file_size = (off_t)0;
  ino_t lease_file_inode = (ino_t)0;
#endif
  struct irec *iface;
  int peerfd = 0, peerfd6 = 0;
  struct irec *interfaces = NULL;
  char *mxname = NULL;
  char *mxtarget = NULL;
  char *domain_suffix = NULL;
  char *username = CHUSER;
  struct iname *if_names = NULL;
  struct iname *if_addrs = NULL;
  struct server *serv_addrs = NULL;
  char *dnamebuff, *packet;
  struct server *servers, *last_server;
  int read_peerfd = -1;
 
  sighup = 1; /* init cache the first time through */
  sigusr1 = 0; /* but don't dump */
  signal(SIGUSR1, sig_handler);
  signal(SIGHUP, sig_handler);

  /* These get allocated here to avoid overflowing the small stack
     on embedded systems. dnamebuff is big enough to hold one
     maximal sixed domain name and gets passed into all the processing
     code. We manage to get away with one buffer. */
  dnamebuff = safe_malloc(MAXDNAME);
  /* Size: we check after adding each record, so there must be 
     memory for the largest packet, and the largest record */
  packet = safe_malloc(DNSPACKETSZ);

//add by michael to support custom404 page at 20081215
#ifdef CUSTOM404_SUPPORT
{
	ctm404_enable = 0;
#if 0
	time_t tmp;
	struct tm *p;
	time(&tmp);
	p = localtime(&tmp);
	fprintf(stderr,"the dnsmasq_process start time is:[%d/%d/%d--%d:%d:%d]\n",(1900+p->tm_year),(1+p->tm_mon),(p->tm_mday),p->tm_hour,p->tm_min,p->tm_sec);
#endif
#if 0
	FILE *fp_tmp;
	if((fp_tmp = fopen("/tmp/.ctm404","r")) != NULL)
	{
		char tmp[4];
		memset(tmp,'\0',sizeof(tmp));
		fgets(tmp,sizeof(tmp),fp_tmp);
		ctm404_enable = atoi(tmp);
		fclose(fp_tmp);
	}
#else
	if(nvram_get("ctm404_enable") != NULL)
		ctm404_enable = atoi(nvram_get("ctm404_enable"));
	//add by michael to fix to disable CWA wan wan is down at 20090224
	wan_link = 0;
	wan_link = check_wan_link(0);
	
//add by michael to fix the wan domain issue at 20090312
	memset(domain_name,0,sizeof(domain_name));
	if(nvram_get("wan_domain") != NULL && strcmp(nvram_get("wan_domain"),"") != 0)
		strncpy(domain_name,nvram_get("wan_domain"),sizeof(domain_name));
	else if(nvram_get("wan_get_domain") != NULL && strcmp(nvram_get("wan_get_domain"),"") != 0)
		strncpy(domain_name,nvram_get("wan_get_domain"),sizeof(domain_name));
#endif	
}
#endif
	memset(lan_ipaddr,0,sizeof(lan_ipaddr));
	if(nvram_get("lan_ipaddr") != NULL)
		strncpy(lan_ipaddr,nvram_get("lan_ipaddr"),sizeof(lan_ipaddr));
	else
		strncpy(lan_ipaddr,"192.168.1.1",sizeof(lan_ipaddr));

#ifdef ROUTER_URL_SUPPORT
	memset(router_url_address,0,sizeof(router_url_address));
	if(nvram_get("router_url_address") != NULL)
		strncpy(router_url_address,nvram_get("router_url_address"),sizeof(router_url_address));
	else
		//Jemmy add for new model E300 2009.9.17
#if (LINKSYS_MODEL == E300)
		strncpy(router_url_address,"http://E300.com",sizeof(router_url_address));
#elif (LINKSYS_MODEL == E1550)
		strncpy(router_url_address,"http://E1550.com",sizeof(router_url_address));
#elif (LINKSYS_MODEL == E2500)
		strncpy(router_url_address,"http://E2500.com",sizeof(router_url_address));
#elif (LINKSYS_MODEL == E3200)
		strncpy(router_url_address,"http://E3200.com",sizeof(router_url_address));
#elif (LINKSYS_MODEL == E4200)
		strncpy(router_url_address,"http://E4200.com",sizeof(router_url_address));
#else
#error "Unknown Model!!!"
#endif
#endif

#ifdef HAVE_FILE_SYSTEM
  options = read_opts(argc, argv, dnamebuff, &resolv, &mxname, &mxtarget, &lease_file,
		      &username, &domain_suffix, &runfile, &if_names, &if_addrs, 
		      &serv_addrs, &cachesize, &port, &time_to_live,&read_peerfd) ;
#else
  options = read_opts(argc, argv, dnamebuff, NULL, &mxname, &mxtarget, NULL,
		      &username, &domain_suffix, NULL, &if_names, &if_addrs, 
		      &serv_addrs, &cachesize, &port, &time_to_live,&read_peerfd) ;
#endif
  
#if 0  
//Fixed 2008/08/11 random port
  /* peerfd is not bound to a low port
     so that we can send queries out on it without them getting
     blocked at firewalls */
  
  if ((peerfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1 && 
      errno != EAFNOSUPPORT &&
      errno != EINVAL)
    die("dnsmasq: cannot create socket: %s", NULL);
  
#ifdef HAVE_IPV6
  if ((peerfd6 = socket(AF_INET6, SOCK_DGRAM, 0)) == -1 && 
      errno != EAFNOSUPPORT &&
      errno != EINVAL)
    die("dnsmasq: cannot create IPv6 socket: %s", NULL);
#else
  peerfd6 = -1;
#endif
#endif
   
  peerfd = bind_wanport(peerfd);
#ifdef HAVE_IPV6
  peerfd6 = bind_wanport6(peerfd6);
#else
  peerfd6 = -1;
#endif
  
  if (peerfd == -1 && peerfd6 == -1)
    die("dnsmasq: no kernel support for IPv4 _or_ IPv6.", NULL);
  
  forward_init(1);

  cache_init(cachesize, options & OPT_LOG);

  /* ******* zg porting DWG814I Source code on 2006.11.06 ******* */
  /* ******* To fixed cdrouterv3.3 item 333(dna_45) item 334(dns_45) failed bug ******* */
  init_dns_msg_buf();
  
  setbuf(stdout, NULL);

#ifdef HAVE_FILE_SYSTEM
  if (!(options & OPT_DEBUG))
    {
      FILE *pidfile;
      struct passwd *ent_pw;
        
      /* The following code "daemonizes" the process. 
	 See Stevens section 12.4 */

#ifdef HAVE_FORK
      if (fork() != 0 )
	exit(0);
      
      setsid();
      
      if (fork() != 0)
	exit(0);
#endif
      
      interfaces = find_all_interfaces(if_names, if_addrs, port);
      
      /* open a socket bound to NS port on each local interface.
         this is necessary to ensure that our replies originate from
         the address they were sent to. See Stevens page 531 */
      for (iface = interfaces; iface; iface = iface->next)
      {
    	  /* 2010-12-07 ruby add to support IPv6 */
    	  char temp[256]="";
    	  switch(iface->addr.sa.sa_family)
    	  {
    	  case AF_INET:
    		  inet_ntop(AF_INET, &iface->addr.in.sin_addr, temp, 256);
    		  fprintf(stderr, "[Dnsmasq], socket AF_INET: %s\n", temp);
    		  break;
#ifdef HAVE_IPV6
    	  case AF_INET6:
    		  inet_ntop(AF_INET6, &iface->addr.in6.sin6_addr, temp, 256);
    		  fprintf(stderr, "[Dnsmasq], socket AF_INET6: %s, Interface-ID: %d\n", 
    				  temp, iface->addr.in6.sin6_scope_id);
    		  break;
#endif
    	  }
    	  //////////
    	  if ((iface->fd = socket(iface->addr.sa.sa_family, SOCK_DGRAM, 0)) == -1)
    		  die("cannot create socket: %s", NULL);

    	  if (bind(iface->fd, &iface->addr.sa, sa_len(&iface->addr)))
    		  die("bind failed: %s", NULL);
      }
      
      chdir("/");
      umask(022); /* make pidfile 0644 */
      
      /* write pidfile _after_ forking ! */
      if (runfile && (pidfile = fopen(runfile, "w")))
      	{
	  fprintf(pidfile, "%d\n", (int) getpid());
	  fclose(pidfile);
	}
      
      umask(0);

      for (i=0; i<64; i++)
	{
	  if (i == peerfd || i == peerfd6)
	    continue;
	  for (iface = interfaces; iface; iface = iface->next)
	    if (iface->fd == i)
	      break;
	  if (!iface)
	    close(i);
	}

      /* Change uid and gid for security */
      if (username && (ent_pw = getpwnam(username)))
	{
	  gid_t dummy;
	  struct group *gp;
	  /* remove all supplimentary groups */
	  setgroups(0, &dummy);
	  /* change group to "dip" if it exists, for /etc/ppp/resolv.conf 
	     otherwise get the group for "nobody" */
	  if ((gp = getgrnam("dip")) || (gp = getgrgid(ent_pw->pw_gid)))
	    setgid(gp->gr_gid); 
	  /* finally drop root */
	  setuid(ent_pw->pw_uid);
	}
    }
#else
#endif

  /* In debug mode, log to stderr too and cut the prefix crap. */
  openlog("dnsmasq", options & OPT_DEBUG ? LOG_PERROR : LOG_PID, LOG_DAEMON);
  
  if (cachesize)
    syslog(LOG_INFO, "started, version %s cachesize %d", VERSION, cachesize);
  else
    syslog(LOG_INFO, "started, version %s cache disabled", VERSION);
  
  if (mxname)
    syslog(LOG_INFO, "serving MX record for mailhost %s target %s", 
	   mxname, mxtarget);
  
  //if (getuid() == 0 || geteuid() == 0)
  //  syslog(LOG_WARNING, "failed to drop root privs");
  
  serv_addrs = servers = last_server = check_servers(serv_addrs, interfaces, peerfd, peerfd6);
  
  while (1)
    {
      int ready, maxfd = peerfd > peerfd6 ? peerfd : peerfd6;
      fd_set rset;
      HEADER *header;

      /* ******* zg porting DWG814I Source code on 2006.11.06 ******* */
      /* ******* To fixed cdrouterv3.3 item 333(dna_45) item 334(dns_45) failed bug ******* */
      struct timeval tm;

#ifdef HAVE_FILE_SYSTEM
      struct stat statbuf;
#endif
   
      if (first_loop)
	/* do init stuff only first time round. */
	{
	  first_loop = 0;
	  ready = 0;
	}
      else
	{
	  FD_ZERO(&rset);

	  if (peerfd != -1)
	    FD_SET(peerfd, &rset);
	  if (peerfd6 != -1)
	    FD_SET(peerfd6, &rset);
	    	  
	  for (iface = interfaces; iface; iface = iface->next)
	    {
	      FD_SET(iface->fd, &rset);
	      if (iface->fd > maxfd)
		maxfd = iface->fd;
	    }
	  
         /* ******* zg porting DWG814I Source code on 2006.11.06 ******* */
         /* ******* To fixed cdrouterv3.3 item 333(dna_45) item 334(dns_45) failed bug ******* */
         tm.tv_sec = DNS_TIMER;
         tm.tv_usec = 0;
         ready = select(maxfd+1, &rset, NULL, NULL, &tm);
                                                                                           
         if (ready == 0)
         {
                check_servers_response(peerfd, peerfd6, options && OPT_ORDER, dnamebuff);
                continue;
         }
          //ready = select(maxfd+1, &rset, NULL, NULL, NULL);
         /* ******* end by zg porting DWG814I Source code on 2006.11.06 ******* */
	  
	  if (ready == -1)
	    {
	      if (errno == EINTR)
		ready = 0; /* do signal handlers */
	      else
		continue;
	    }
	}

#ifdef HAVE_FILE_SYSTEM
      if (sighup)
	{
	  signal(SIGHUP, SIG_IGN);
	  cache_reload(options & OPT_NO_HOSTS, dnamebuff);
	  if (resolv && (options & OPT_NO_POLL))
	    servers = last_server = 
	      check_servers(reload_servers(resolv, dnamebuff, servers), 
			    interfaces, peerfd, peerfd6);
	  sighup = 0;
	  signal(SIGHUP, sig_handler);
	}

      if (sigusr1)
	{
	  signal(SIGUSR1, SIG_IGN);
	  dump_cache(options & (OPT_DEBUG | OPT_LOG), cachesize);
	  sigusr1 = 0;
	  signal(SIGUSR1, sig_handler);
	}

      if (resolv && !(options & OPT_NO_POLL))
	{
	  if (stat(resolv, &statbuf) == -1)
	    {
	      if (!logged_resolv)
		syslog(LOG_WARNING, "failed to access %s: %m", resolv);
	      logged_resolv = 1;
	    }
	  else
	    {
	      logged_resolv = 0;
	      if ((statbuf.st_mtime > resolv_changed) &&
		  (statbuf.st_mtime < time(NULL) || resolv_changed == 0))
		{
		  resolv_changed = statbuf.st_mtime;
		  servers = last_server = 
		    check_servers(reload_servers(resolv, dnamebuff, servers),
				  interfaces, peerfd, peerfd6);
		}
	    }
	}
#else
#endif

#ifdef HAVE_FILE_SYSTEM
      if (lease_file)
	{
	  if (stat(lease_file, &statbuf) == -1)
	    {
	      if (!logged_lease)
		syslog(LOG_WARNING, "failed to access %s: %m", lease_file);
	      logged_lease = 1;
	    }
	  else
	    { 
	      logged_lease = 0;
	      if ((lease_file_size == (off_t)0) ||
		  (statbuf.st_size > lease_file_size) ||
		  (statbuf.st_ino != lease_file_inode))
		{
		  lease_file_size = statbuf.st_size;
		  lease_file_inode = statbuf.st_ino;
		  load_dhcp(lease_file, domain_suffix, time(NULL), dnamebuff);
		}
	    }
	}
#else
#endif

      if (ready == 0)
	continue; /* no sockets ready */
      
      if (peerfd != -1 && FD_ISSET(peerfd, &rset))
      {
	last_server = reply_query(peerfd, packet, dnamebuff, last_server, &time_to_live);
	//Fixed 2008/08/11 rand port
	if(read_peerfd == 0) read_peerfd = 1;
      }
      if (peerfd6 != -1 && FD_ISSET(peerfd6, &rset))
      {
	last_server = reply_query(peerfd6, packet, dnamebuff, last_server, &time_to_live);
	//Fixed 2008/08/11 rand port
	if(read_peerfd == 0) read_peerfd = 1;
      }

      /* ******* zg porting DWG814I Source code on 2006.11.06 ******* */
      /* ******* To fixed cdrouterv3.3 item 333(dna_45) item 334(dns_45) failed bug ******* */
      check_servers_response(peerfd, peerfd6, options && OPT_ORDER, dnamebuff);

      for (iface = interfaces; iface; iface = iface->next)
	{
	  if (FD_ISSET(iface->fd, &rset))
	    {
	      /* request packet, deal with query */
	      union mysockaddr udpaddr;
	      socklen_t udplen = sizeof(udpaddr);
	      int m, n = recvfrom(iface->fd, packet, DPACKETSZ, 0, &udpaddr.sa, &udplen); 
	      udpaddr.sa.sa_family = iface->addr.sa.sa_family;
#ifdef HAVE_IPV6
	      if (udpaddr.sa.sa_family == AF_INET6)
		udpaddr.in6.sin6_flowinfo = htonl(0);
#endif	      
	      header = (HEADER *)packet;
	      if (n >= (int)sizeof(HEADER) && !header->qr)
		{
		  m = answer_request (header, ((char *) header) + DPACKETSZ, (unsigned int)n, 
				      mxname, mxtarget, options, dnamebuff);
		  if (m >= 1)
		    {
		      /* answered from cache, send reply */
		      sendto(iface->fd, (char *)header, m, 0, 
			     &udpaddr.sa, sa_len(&udpaddr));
		    }
		  else if(m == 0) 
		    {
		      /* cannot answer from cache, send on to real nameserver */
		      last_server = forward_query(iface->fd, peerfd, peerfd6, &udpaddr, header, n, 
						  options && OPT_ORDER, dnamebuff,
						  servers, last_server);
		    }
		//add the bt patch from ethan at 20090309
		    else{
#if 0
  			/* could not send on, return empty answer */
			  header->qr = 1; /* response */
			  header->aa = 0; /* authoritive - never */
			  header->ra = 1; /* recursion if available */
			  header->tc = 0; /* not truncated */
			  header->rcode = NOERROR; /* no error */
			  header->ancount = htons(0); /* no answers */
			  header->nscount = htons(0);
			  header->arcount = htons(0);
		      	sendto(iface->fd, (char *)header, m, 0, 
				     &udpaddr.sa, sa_len(&udpaddr));
#endif
			}
		//end by michael
		}
	      
	    }
	}
	//Fixed 2008/08/11 random port
        if(read_peerfd == 1)
        {
                peerfd = bind_wanport(peerfd);
		#ifdef HAVE_IPV6
                peerfd6 = bind_wanport6(peerfd6);
		#endif
                read_peerfd = 0;
        }

    }
  
  return 0;
}

//Fixed 2008/08/11 random port
static void rand_port(int *port)
{
        struct timeval timer_now;
        
	gettimeofday (&timer_now, NULL);

        srand(timer_now.tv_usec);
        *port = (random () % (65536-2048)) + 2048;
}

static int bind_wanport(int peerfd)
{
        struct sockaddr_in temp;
        int count = 0;
        int wan_port=0;         

        if(peerfd > 0)
                close(peerfd);
        
	if ((peerfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1 &&
              errno != EAFNOSUPPORT && errno != EINVAL)        
                die("dnsmasq: cannot create socket: %s", NULL);

	bzero(&temp,sizeof(temp));

        do
        {
                rand_port(&wan_port);
                temp.sin_port=htons(wan_port);

                if((count++) > 5)
                {
                        temp.sin_port=0;
                        bind(peerfd, (struct sockaddr *)&temp, sizeof(temp));
                        break;
                }
        }while(bind(peerfd, (struct sockaddr *)&temp, sizeof(struct sockaddr_in)));
        
	return peerfd;
}

#ifdef HAVE_IPV6
static int bind_wanport6(int peerfd)
{
        struct sockaddr_in6 temp6;
        int count = 0;
        int wan_port=0;         

        if(peerfd > 0)
                close(peerfd);

	if ((peerfd = socket(AF_INET6, SOCK_DGRAM, 0)) == -1
	     && errno != EAFNOSUPPORT
	     && errno != EINVAL)
		die("dnsmasq: cannot create socket: %s", NULL);

	bzero(&temp6, sizeof(temp6));

	temp6.sin6_family = AF_INET6;
	temp6.sin6_flowinfo = htonl(0);
	temp6.sin6_addr = in6addr_any;

        do
        {
                rand_port(&wan_port);
                temp6.sin6_port=htons(wan_port);

                if((count++) > 5)
                {
                        temp6.sin6_port=0;
                        bind(peerfd, (struct sockaddr *)&temp6, sizeof(temp6));
                        break;
                }
        } while( bind(peerfd, (struct sockaddr *)&temp6, sizeof(temp6)) );
        
	return peerfd;
}
#endif /*HAVE_IPV6*/
