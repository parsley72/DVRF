/***********************************************************************
*
* main.c
*
* Main program of l2tp
*
* Copyright (C) 2002 by Roaring Penguin Software Inc.
*
* This software may be distributed under the terms of the GNU General
* Public License, Version 2, or (at your option) any later version.
*
* LIC: GPL
*
***********************************************************************/

static char const RCSID[] =
"$Id: main.c,v 1.4 2007/08/20 09:59:49 jack Exp $";

#include "l2tp.h"
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>

int got_signal_term = 0;
unsigned int l2tp_redial_times = 0;
static void
usage(int argc, char *argv[], int exitcode)
{
    fprintf(stderr, "\nl2tpd Version %s Copyright 2002 Roaring Penguin Software Inc.\n", VERSION);
    fprintf(stderr, "http://www.roaringpenguin.com/\n\n");
    fprintf(stderr, "Usage: %s [options]\n", argv[0]);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "-d level               -- Set debugging to 'level'\n");
    fprintf(stderr, "-f                     -- Do not fork\n");
    fprintf(stderr, "-h                     -- Print usage\n");
    fprintf(stderr, "\nThis program is licensed under the terms of\nthe GNU General Public License, Version 2.\n");
    exit(exitcode);
}

static void l2tp_term(int sig)
{
	got_signal_term = 1;
}
	
int
main(int argc, char *argv[])
{
    EventSelector *es = Event_CreateSelector();
    int i;
    int opt;
    int do_fork = 1; 
    int debugmask = 0; //original = 0; //debug = 65535;

    while((opt = getopt(argc, argv, "d:fh")) != -1) {
	switch(opt) {
	case 'h':
	    usage(argc, argv, EXIT_SUCCESS);
	    break;
	case 'f':
	    do_fork = 0;
	    break;
	case 'd':
	    sscanf(optarg, "%d", &debugmask);
	    break;
	default:
	    usage(argc, argv, EXIT_FAILURE);
	}
    }
    cprintf("%s-l2tp_random_init() entry.\n",__FUNCTION__);
    l2tp_random_init();
    cprintf("%s-l2tp_tunnel_init(es) entry.\n",__FUNCTION__);
    l2tp_tunnel_init(es);
    cprintf("%s-l2tp_peer_init() entry.\n",__FUNCTION__);
    l2tp_peer_init();
    cprintf("%s-l2tp_debug_set_bitmask(debugmask) entry.\n",__FUNCTION__);
    l2tp_debug_set_bitmask(debugmask);

    //Jemmy add for init l2tp redial times 2008.5.8	
    //buf_to_file("/tmp/ppp/l2tp-redial-times", "0");
    l2tp_redial_times = 0;
    //Jemmy end

    if (l2tp_parse_config_file(es, "/tmp/l2tp.conf") < 0) { //2005-04-14 by kanki
	l2tp_die();
    }
    cprintf("%s-l2tp_network_init(es) entry.\n",__FUNCTION__);
    if (!l2tp_network_init(es)) { //waitting recvied packet for L2TP 
	l2tp_die();
    }

    /* Daemonize */
    if (do_fork) {
	i = fork();
	if (i < 0) {
	    perror("fork");
	    exit(EXIT_FAILURE);
	} else if (i != 0) {
	    /* Parent */
	    exit(EXIT_SUCCESS);
	}

	setsid();
	signal(SIGHUP, SIG_IGN);
	cprintf("L2TP setup SIGTERM signal!\n");
	//Jemmy add for shutdown l2tp connection when recevice SIGTERM signal
	signal(SIGTERM, l2tp_term);
	i = fork();
	if (i < 0) {
	    perror("fork");
	    exit(EXIT_FAILURE);
	} else if (i != 0) {
	    exit(EXIT_SUCCESS);
	}

	chdir("/");

	/* Point stdin/stdout/stderr to /dev/null */
	for (i=0; i<3; i++) {
	    close(i);
	}
	i = open("/dev/console", O_RDWR); //2005-04-14 by kanki for debugging
	if (i >= 0) {
	    dup2(i, 0);
	    dup2(i, 1);
	    dup2(i, 2);
	    if (i > 2) close(i);
	}
    }

    while(1) {
	i = Event_HandleEvent(es);
	//cprintf("%s[%d]-Event_HandleEvent(es)....\n",__FUNCTION__,__LINE__);
	if (i < 0) {
	    fprintf(stderr, "Event_HandleEvent returned %d\n", i);
	    l2tp_cleanup();
	    exit(EXIT_FAILURE);
	}
	if (got_signal_term == 1)
	{
		tunnel_cleanup_sessions();
		got_signal_term = 0;
		return 0;
	}
    }
    return 0;
}
