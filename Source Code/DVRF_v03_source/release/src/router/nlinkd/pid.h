
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

#ifndef __PID_H__
#define __PID_H__

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>


#define PROXY_PID_FILE      "/var/run/nlinkd.pid"
#define MAX_PID_BUF_SIZE 16

/* write_pid
 *
 * Writes the pid to the specified file. If that fails 0 is
 * returned, otherwise the pid.
 */
static inline int write_pid (char *pidfile)
{
	FILE *f;
	int fd;
	int pid;

	if ( ((fd = open(pidfile, O_RDWR|O_CREAT, 0644)) == -1)
	   || ((f = fdopen(fd, "r+")) == NULL) ) {
	  return 0;
	}

	if (flock(fd, LOCK_EX|LOCK_NB) == -1) {
	  fscanf(f, "%d", &pid);
	  fclose(f);
	  return 0;
	}

	pid = getpid();
	if (!fprintf(f,"%d\n", pid)) {
	  close(fd);
	  return 0;
	}
	fflush(f);

	if (flock(fd, LOCK_UN) == -1) {
	  close(fd);
	  return 0;
	}
	close(fd);

	return pid;
}

/* remove_pid
 *
 * Remove the the specified file. The result from unlink(2)
 * is returned
 */
static inline int remove_pid (char *pidfile)
{
	return unlink (pidfile);
}


static inline int read_pid(char *pidfile)
{
    FILE *fp;
    char szBuf[MAX_PID_BUF_SIZE];
    int pid;
    
    fp = fopen(pidfile, "r");
    
    if (fp == NULL)
    {
        return -1;
    }
    
    szBuf[MAX_PID_BUF_SIZE - 1] = '\0';
    if (NULL == fgets(szBuf, MAX_PID_BUF_SIZE - 1, fp))
    {
        fclose(fp);
        return -1;
    }
    
    pid = strtol(szBuf, NULL, 10);
   
    fclose(fp);
    return pid;
}

#endif	//__PID_H__
