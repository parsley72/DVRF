#!/bin/sh

PATH1="/tmp/process.output"
PATH2="/tmp/httpd.found"
PATH3="/tmp/find_lang"

until false
do
	sleep 5
	ps > $PATH1
	grep -i "httpd" $PATH1 > $PATH2
	if test ! -s $PATH2
	then
		nvram get "find_lang" > $PATH3
		if test -s $PATH3
		then
			cd /tmp/www
		else
			cd /www
		fi
		httpd
	fi
	rm -f $PATH1
	rm -f $PATH2
	rm -f $PATH3
done

