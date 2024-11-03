#
# milli_httpd Makefile
#
# Copyright 2007, Broadcom Corporation
# All Rights Reserved.
# 
# THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
# KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
# SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
#
# $Id: Makefile,v 1.57 2007/12/10 07:29:38 mark Exp $
#

all:

clean:

install:
	install -D httpd $(INSTALLDIR)/usr/sbin/httpd
	$(STRIP) $(INSTALLDIR)/usr/sbin/httpd
ifeq ($(HTTPS_SUPPORT),1)
	install -d $(INSTALLDIR)/etc
	install openssl.cnf $(INSTALLDIR)/etc
	install -m 755 gencert.sh $(INSTALLDIR)/usr/sbin
# wuzh add for selfsign
ifeq ($(SELFSIGN_SUPPORT),1)
	cd $(INSTALLDIR)/etc && ln -sf /tmp/cert.pem cert.pem
	cd $(INSTALLDIR)/etc && ln -sf /tmp/key.pem key.pem
else
	install *.pem $(INSTALLDIR)/etc
endif
endif

cert:
	# create the key and certificate request
	openssl req -new -out cert.csr -config openssl.cnf -keyout privkey.pem -days 3650 -newkey rsa:512
	# remove the passphrase from the key:
	openssl rsa -in privkey.pem -out key.pem
	# convert the certificate request into a signed certificate
	openssl x509 -in cert.csr -out cert.pem -req -signkey key.pem 
	rm -f cert.csr privkey.pem
	# Show human-readable format
	openssl x509 -in cert.pem -text -noout

httpd: $(OBJS) $(EGHN_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

build_date.o: build_date.c
build_date:
	echo "#define BUILD_DATE \"`date \"+%b %d %Y\"`\"" > build_date.c
	echo "#define BUILD_TIME \"`date \"+%H:%M:%S\"`\"" >> build_date.c

# for eghn
ifeq ($(EGHN_SUPPORT),1)
hnap_eghn_ext_httpd_interface.o:hnap_eghn_ext_httpd_interface.c
	$(CC) $(CFLAGS) -o $@ -c $<
endif
# for eghn

.%.depend: %.c
	$(CC) $(CFLAGS) -M $< > $@

include $(OBJS:%.o=.%.depend)
