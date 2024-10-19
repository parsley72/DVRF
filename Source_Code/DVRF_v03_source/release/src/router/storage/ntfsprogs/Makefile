#
# mkdosfs top-level Makefile for NASoC
#
# Copyright 2001-2004, Broadcom Corporation
# All Rights Reserved.
#
# THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
# KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
# SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
#

PREFIX = $(INSTALLDIR)
SBINDIR = $(PREFIX)/sbin


INSTALL_ROOT=$(INSTALLDIR)
#CC=mipsel-linux-gcc

export INSTALL_ROOT
#export CC

all:
	$(MAKE) -C ntfsprogs-2.0.0

install:
	mkdir -p $(SBINDIR)
	install -m 755 ntfsprogs-2.0.0/ntfsprogs/ntfslabel $(SBINDIR)
	$(STRIP) $(SBINDIR)/ntfslabel

clean:
	#$(MAKE) -C mkdosfs-0.4 CC=mipsel-linux-gcc clean
	$(MAKE) -C ntfsprogs-2.0.0 clean
