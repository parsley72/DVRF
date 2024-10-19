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


INSTALL_ROOT=$(INSTALLDIR)
#CC=mipsel-linux-gcc

export INSTALL_ROOT
#export CC

all:
	#$(MAKE) -C mkdosfs-0.4 CC=mipsel-linux-gcc
	$(MAKE) -C mkdosfs-2.11

install:
	#$(MAKE) -C mkdosfs-0.4 CC=mipsel-linux-gcc install
	$(MAKE) -C mkdosfs-2.11 install
	rm -rf $(INSTALLDIR)/usr/man
	$(STRIP) $(INSTALLDIR)/sbin/mkdosfs

clean:
	#$(MAKE) -C mkdosfs-0.4 CC=mipsel-linux-gcc clean
	$(MAKE) -C mkdosfs-2.11 clean
