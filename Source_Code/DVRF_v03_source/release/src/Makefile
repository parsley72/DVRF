#
# Toplevel Makefile for the BCM947xx Linux Router release
#
# Copyright 2007, Broadcom Corporation
# All Rights Reserved.
# 
# THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
# KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
# SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
#
# $Id: Makefile,v 1.84 2007/06/01 05:58:13 michael Exp $
#

SRCBASE := $(shell pwd)
RELEASEDIR := $(shell (cd $(SRCBASE)/.. && pwd -P))
PATH := $(RELEASEDIR)/tools:$(PATH)

project:all install

#install: cytools all
install: 
	install -d $(RELEASEDIR)/image
	$(MAKE) -C router install	
#	-cp shared/nvram/*.txt $(RELEASEDIR)/image/

	# add CyberTAN header
	if grep -q "WL_FULL_SUPPORT=1" cy_conf.mak ; then \
		cp router/`cat router/.platform`/linux.trx $(RELEASEDIR)/image/wl_full_linux.trx; \
		addpattern -i $(RELEASEDIR)/image/wl_full_linux.trx -o $(RELEASEDIR)/image/wl_full_code.bin -g -s; \
	else \
		cp router/`cat router/.platform`/linux.trx $(RELEASEDIR)/image/linux.trx; \
		addpattern -i $(RELEASEDIR)/image/linux.trx -o $(RELEASEDIR)/image/code.bin -g -s; \
	fi

	( . ./.kernel; \
	if [ "$${LINUX_VERSION}" = "2_6" ] ; then \
		if grep -q "CONFIG_BLK_DEV_INITRD=y" linux/linux-2.6/.config ; then \
			addpattern -i $(RELEASEDIR)/image/mfg.trx -o $(RELEASEDIR)/image/mfg_code.bin -g -s; \
		fi \
	else \
		if grep -q "CONFIG_EMBEDDED_RAMDISK=y" linux/linux/.config ; then \
			addpattern -i $(RELEASEDIR)/image/mfg.trx -o $(RELEASEDIR)/image/mfg_code.bin -g -s; \
		fi \
	fi )

	$(MAKE) build_rom

build_rom:	

clean:
	$(MAKE) -C router $@
	$(MAKE) -C cfe $@
	rm -rf $(SRCBASE)/cy_conf.mak $(SRCBASE)/cy_conf.h
	rm -rf $(SRCBASE)/include/cy_conf.h
	rm -rf $(SRCBASE)/.select $(SRCBASE)/.model $(SRCBASE)/.kernel

all:
	if test ! -f .select && test -f cy_configure; then \
		./select.sh; \
		echo "Press any key to continue:" ; read; \
		$(MAKE) cytools; \
	fi
ifeq ($(wildcard $(SRCBASE)/include/cy_conf.h),)
	./gen.pl
endif
	cp -f $(SRCBASE)/cy_conf.h $(SRCBASE)/include/cy_conf.h

	$(MAKE) -C router $@
	
	$(MAKE) boot

boot:
ifneq ($(wildcard pmon),)
endif
ifneq ($(wildcard cfe),)
	( . ./.model; \
	if [ "$${LINKSYS_MODEL}" = "E300" ] ; then \
		$(MAKE) -C cfe CFG_ET=1 CFG_GMAC=1 ; \
		cp cfe/build/broadcom/bcm947xx/cfe.bin $(RELEASEDIR)/image/ ; \
		cp cfe/build/broadcom/bcm947xx/compressed/cfez.bin $(RELEASEDIR)/image/ ; \
	elif [ "$${LINKSYS_MODEL}" = "E30X" ] ; then \
		$(MAKE) -C cfe CFG_ET=1 CFG_GMAC=1 ; \
		cp cfe/build/broadcom/bcm947xx/cfe.bin $(RELEASEDIR)/image/ ; \
		cp cfe/build/broadcom/bcm947xx/compressed/cfez.bin $(RELEASEDIR)/image/ ; \
	elif [ "$${LINKSYS_MODEL}" = "E1550" ] ; then \
		$(MAKE) -C cfe CFG_ET=1 CFG_GMAC=1 ; \
		cp cfe/build/broadcom/bcm947xx/cfe.bin $(RELEASEDIR)/image/ ; \
		cp cfe/build/broadcom/bcm947xx/compressed/cfez.bin $(RELEASEDIR)/image/ ; \
	elif [ "$${LINKSYS_MODEL}" = "E155X" ] ; then \
		$(MAKE) -C cfe CFG_ET=1 CFG_GMAC=1 ; \
		cp cfe/build/broadcom/bcm947xx/cfe.bin $(RELEASEDIR)/image/ ; \
		cp cfe/build/broadcom/bcm947xx/compressed/cfez.bin $(RELEASEDIR)/image/ ; \
	elif [ "$${LINKSYS_MODEL}" = "E2500" ] ; then \
		$(MAKE) -C cfe CFG_ET=1 CFG_GMAC=1 ; \
		cp cfe/build/broadcom/bcm947xx/cfe.bin $(RELEASEDIR)/image/ ; \
		cp cfe/build/broadcom/bcm947xx/compressed/cfez.bin $(RELEASEDIR)/image/ ; \
	else \
		$(MAKE) -C cfe ; \
		cp cfe/build/broadcom/bcm947xx/cfe.bin $(RELEASEDIR)/image/ ; \
		cp cfe/build/broadcom/bcm947xx/compressed/cfez.bin $(RELEASEDIR)/image/ ; \
	fi )
endif

cytools:



select:
	./select.sh
	@read
	$(MAKE)	install

.PHONY: all clean install
