#
# Broadcom Linux Router Makefile
# 
# Copyright (C) 2008, Broadcom Corporation
# All Rights Reserved.
# 
# THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
# KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
# SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
#
# $Id: Makefile,v 1.157.4.22 2009/03/18 10:29:03 jack Exp $
#

include .config
ifneq ($(wildcard ../cy_conf.mak),)
  include ../cy_conf.mak
endif


#
# Paths
#


CPU ?=
LINUX_VERSION = 2_6

# Source bases
export PLATFORM LINUXDIR LIBDIR USRLIBDIR LINUX_VERSION
export TOP := $(shell pwd)
export SRCBASE := $(shell (cd $(TOP)/.. && pwd -P))

ifeq ($(LINUX_VERSION),2_6)
export 	LINUXDIR := $(SRCBASE)/linux/linux-2.6
else
export 	LINUXDIR := $(SRCBASE)/linux/linux
endif


#
# Cross-compile environment variables
#

# Build platform
export BUILD := i386-pc-linux-gnu
export HOSTCC := gcc

# uClibc wrapper
ifeq ($(CONFIG_UCLIBC),y)
export PLATFORM := $(PLATFORM)-uclibc
endif

ifeq ($(PLATFORM),mipsel)
ifeq ($(LINUX_VERSION),2_6)
export CROSS_COMPILE := mipsel-linux-linux26-
else
export CROSS_COMPILE := mipsel-linux-
endif
export CONFIGURE := ./configure mipsel-linux --build=$(BUILD)
export TOOLCHAIN := $(shell cd $(dir $(shell which $(CROSS_COMPILE)gcc))/../mipsel-linux && pwd -P)
endif

ifeq ($(PLATFORM),mipsel-uclibc)
ifeq ($(LINUX_VERSION),2_6)
export CROSS_COMPILE := mipsel-uclibc-linux26-
else
export CROSS_COMPILE := mipsel-uclibc-
endif
export CONFIGURE := ./configure mipsel-linux --build=$(BUILD)
export TOOLCHAIN := $(shell cd $(dir $(shell which $(CROSS_COMPILE)gcc))/.. && pwd -P)
endif


#
# Packages
#
ifeq ($(LINUX_VERSION),2_6)
PKG_IPTABLES := iptables-1.x
PKG_BUSYBOX := busybox-1.x
PKG_IGMP_PROXY := igmp-proxy-1.x
PKG_IPROUTE2 := iproute2-1.x
PKG_RC := rc-1.x
PKG_HTTPD := httpd-1.x
PKG_HNAP := hnap-1.x
else
PKG_IPTABLES := iptables
PKG_BUSYBOX := busybox
PKG_IGMP_PROXY := igmp-proxy
PKG_IPROUTE2 := iproute2
PKG_RC := rc
PKG_HTTPD := httpd
PKG_HNAP := hnap
endif

ifeq ($(LINUX_VERSION),2_4)
CFLAGS	+= -DLINUX24
endif
ifeq ($(LINUX_VERSION),2_6)
CFLAGS	+= -DLINUX26
endif

CFLAGS	+= -DBCMVISTAROUTER

ifeq ($(CONFIG_BCMWPA2),y)
export CFLAGS += -DBCMWPA2
endif

ifeq ("$(CONFIG_USBAP)","y")
export CFLAGS += -D__CONFIG_USBAP__
endif

export CXX := $(CROSS_COMPILE)g++
ifeq ($(CONFIG_WSCCMD),y)
export CONFIG_WSCCMD
export CFLAGS += -DBCMWPS
endif

ifeq ($(CONFIG_EMF),y)
export CFLAGS += -D__CONFIG_EMF__
endif

ifeq ($(CONFIG_IGMP_PROXY),y)
export CFLAGS += -D__CONFIG_IGMP_PROXY__
endif

ifeq ($(CONFIG_SOUND),y)
export CFLAGS += -D__CONFIG_SOUND__
endif

ifeq ($(CONFIG_VOIP),y)
export CFLAGS += -DBCMVOIP
endif

ifeq ($(CONFIG_SQUASHFS), y)
ROOT_IMG :=target.squashfs
else
ROOT_IMG := target.cramfs
endif

ifeq ($(CONFIG_WAPI),y)
export CFLAGS += -DBCMWAPI_WAI -DBCMWAPI_WPI
endif

ifeq ($(CONFIG_PHYMON_UTILITY),y)
export CFLAGS += -DPHYMON
endif

ifeq ($(LINUXDIR), $(SRCBASE)/linux/linux-2.6)
CRAMFSDIR := cramfs
else
CRAMFSDIR := $(LINUXDIR)/scripts/cramfs
endif

ifeq ($(CONFIG_BCMDCS),y)
export CFLAGS += -DBCM_DCS
endif

ifeq ($(CONFIG_EXTACS),y)
export CFLAGS += -DEXT_ACS
endif


export CC := $(CROSS_COMPILE)gcc
export AR := $(CROSS_COMPILE)ar
export AS := $(CROSS_COMPILE)as
export LD := $(CROSS_COMPILE)ld
export NM := $(CROSS_COMPILE)nm
export RANLIB := $(CROSS_COMPILE)ranlib
export STRIP := $(CROSS_COMPILE)strip
export STRIPPROG := $(CROSS_COMPILE)strip
export SIZE := $(CROSS_COMPILE)size

#
# Install and target directories
#

export PLATFORMDIR := $(TOP)/$(PLATFORM)
export INSTALLDIR := $(PLATFORMDIR)/install
export TARGETDIR := $(PLATFORMDIR)/target

define STRIP_DEBUG_SYMBOLS
	@dbgsymf=$(basename $(1))_dbgsym$(suffix $(1)); \
	if [ "$(1)" -nt "$${dbgsymf}" ]; then \
	   echo "#- $0"; \
	   ls -ln $1 | awk '{printf "Orig  size: %10d bytes, %s\n",$$5,$$NF}'; \
	   cp -p -v $1 $$dbgsymf; $(STRIP) -d $(1); touch $$dbgsymf; \
	   ls -ln $1 | awk '{printf "Strip size: %10d bytes, %s\n",$$5,$$NF}'; \
	fi
endef

ifeq ($(POLARSSL_SUPPORT), 1)
	SSL_MODULE = polarssl
else
ifeq ($(XYSSL_SUPPORT), 1)
	SSL_MODULE = xyssl
else
	SSL_MODULE = openssl
endif
endif


# USB AP support
# note : the dongle target is only for after pre-build
obj-$(CONFIG_USBAP) += bmac dongle

# always build libbcmcrypto
obj-y += libbcmcrypto
export LDFLAGS += -L$(TOP)/libbcmcrypto -lbcmcrypto

#
# Configuration
#
ifeq ($(BUILD_MFG_SUPPORT),1)
# wl.mk use WLTEST !!! don't use WLMFG right now.
ifeq ($(LINUX_VERSION),2_6)
export BUILD_MFG := 1
else
export WLTEST := 1
endif
#CONFIG_IPTABLES=n
else
CONFIG_IPTABLES=y
endif

#ifdef BCMSOUND
obj-$(CONFIG_SALSA) += salsa
obj-$(CONFIG_LIBZ) += libz
obj-$(CONFIG_LIBID3TAG) += libid3tag
obj-$(CONFIG_LIBMAD) += libmad
obj-$(CONFIG_MADPLAY) += madplay
obj-$(CONFIG_APLAY) += alsa-utils/aplay
#endif
obj-$(CONFIG_NVRAM) += nvram
obj-$(CONFIG_SHARED) += shared 
obj-$(CONFIG_XYSSL) += xyssl
obj-$(CONFIG_POLARSSL) += polarssl

obj-$(CONFIG_XYSSL) += selfsign
obj-$(CONFIG_POLARSSL) += selfsign

obj-$(CONFIG_LIBBCM) += libbcm
obj-$(CONFIG_WWW) += www
obj-$(CONFIG_GLIBC) += lib
obj-$(CONFIG_UCLIBC) += lib
obj-$(CONFIG_WL_IOCMD) += wl_iocmd
obj-$(CONFIG_BRIDGE) += bridge
obj-$(CONFIG_BUSYBOX) += $(PKG_BUSYBOX)
obj-$(CONFIG_DNSMASQ) += dnsmasq
obj-$(CONFIG_IPTABLES) += $(PKG_IPTABLES)
obj-$(CONFIG_LIBIPT) += $(PKG_IPTABLES)
obj-$(CONFIG_NAS) += nas
obj-$(CONFIG_NAS) += eapd/linux
obj-$(CONFIG_SES) += ses/ses
obj-$(CONFIG_EZC) += ezc
obj-$(CONFIG_NETCONF) += netconf
obj-$(CONFIG_NTP) += ntpclient
obj-$(CONFIG_PPP) += ppp
obj-$(CONFIG_UDHCPD) += udhcpd
obj-$(CONFIG_UPNP) += upnp
obj-$(CONFIG_UTILS) += utils
obj-$(CONFIG_TCP_WRAPPER) += tcp_wrapper
obj-$(CONFIG_PORTMAP) += portmap
obj-$(CONFIG_ETC) += etc
obj-$(CONFIG_VLAN) += vlan
obj-$(CONFIG_UTELNETD) += utelnetd
obj-$(CONFIG_NFS) += nfs-utils
obj-$(CONFIG_POPT) += popt
obj-$(CONFIG_SECSRL) += sec_srl
obj-$(CONFIG_GMP) += gmp
obj-$(CONFIG_SEUTIL) += se-utils
obj-$(CONFIG_STORAGE) += storage
obj-$(CONFIG_EBTABLES) += ebtables
obj-$(CONFIG_MATRIXSSL) += matrixssl
obj-$(CONFIG_PCIUTILS) += pciutils
obj-$(CONFIG_TWONKY) += twonky


##################################################################
CONFIG_OTHERS=y

CONFIG_OPENSSL=y
obj-$(CONFIG_L2TP) += rp-l2tp
obj-$(CONFIG_HEARTBEAT) += bpalogin




obj-$(CONFIG_SMB302) += samba-3.0.2
obj-$(CONFIG_SMB3025) += samba-3.0.25c
obj-$(CONFIG_SMB3215) += samba-3.2.15

ifeq ($(FTP_SUPPORT),1)
obj-$(CONFIG_PROFTPD) += proftpd
obj-$(CONFIG_VSFTPD) += vsftpd
endif

#added by tlhh
ifeq ($(WIRELESS_WARNING_PAGE_SUPPORT),1)
obj-y += nlinkd
endif

ifeq ($(PRINTER_SERVER_SUPPORT),1)
obj-$(CONFIG_PRINTER_SERVER) += ippd
endif

ifeq ($(LLTD_SUPPORT),1)
obj-$(CONFIG_LLTD) += lltd
endif

ifeq ($(MULTICAST_SUPPORT),1)
obj-$(CONFIG_MULTICAST) += $(PKG_IGMP_PROXY)
endif

ifeq ($(IGMP_X_MLD_SUPPORT),1)
obj-$(CONFIG_IGMP_X_MLD) += igmp-x-mld
endif

ifeq ($(MEDIA_SERVER_SUPPORT),1)
#obj-$(CONFIG_MEDIA_SERVER) += upnpmms
endif

ifeq ($(VERIZON_LAN_SUPPORT),1)
obj-$(CONFIG_VERIZON_LAN) += dhcprelay
endif

obj-$(CONFIG_CRON) += cron
obj-$(CONFIG_PPTP) += pptp-client
obj-$(CONFIG_PPPD) += pppd
obj-$(CONFIG_ZEBRA) += zebra
obj-$(CONFIG_DDNS) += ipupdate
obj-$(CONFIG_TZO_WEB_CLIENT2) += tzoupdate-1.11
obj-$(CONFIG_OTHERS) += others
obj-$(CONFIG_DIAG) += traceroute
obj-$(CONFIG_LIBPCAP) += libpcap
obj-$(CONFIG_HW_QOS) += $(PKG_IPROUTE2)

#########EGHN##########
ifeq ($(EGHN_SUPPORT), 1)
obj-$(CONFIG_EGHN)+= libupnp-1.6.0
obj-$(CONFIG_EGHN)+= eghn
endif

obj-$(CONFIG_RC) += $(PKG_RC)
obj-$(CONFIG_HTTPD) += $(PKG_HTTPD)
obj-$(CONFIG_TFTPD) += tftpd
#######################

ifeq ($(PPPOE_RELAY_SUPPORT),1)
obj-$(CONFIG_PPPOE_RELAY) += rp-pppoe
endif

obj-$(CONFIG_WSCCMD) += wsc/Wsccmd/src/linux
obj-$(CONFIG_WPS) += wps
obj-$(CONFIG_EMF) += emf
obj-$(CONFIG_EMF) += igs
obj-$(CONFIG_IGMP_PROXY) += igmp

ifeq ($(LINUXDIR), $(SRCBASE)/linux/linux-2.6)
obj-y += udev
obj-y += hotplug2
endif

obj-$(CONFIG_LLD2D) += lltd/wrt54g-linux
#if defined(BCMDBG)
obj-$(CONFIG_UTELNETD) += utelnetd
#endif
#if defined(PHYMON)
obj-$(CONFIG_PHYMON_UTILITY) += phymon
#endif
#if defined(EXT_ACS)
obj-$(CONFIG_EXTACS) += acsd
#endif


ifeq ($(HNAP_SUPPORT),1)
obj-$(CONFIG_HNAP) += $(PKG_HNAP)
endif

ifeq ($(CES_MDNS_SUPPORT),1)
obj-$(CONFIG_CES_MDNS) += cesmDNS
endif

ifeq ($(EXPAT_SUPPORT),1)
obj-$(CONFIG_EXPAT) += expat
endif

ifeq ($(LIBREGDOM_SUPPORT),1)
obj-$(CONFIG_LIBREGDOM) += libregdom
endif

obj-$(CONFIG_RADVD) += radvd
obj-$(CONFIG_IPROUTE2) += $(PKG_IPROUTE2)
obj-$(CONFIG_IPUTILS) += iputils

## dhclient & dhcpd utility for IPv6
ifeq ($(DHCPV6S_SUPPORT),1)
obj-$(CONFIG_DHCPV6S) += dhcp
obj-$(CONFIG_DHCPV6S) += arp
#endif

obj-clean := $(foreach obj,$(obj-y) $(obj-n),$(obj)-clean)
obj-install := $(foreach obj,$(obj-y),$(obj)-install)


#
# Basic rules
#

# generate $(LINUXDIR)/.config, some $(obj-y) need it
all:build_kernel_deps $(obj-y) build_kernel

build_kernel_deps: $(LINUXDIR)/.config
	$(MAKE) -C $(LINUXDIR) depend

build_kernel: $(LINUXDIR)/.config
	echo $(PLATFORM) > .platform
	# Also build kernel
ifeq ($(LINUXDIR), $(SRCBASE)/linux/linux-2.6)
	if ! grep -q "CONFIG_BLK_DEV_INITRD=y" $(LINUXDIR)/.config ; then \
	    $(MAKE) LDFLAGS="" -C $(LINUXDIR) zImage ; \
	    $(MAKE) LDFLAGS="" CONFIG_SQUASHFS=$(CONFIG_SQUASHFS) -C $(SRCBASE)/router/compressed ; \
	fi
else
	if ! grep -q "CONFIG_EMBEDDED_RAMDISK=y" $(LINUXDIR)/.config ; then \
	    $(MAKE) LDFLAGS="" -C $(LINUXDIR) zImage ; \
		rm -f $(LINUXDIR)/a.out ; \
	fi
endif
	rm -rf $(SRCBASE)/linux/linux/drivers/net/et/*.o
	rm -rf $(SRCBASE)/linux/linux/drivers/net/bcm57xx/*.o
	if grep -q "CONFIG_MODULES=y" $(LINUXDIR)/.config ; then \
	    $(MAKE) LDFLAGS="" -C $(LINUXDIR) modules ; \
	fi
	# Preserve the debug versions of these and strip for release
	$(call STRIP_DEBUG_SYMBOLS,$(LINUXDIR)/vmlinux)
ifeq ($(LINUXDIR), $(SRCBASE)/linux/linux-2.6)
	$(call STRIP_DEBUG_SYMBOLS,$(LINUXDIR)/drivers/net/wl/wl.ko)
ifeq ("$(CONFIG_USBAP)","y")
	$(call STRIP_DEBUG_SYMBOLS,$(LINUXDIR)/drivers/net/wl/wl_high/wl_high.ko)
endif
	$(call STRIP_DEBUG_SYMBOLS,$(LINUXDIR)/drivers/net/et/et.ko)
	$(call STRIP_DEBUG_SYMBOLS,$(LINUXDIR)/drivers/net/bcm57xx/bcm57xx.ko)
	$(call STRIP_DEBUG_SYMBOLS,$(LINUXDIR)/drivers/net/emf/emf.ko)
	$(call STRIP_DEBUG_SYMBOLS,$(LINUXDIR)/drivers/net/igs/igs.ko)
else
	$(call STRIP_DEBUG_SYMBOLS,$(LINUXDIR)/drivers/net/wl/wl.o)
ifeq ("$(CONFIG_USBAP)","y")
	$(call STRIP_DEBUG_SYMBOLS,$(LINUXDIR)/drivers/net/wl/wl_high/wl_high.o)
endif
	$(call STRIP_DEBUG_SYMBOLS,$(LINUXDIR)/drivers/net/et/et.o)
	$(call STRIP_DEBUG_SYMBOLS,$(LINUXDIR)/drivers/net/bcm57xx/bcm57xx.o)
	$(call STRIP_DEBUG_SYMBOLS,$(LINUXDIR)/drivers/net/emf/emf.o)
	$(call STRIP_DEBUG_SYMBOLS,$(LINUXDIR)/drivers/net/igs/igs.o)
endif

router_clean: $(obj-clean)
	rm -rf $(TARGETDIR)
	rm -rf $(INSTALLDIR)
	rm -f .config
	rm -f $(PLATFORMDIR)/linux.trx $(PLATFORMDIR)/vmlinuz $(PLATFORMDIR)/target.cramfs $(PLATFORMDIR)/target.image

clean_target: 
	rm -rf $(TARGETDIR)
	rm -rf $(INSTALLDIR)
	install -d $(TARGETDIR)
	install -d $(INSTALLDIR)
	rm -f $(PLATFORMDIR)/linux.trx $(PLATFORMDIR)/vmlinuz $(PLATFORMDIR)/target.image
ifeq ($(LINUXDIR), $(SRCBASE)/linux/linux-2.6)
	rm -rf $(SRCBASE)/linux/linux/
else
	rm -rf $(SRCBASE)/linux/linux-2.6/
endif

clean: router_clean
	@echo cleaning LINUXDIR=[$(LINUXDIR)]
ifeq ($(LINUXDIR), $(SRCBASE)/linux/linux-2.6)
	$(MAKE) CONFIG_WL_CONF=wlconfig_lx_router_ap -C $(LINUXDIR) clean
	$(MAKE) -C $(SRCBASE)/router/compressed clean
else
	$(MAKE) -C $(LINUXDIR) clean
endif
	rm -f $(LINUXDIR)/.config
	$(MAKE) -C $(SRCBASE)/cfe/build/broadcom/bcm947xx clean
	find $(SRCBASE) -name ".depend" | xargs rm -f

distclean mrproper: clean
	rm -f .config $(LINUXDIR)/.config

optimize-lib:
	find $(TARGETDIR) -name ".svn"  | xargs rm -rf
	../../tools/optimize_lib.sh zebra/lib/ libzebra.so libzebra.a libzebra_min.so $(TARGETDIR) $(TARGETDIR)/usr/lib/libzebra.so
	#../../tools/optimize_lib.sh shared/ libshared.so libshared.a libshared_min.so $(TARGETDIR) $(TARGETDIR)/usr/lib/libshared.so
	../../tools/optimize_lib.sh lib/ libm.so libm.a libm_min.so $(TARGETDIR) $(TARGETDIR)/lib/libm.so.0
	../../tools/optimize_lib.sh $(PKG_BUSYBOX)/ libbb.so libbb.a libbb_min.so $(TARGETDIR) $(TARGETDIR)/usr/lib/libbb.so
	../../tools/optimize_lib.sh $(PKG_IPTABLES)/ libiptables.so libiptables.a libiptables_min.so $(TARGETDIR) $(TARGETDIR)/usr/lib/libiptables.so

install package: $(filter-out lib-install,$(obj-install)) $(LINUXDIR)/.config
	# Install binaries into target directory
	install -d $(TARGETDIR)
	for dir in $(wildcard $(patsubst %,$(INSTALLDIR)/%,$(obj-y))) ; do \
	    (cd $${dir} && tar cpf - .) | (cd $(TARGETDIR) && tar xpf -) \
	done
	# optimize the crypto library by removing unneeded symbols
	#[ ! -d libbcmcrypto ] || $(MAKE) -C libbcmcrypto optimize
	# Install (and possibly optimize) C library
	$(MAKE) lib-install
	# optimize the others library by removing unneeded symbols
	$(MAKE) optimize-lib
	# Kernel module ufsd.o --> not supported  --dynamic option in mipsel-linux-nm, and will casue optimize libraries error. Install kernel module after optimize libraries
ifeq ($(LINUX_VERSION),2_4)
	install -m 755 others/ufsd.o $(TARGETDIR)/lib
ifeq ($(LINUX_VERSION),2_6)
	install -m 755 others/ufsd.ko $(TARGETDIR)/lib
endif
endif	
	# Install modules into filesystem
	if grep -q "CONFIG_MODULES=y" $(LINUXDIR)/.config ; then \
	    $(MAKE) -C $(LINUXDIR) modules_install DEPMOD=/bin/true INSTALL_MOD_PATH=$(TARGETDIR) ; \
	fi
	if ! grep -q "LINKSYS_MODEL=WRT54GL " $(SRCBASE)/cy_conf.mak && ! grep -q "LINKSYS_MODEL=WRT54G " $(SRCBASE)/cy_conf.mak ; then \
		rm -rf $(TARGETDIR)/lib/modules/2.4.20/kernel/drivers/net/et.4702/ ; \
		rm -rf $(TARGETDIR)/lib/modules/2.4.20/kernel/drivers/net/diag/ ; \
		rm -rf $(TARGETDIR)/lib/modules/2.4.20/kernel/drivers/net/port_based_qos/ ; \
	fi
ifeq ($(LINUX_VERSION),2_6)
ifeq ("$(CONFIG_USBAP)","y")
	# Don't delete wl_high.ko for USBAP
	find $(TARGETDIR) -name "wl_*.ko" | sed s/\.\*wl_high\\\.ko//g | xargs rm -rf
else
	find $(TARGETDIR) -name "wl_*.ko" | xargs rm -rf
endif
else
ifeq ("$(CONFIG_USBAP)","y")
	# Don't delete wl_high.o for USBAP
	find $(TARGETDIR) -name "wl_*.o" | sed s/\.\*wl_high\\\.o//g | xargs rm -rf
else
	find $(TARGETDIR) -name "wl_*.o" | xargs rm -rf
endif
endif #ifeq ($(LINUX_VERSION),2_6)

ifeq ($(LINUX_VERSION),2_6)
	cp $(SRCBASE)/router/others/fsutil-26 $(TARGETDIR)/sbin/fsutil
	cp $(SRCBASE)/router/others/chkntfs-26 $(TARGETDIR)/sbin/chkntfs
endif #ifeq ($(LINUX_VERSION),2_6)
endif #ifeq ($(PARAGON_NTFS_SUPPORT),1)	

	# Prepare filesystem
	cd $(TARGETDIR) && $(TOP)/misc/rootprep.sh
	cd $(TARGETDIR)  &&  find . -iname "CVS" | xargs rm -rf
ifeq ($(LINUX_VERSION),2_6)
ifeq ($(CONFIG_SQUASHFS), y)
	# Make sure mksquashfs 3.0 is used
	$(MAKE) -C squashfs LDFLAGS="" mksquashfs
	squashfs/mksquashfs $(TARGETDIR) $(PLATFORMDIR)/$(ROOT_IMG) -le -noappend -all-root
	for i in $(shell ls $(INSTALLDIR)/utils/usr/sbin) ; do \
		rm -f $(TARGETDIR)/usr/sbin/$${i} ; \
	done
	squashfs/mksquashfs $(TARGETDIR) $(PLATFORMDIR)/$(ROOT_IMG).trim -le -noappend -all-root
else
	# Make sure mkcramfs-2.0 is used
	$(MAKE) -C $(CRAMFSDIR) LDFLAGS="" mkcramfs
	# '-u 0 -g 0' will set the uid and gid of all the files to 0 (root)
	# These options are currently only available on our version of mkcramfs
	$(CRAMFSDIR)/mkcramfs -u 0 -g 0 $(TARGETDIR) $(PLATFORMDIR)/$(ROOT_IMG)
endif
	# Package kernel and filesystem
	if grep -q "CONFIG_BLK_DEV_INITRD=y" $(LINUXDIR)/.config ; then \
		cd $(TARGETDIR) ; \
		find . | cpio -o -H newc | gzip > $(LINUXDIR)/usr/initramfs_data.cpio.gz ; \
		ls -l $(LINUXDIR)/usr/initramfs_data.cpio.gz ; \
		$(MAKE) -C $(LINUXDIR) zImage ; \
		$(MAKE) -C $(SRCBASE)/router/compressed ; \
	else \
		cp $(SRCBASE)/router/compressed/vmlinuz $(PLATFORMDIR)/ ; \
		trx -o $(PLATFORMDIR)/linux.trx $(PLATFORMDIR)/vmlinuz $(PLATFORMDIR)/$(ROOT_IMG) ; \
		addpattern -i $(PLATFORMDIR)/linux.trx -o $(PLATFORMDIR)/linux_lsys.bin -g -s ; \
		if grep -q "CONFIG_SQUASHFS=y" $(LINUXDIR)/.config ; then \
			cp $(SRCBASE)/router/compressed/vmlinuz-lzma $(PLATFORMDIR)/ ; \
			trx -o $(PLATFORMDIR)/linux-lzma.trx $(PLATFORMDIR)/vmlinuz-lzma $(PLATFORMDIR)/$(ROOT_IMG) ; \
		trx -o $(PLATFORMDIR)/linux-trim.trx $(PLATFORMDIR)/vmlinuz-lzma $(PLATFORMDIR)/$(ROOT_IMG).trim ; \
		fi \
	fi
else
	# squashfs-3.0 with lzma patch
	# mkcramfs-2.0 wth lzma patch
	if grep -q "CONFIG_EMBEDDED_RAMDISK=y" $(LINUXDIR)/.config ; then \
	    $(MAKE) -C $(LINUXDIR)/scripts/cramfs mkcramfs CXX=g++ LDFLAGS="" ; \
	    if grep -q "CONFIG_LZMA_FS_INFLATE=y" $(LINUXDIR)/.config ; then \
	        $(LINUXDIR)/scripts/cramfs/mkcramfs -l $(TARGETDIR) $(PLATFORMDIR)/target.image ; \
	        cp $(PLATFORMDIR)/target.image $(LINUXDIR)/arch/mips/ramdisk/ramdisk.gz ; \
	        $(MAKE) -C $(LINUXDIR) zImage ; \
		    if grep -q "MULTILANG_GUI_SUPPORT=1" ../cy_conf.mak ; then \
		            rm -f $(PLATFORMDIR)/*lang.* ; \
		            rm -f $(PLATFORMDIR)/lcode.trx ; \
			    $(LINUXDIR)/scripts/cramfs/mkcramfs -l www/$(WEB_PAGE) $(PLATFORMDIR)/default_lang.image ; \
		    fi \
	    else \
	        $(LINUXDIR)/scripts/cramfs/mkcramfs $(TARGETDIR) $(PLATFORMDIR)/target.image ; \
	        cp $(PLATFORMDIR)/target.image $(LINUXDIR)/arch/mips/ramdisk/ramdisk.gz ; \
	        $(MAKE) -C $(LINUXDIR) zImage ; \
		    if grep -q "MULTILANG_GUI_SUPPORT=1" ../cy_conf.mak ; then \
		            rm -f $(PLATFORMDIR)/*lang.* ; \
		            rm -f $(PLATFORMDIR)/lcode.trx ; \
			    $(LINUXDIR)/scripts/cramfs/mkcramfs www/$(WEB_PAGE) $(PLATFORMDIR)/default_lang.image ; \
		    fi \
	    fi \
	elif grep -q "CONFIG_SQUASHFS=y" $(LINUXDIR)/.config ; then \
	    $(MAKE) -C $(LINUXDIR)/scripts/squashfs LDFLAGS="" ; \
	    if grep -q "CONFIG_LZMA_FS_INFLATE=y" $(LINUXDIR)/.config ; then \
	        $(LINUXDIR)/scripts/squashfs/mksquashfs-lzma $(TARGETDIR) $(PLATFORMDIR)/target.image -le -info -noappend; \
	            if grep -q "MULTILANG_GUI_SUPPORT=1" ../cy_conf.mak ; then \
	                    rm -f $(PLATFORMDIR)/*lang.* ; \
	                    rm -f $(PLATFORMDIR)/lcode.trx ; \
		            $(LINUXDIR)/scripts/squashfs/mksquashfs-lzma www/$(WEB_PAGE) $(PLATFORMDIR)/default_lang.image -info ; \
	            fi \
	    else \
		$(LINUXDIR)/scripts/squashfs/mksquashfs $(TARGETDIR) $(PLATFORMDIR)/target.image -le -info -noappend; \
		    if grep -q "MULTILANG_GUI_SUPPORT=1" ../cy_conf.mak ; then \
		            rm -f $(PLATFORMDIR)/*lang.* ; \
		            rm -f $(PLATFORMDIR)/lcode.trx ; \
			    $(LINUXDIR)/scripts/cramfs/mkcramfs www/$(WEB_PAGE) $(PLATFORMDIR)/default_lang.image ; \
		    fi \
            fi \
	elif grep -q "CONFIG_CRAMFS=y" $(LINUXDIR)/.config ; then \
	    $(MAKE) -C $(LINUXDIR)/scripts/cramfs mkcramfs CXX=g++ LDFLAGS="" ; \
	    if grep -q "CONFIG_LZMA_FS_INFLATE=y" $(LINUXDIR)/.config ; then \
	        $(LINUXDIR)/scripts/cramfs/mkcramfs -l $(TARGETDIR) $(PLATFORMDIR)/target.image ; \
		    if grep -q "MULTILANG_GUI_SUPPORT=1" ../cy_conf.mak ; then \
		            rm -f $(PLATFORMDIR)/*lang.* ; \
		            rm -f $(PLATFORMDIR)/lcode.trx ; \
			    $(LINUXDIR)/scripts/cramfs/mkcramfs -l www/$(WEB_PAGE) $(PLATFORMDIR)/default_lang.image ; \
		    fi \
	    else \
	        $(LINUXDIR)/scripts/cramfs/mkcramfs $(TARGETDIR) $(PLATFORMDIR)/target.image ; \
		    if grep -q "MULTILANG_GUI_SUPPORT=1" ../cy_conf.mak ; then \
		            rm -f $(PLATFORMDIR)/*lang.* ; \
		            rm -f $(PLATFORMDIR)/lcode.trx ; \
			    $(LINUXDIR)/scripts/cramfs/mkcramfs www/$(WEB_PAGE) $(PLATFORMDIR)/default_lang.image ; \
		    fi \
	    fi \
	fi
	# Package kernel and filesystem
	if grep -q "CONFIG_EMBEDDED_RAMDISK=y" $(LINUXDIR)/.config ; then \
		cp -f $(LINUXDIR)/arch/mips/brcm-boards/bcm947xx/compressed/vmlinuz $(SRCBASE)/../image/mfg.bin ; \
		trx -o $(SRCBASE)/../image/mfg.trx $(LINUXDIR)/arch/mips/brcm-boards/bcm947xx/compressed/vmlinuz ; \
	fi
	cp $(LINUXDIR)/arch/mips/brcm-boards/bcm947xx/compressed/vmlinuz $(PLATFORMDIR)/ ;
	if grep -q "CONFIG_KERNEL_LZMA_COMPRESSION=y" $(LINUXDIR)/.config ; then \
		$(MAKE) -C $(SRCBASE)/../tools/lzma-loader ; \
		trx -o $(PLATFORMDIR)/linux.trx $(SRCBASE)/../tools/lzma-loader/loader.gz $(PLATFORMDIR)/vmlinuz $(PLATFORMDIR)/target.image ; \
	else \
		trx -o $(PLATFORMDIR)/linux.trx $(PLATFORMDIR)/vmlinuz $(PLATFORMDIR)/target.image ; \
	fi
endif #ifeq ($(LINUX_VERSION),2_6)
ifeq ($(LINUX_VERSION),2_6)
	# Pad self-booting Linux to a 64 KB boundary
	cp $(SRCBASE)/router/compressed/zImage $(PLATFORMDIR)/
	dd conv=sync bs=64k < $(PLATFORMDIR)/zImage > $(PLATFORMDIR)/linux.bin
	# Append filesystem to self-booting Linux
	cat $(PLATFORMDIR)/$(ROOT_IMG) >> $(PLATFORMDIR)/linux.bin
else
	# Pad self-booting Linux to a 64 KB boundary
	cp $(LINUXDIR)/arch/mips/brcm-boards/bcm947xx/compressed/zImage $(PLATFORMDIR)/
	dd conv=sync bs=64k < $(PLATFORMDIR)/zImage > $(PLATFORMDIR)/linux.bin
	# Append filesystem to self-booting Linux
	cat $(PLATFORMDIR)/target.image >> $(PLATFORMDIR)/linux.bin
endif #ifeq ($(LINUX_VERSION),2_6)

#
# Configuration rules
#

conf mconf:
	$(MAKE) -C config
	@./config/$@ ./config/Config
	# Also configure kernel
	$(MAKE) k$@

oldconf: .config
	$(MAKE) -C config
	@./config/conf -o ./config/Config
	# Also configure kernel
	$(MAKE) k$@

kconf:
	$(MAKE) -C $(LINUXDIR) config

kmconf: $(LINUXDIR)/.config
	$(MAKE) -C $(LINUXDIR) menuconfig

koldconf: $(LINUXDIR)/.config
	$(MAKE) -C $(LINUXDIR) oldconfig

# Convenience
config: conf

menuconfig: mconf

oldconfig: oldconf

# Default configurations
.config:
	cp config/defconfig-$(LINKSYS_MODEL) $@
	$(MAKE) oldconfig

$(LINUXDIR)/.config:
	cp $(LINUXDIR)/arch/mips/defconfig-bcm947xx-$(LINKSYS_MODEL) $@

#
# Overrides
#
############################
# libshared.so need MD5 functions in libbcmcrypto
shared: libbcmcrypto
	$(MAKE) -C shared
############################

$(PKG_BUSYBOX)/Config.h: dummy
ifeq ($(PKG_BUSYBOX), busybox-1.x)
	cd $(PKG_BUSYBOX) && rm -f Config.h && ln -sf include/autoconf.h Config.h && touch Config.h
endif
	cd $(PKG_BUSYBOX) && rm -f .config && cp configs/bbconfig-$(LINKSYS_MODEL) .config && $(MAKE) LDFLAGS="" clean && $(MAKE) LDFLAGS="" oldconfig
ifneq ($(PKG_BUSYBOX), busybox-1.x)
	$(MAKE) -C $(PKG_BUSYBOX) LDFLAGS="" dep
endif

$(PKG_BUSYBOX): $(PKG_BUSYBOX)/Config.h
ifeq ($(PKG_BUSYBOX), busybox-1.x)
	$(MAKE) -C $(PKG_BUSYBOX) ARCH=mips LDFLAGS="" INSTALL
else
	$(MAKE) -C $(PKG_BUSYBOX) ARCH=mips STRIPTOOL=$(STRIP) LDFLAGS=""
endif

$(PKG_BUSYBOX)-install:
	rm -rf $(INSTALLDIR)/$(PKG_BUSYBOX)
ifeq ($(PKG_BUSYBOX), busybox-1.x)
	$(MAKE) -C $(PKG_BUSYBOX) ARCH=mips STRIPTOOL=$(STRIP) CONFIG_PREFIX=$(INSTALLDIR)/$(PKG_BUSYBOX) LDFLAGS="" install
else
	$(MAKE) -C $(PKG_BUSYBOX) ARCH=mips STRIPTOOL=$(STRIP) PREFIX=$(INSTALLDIR)/$(PKG_BUSYBOX) LDFLAGS="" install
endif
	#install -D $(PKG_BUSYBOX)/libbb.so $(INSTALLDIR)/$(PKG_BUSYBOX)/usr/lib/libbb.so
	#$(STRIP) $(INSTALLDIR)/$(PKG_BUSYBOX)/usr/lib/libbb.so
	install -d $(INSTALLDIR)/$(PKG_BUSYBOX)/etc/
	ln -sf /tmp/passwd $(INSTALLDIR)/$(PKG_BUSYBOX)/etc/passwd
	ln -sf /tmp/group $(INSTALLDIR)/$(PKG_BUSYBOX)/etc/group
	ln -sf /tmp/shadow $(INSTALLDIR)/$(PKG_BUSYBOX)/etc/shadow
	ln -sf /tmp/gshadow $(INSTALLDIR)/$(PKG_BUSYBOX)/etc/gshadow

$(PKG_HTTPD): nvram shared hsiab expat $(PKG_HNAP)
	$(MAKE) -C $(PKG_HTTPD)

xyssl:
	$(MAKE) -C xyssl/library
	$(MAKE) -C xyssl/library shared

xyssl-install:
	install -D xyssl/library/libxyssl.so $(INSTALLDIR)/xyssl/usr/lib/libxyssl.so
	$(STRIP) $(INSTALLDIR)/xyssl/usr/lib/libxyssl.so

xyssl-clean:
	$(MAKE) -C xyssl/library clean
	
polarssl:
	$(MAKE) -C polarssl/library
	$(MAKE) -C polarssl/library shared

polarssl-install:
	install -D polarssl/library/libpolarssl.so $(INSTALLDIR)/polarssl/usr/lib/libpolarssl.so
	$(STRIP) $(INSTALLDIR)/polarssl/usr/lib/libpolarssl.so

polarssl-clean:
	$(MAKE) -C polarssl/library clean

selfsign:
	$(MAKE) -C selfsign/openssl/selfsign

selfsign-install:
	install -D selfsign/openssl/selfsign/selfsign $(INSTALLDIR)/$(SSL_MODULE)/usr/bin/selfsign
	$(STRIP) $(INSTALLDIR)/$(SSL_MODULE)/usr/bin/selfsign

selfsign-clean:
	$(MAKE) -C selfsign/openssl/selfsign clean

ifeq ($(CONFIG_LIBREGDOM),y)
libregdom:
	[ ! -f libregdom/Makefile ] || $(MAKE) -C libregdom

libregdom-install:
	[ ! -f libregdom/Makefile ] || $(MAKE) -C libregdom install
	
libregdom-clean:
	$(MAKE) -C libregdom clean
endif

#ifeq ($(CONFIG_TRENDMICRO_SSS),y)
#hnap: expat trendmicro
#	[ ! -f hnap/Makefile ] || $(MAKE) -C hnap

$(PKG_HNAP)-install:
	[ ! -f $(PKG_HNAP)/Makefile ] || $(MAKE) -C $(PKG_HNAP) install

$(PKG_HNAP)-clean:
	[ ! -f $(PKG_HNAP)/Makefile ] || $(MAKE) -C $(PKG_HNAP) clean
#endif	

cesmDNS:
	$(MAKE) -C cesmDNS/mDNSPosix os=linux
cesmDNS-install:
	install -D cesmDNS/mDNSPosix/build/mDNS $(INSTALLDIR)/cesmDNS/usr/sbin/cesmDNS
	install -D cesmDNS/mDNSPosix/Services.txt $(INSTALLDIR)/cesmDNS/etc/Services.txt
	$(STRIP) $(INSTALLDIR)/cesmDNS/usr/sbin/cesmDNS
cesmDNS-clean:
	$(MAKE) -C cesmDNS/mDNSPosix clean

expat:
	$(MAKE) -C expat buildlib

expat-install:
	install -D expat/libexpat.so $(INSTALLDIR)/expat/usr/lib/libexpat.so
	$(STRIP) $(INSTALLDIR)/expat/usr/lib/libexpat.so

expat-clean:
	$(MAKE) -C expat clean

$(PKG_RC): nvram shared hsiab libnet $(PKG_BUSYBOX)
ifneq ($(CONFIG_NETCONF),)
$(PKG_RC): netconf
endif
ifneq ($(CONFIG_BUSYBOX),)
$(PKG_RC): $(PKG_BUSYBOX)/Config.h
endif

www:
	$(MAKE) -C www/$(WEB_PAGE) $* INSTALLDIR=$(INSTALLDIR)/www

www-install:
	$(MAKE) -C www/$(WEB_PAGE) install INSTALLDIR=$(INSTALLDIR)/www

www-clean:
	$(MAKE) -C www/$(WEB_PAGE) clean INSTALLDIR=$(INSTALLDIR)/www

bridge:
ifeq ($(LINUXDIR), $(SRCBASE)/linux/linux-2.6)
	$(MAKE) -C bridge-1.x
else
	$(MAKE) -C bridge brctl/brctl
endif

dongle :

bridge-install:
ifeq ($(LINUXDIR), $(SRCBASE)/linux/linux-2.6)
	install -D bridge-1.x/brctl/brctl $(INSTALLDIR)/bridge/usr/sbin/brctl
else
	install -D bridge/brctl/brctl $(INSTALLDIR)/bridge/usr/sbin/brctl
endif
	$(STRIP) $(INSTALLDIR)/bridge/usr/sbin/brctl

dnsmasq-install:
	install -D dnsmasq/dnsmasq $(INSTALLDIR)/dnsmasq/usr/sbin/dnsmasq
	$(STRIP) $(INSTALLDIR)/dnsmasq/usr/sbin/dnsmasq

$(PKG_IPTABLES):
ifeq ($(LINUX_VERSION),2_6)
	[ -f $(PKG_IPTABLES)/Makefile ] || ( cd $(PKG_IPTABLES) && CC=$(CC) ./configure --prefix=/usr --with-xtlibdir=/usr/lib/iptables --host=mipsel && cd .. )
	$(MAKE) -C $(PKG_IPTABLES) BINDIR=/usr/sbin LIBDIR=/usr/lib KERNEL_DIR=$(LINUXDIR) CC=$(CC)
 
else# LINUX_VERSION 2.6
	$(MAKE) -C $(PKG_IPTABLES) BINDIR=/usr/sbin LIBDIR=/usr/lib KERNEL_DIR=$(LINUXDIR)
endif# LINUX_VERSION 2.6

$(PKG_IPTABLES)-install:
ifeq ($(CONFIG_IPTABLES),y)
	install -d $(INSTALLDIR)/$(PKG_IPTABLES)/usr/lib/iptables
	install $(PKG_IPTABLES)/extensions/*.so $(INSTALLDIR)/$(PKG_IPTABLES)/usr/lib/iptables
	$(STRIP) $(INSTALLDIR)/$(PKG_IPTABLES)/usr/lib/iptables/*.so
	install -D $(PKG_IPTABLES)/iptables $(INSTALLDIR)/$(PKG_IPTABLES)/usr/sbin/iptables
	$(STRIP) $(INSTALLDIR)/$(PKG_IPTABLES)/usr/sbin/iptables
	install -D $(PKG_IPTABLES)/iptables-restore $(INSTALLDIR)/$(PKG_IPTABLES)/usr/sbin/iptables-restore
	$(STRIP) $(INSTALLDIR)/$(PKG_IPTABLES)/usr/sbin/iptables-restore
	install -D $(PKG_IPTABLES)/ip6tables $(INSTALLDIR)/$(PKG_IPTABLES)/usr/sbin/ip6tables
	$(STRIP) $(INSTALLDIR)/$(PKG_IPTABLES)/usr/sbin/ip6tables
	install -D $(PKG_IPTABLES)/ip6tables-restore $(INSTALLDIR)/$(PKG_IPTABLES)/usr/sbin/ip6tables-restore
	$(STRIP) $(INSTALLDIR)/$(PKG_IPTABLES)/usr/sbin/ip6tables-restore
ifeq ($(LINUX_VERSION),2_6)
        # not install in iptables-1.x
else
	install -D $(PKG_IPTABLES)/libiptables.so $(INSTALLDIR)/$(PKG_IPTABLES)/usr/lib/libiptables.so
	$(STRIP) $(INSTALLDIR)/$(PKG_IPTABLES)/usr/lib/libiptables.so
	install -d $(INSTALLDIR)/$(PKG_IPTABLES)/etc/l7-protocols/protocols
	install $(PKG_IPTABLES)/l7-protocols/protocols/*.pat $(INSTALLDIR)/$(PKG_IPTABLES)/etc/l7-protocols/protocols
	install -d $(INSTALLDIR)/$(PKG_IPTABLES)/etc/l7-protocols/file_types
	install $(PKG_IPTABLES)/l7-protocols/file_types/*.pat $(INSTALLDIR)/$(PKG_IPTABLES)/etc/l7-protocols/file_types
	install -d $(INSTALLDIR)/$(PKG_IPTABLES)/etc/l7-protocols/extra
	install $(PKG_IPTABLES)/l7-protocols/extra/*.pat $(INSTALLDIR)/$(PKG_IPTABLES)/etc/l7-protocols/extra
	install -d $(INSTALLDIR)/$(PKG_IPTABLES)/etc/l7-protocols/weakpatterns
	install $(PKG_IPTABLES)/l7-protocols/weakpatterns/*.pat $(INSTALLDIR)/$(PKG_IPTABLES)/etc/l7-protocols/weakpatterns
	install -d $(INSTALLDIR)/$(PKG_IPTABLES)/etc/l7-protocols/malware
	install $(PKG_IPTABLES)/l7-protocols/malware/*.pat $(INSTALLDIR)/$(PKG_IPTABLES)/etc/l7-protocols/malware
	install $(PKG_IPTABLES)/l7-protocols/*.* $(INSTALLDIR)/$(PKG_IPTABLES)/etc/l7-protocols
endif# LINUX_VERSION 2.6
else
	# So that generic rule does not take precedence
	@true
endif

$(PKG_IPTABLES)-clean:
ifeq ($(LINUX_VERSION),2_6)
	[ -f $(PKG_IPTABLES)/Makefile ] || $(MAKE) -C $(PKG_IPTABLES) KERNEL_DIR=$(LINUXDIR) clean
else # LINUX_VERSION 2.6
	-$(MAKE) -C $(PKG_IPTABLES) KERNEL_DIR=$(LINUXDIR) clean

endif # LINUX_VERSION 2.6

#nas: nvram shared

netconf: $(PKG_IPTABLES)
ifeq ($(CONFIG_NETCONF),y)
	make LINUXDIR=$(LINUXDIR) -C netconf
else
	# In case of "Prerequisite 'iptables' is newer than target 'netconf'"
	@true
endif

nfs-utils-install:
	rm -rf $(INSTALLDIR)/nfs-utils
	$(MAKE) -C nfs-utils install INSTALLDIR=$(INSTALLDIR)/nfs-utils
	install -d $(INSTALLDIR)/nfs-utils/etc
	cd $(INSTALLDIR)/nfs-utils/etc && ln -sf /tmp/hosts.allow hosts.allow
	cd $(INSTALLDIR)/nfs-utils/etc && ln -sf /tmp/hosts.deny hosts.deny
	install -d $(INSTALLDIR)/nfs-utils/shares

ntpclient-install:
	install -D ntpclient/ntpclient $(INSTALLDIR)/ntpclient/usr/sbin/ntpclient
	$(STRIP) $(INSTALLDIR)/ntpclient/usr/sbin/ntpclient

portmap: tcp_wrapper

ppp:
	$(MAKE) -C ppp/pppoecd $* INSTALLDIR=$(INSTALLDIR)/ppp

ppp-install:
	$(MAKE) -C ppp/pppoecd install INSTALLDIR=$(INSTALLDIR)/ppp

ppp-clean:
	$(MAKE) -C ppp/pppoecd clean INSTALLDIR=$(INSTALLDIR)/ppp

popt-install:
	install -D popt/libpopt.so $(INSTALLDIR)/popt/usr/lib/libpopt.so
	$(STRIP) $(INSTALLDIR)/popt/usr/lib/libpopt.so

#raidtools: popt

udhcpd: shared nvram

se-utils: nvram sec_srl gmp

udhcpd-install:
	install -D udhcpd/udhcpd $(INSTALLDIR)/udhcpd/usr/sbin/udhcpd
	install -D udhcpd/dumpleases $(INSTALLDIR)/udhcpd/usr/sbin/dumpleases
	$(STRIP) $(INSTALLDIR)/udhcpd/usr/sbin/udhcpd
	$(STRIP) $(INSTALLDIR)/udhcpd/usr/sbin/dumpleases
	cd $(INSTALLDIR)/udhcpd/usr/sbin && ln -sf udhcpd udhcpc

#upnp: netconf nvram shared

#user_group: nvram shared

#wlconf: nvram shared

#user_note: shared

#respart: nvram shared

#disktestwait: nvram shared

#disconnect_disk: nvram shared

ifeq ($(STORAGE_SUPPORT),1)
storage: nvram shared popt
	$(MAKE) -C storage/archive
	$(MAKE) -C storage/disconnect_disk
	$(MAKE) -C storage/disktestwait
	$(MAKE) -C storage/respart
	$(MAKE) -C storage/user_group
	$(MAKE) -C storage/user_note
	$(MAKE) -C storage/wipedisks
	#$(MAKE) -C storage/raidtools
	#$(MAKE) -C storage/reiserfsprogs
	$(MAKE) -C storage/dosfstools
	$(MAKE) -C storage/mkdosfs
	#cd storage/ntfsprogs/ntfsprogs-2.0.0 && ./configure --enable-shared=no --host=mipsel-linux
	#$(MAKE) -C storage/ntfsprogs

storage-install:
	$(MAKE) -C storage/archive INSTALLDIR=$(INSTALLDIR)/storage install
	$(MAKE) -C storage/disconnect_disk INSTALLDIR=$(INSTALLDIR)/storage install
	$(MAKE) -C storage/disktestwait INSTALLDIR=$(INSTALLDIR)/storage install
	$(MAKE) -C storage/respart INSTALLDIR=$(INSTALLDIR)/storage install
	$(MAKE) -C storage/user_group INSTALLDIR=$(INSTALLDIR)/storage install
	$(MAKE) -C storage/user_note INSTALLDIR=$(INSTALLDIR)/storage install
	$(MAKE) -C storage/wipedisks INSTALLDIR=$(INSTALLDIR)/storage install
	#$(MAKE) -C storage/raidtools INSTALLDIR=$(INSTALLDIR)/storage install
	#$(MAKE) -C storage/reiserfsprogs INSTALLDIR=$(INSTALLDIR)/storage install
	$(MAKE) -C storage/dosfstools INSTALLDIR=$(INSTALLDIR)/storage install
	$(MAKE) -C storage/mkdosfs INSTALLDIR=$(INSTALLDIR)/storage install
	#$(MAKE) -C storage/ntfsprogs INSTALLDIR=$(INSTALLDIR)/storage install

storage-clean:
	$(MAKE) -C storage/archive clean
	$(MAKE) -C storage/disconnect_disk clean
	$(MAKE) -C storage/disktestwait clean
	$(MAKE) -C storage/respart clean
	$(MAKE) -C storage/user_group clean
	$(MAKE) -C storage/user_note clean
	$(MAKE) -C storage/wipedisks clean
	#$(MAKE) -C storage/raidtools clean
	#$(MAKE) -C storage/reiserfsprogs clean
	$(MAKE) -C storage/dosfstools clean
	$(MAKE) -C storage/mkdosfs clean
	#$(MAKE) -C storage/ntfsprogs clean
endif

vlan:
	$(MAKE) -C vlan CROSS=$(CROSS_COMPILE) STRIPTOOL=$(STRIP) CCFLAGS="-g -O2 -D_GNU_SOURCE -Wall -I$(LINUXDIR)/include"

vlan-install:
	$(MAKE) -C vlan CROSS=$(CROSS_COMPILE) STRIPTOOL=$(STRIP) INSTALLDIR=$(INSTALLDIR) install

vlan-clean:
	$(MAKE) -C vlan clean

#nas:
	#$(MAKE) -C nas

nas-install:
	#$(MAKE) -C nas install
	#cd $(INSTALLDIR)/nas/usr/sbin && ln -sf nas nas4not
	install -D -m 755 nas/nas/nas  $(INSTALLDIR)/nas/usr/sbin/nas
	$(STRIP) $(INSTALLDIR)/nas/usr/sbin/nas
	cd $(INSTALLDIR)/nas/usr/sbin && ln -sf nas nas4not

nas-eapd:
	$(MAKE) -C nas-eapd

nas-eapd-install:
	#$(MAKE) -C nas install
	#cd $(INSTALLDIR)/nas/usr/sbin && ln -sf nas nas4not
	install -D -m 755 nas-eapd/nas/nas  $(INSTALLDIR)/nas-eapd/usr/sbin/nas
	$(STRIP) $(INSTALLDIR)/nas-eapd/usr/sbin/nas
	cd $(INSTALLDIR)/nas-eapd/usr/sbin && ln -sf nas nas4not

libbcm:
	[ ! -f libbcm/Makefile ] || $(MAKE) -C libbcm

libbcm-install:
	[ ! -f libbcm/Makefile ] || install -D libbcm/libbcm.so $(INSTALLDIR)/libbcm/usr/lib/libbcm.so
	$(STRIP) $(INSTALLDIR)/libbcm/usr/lib/libbcm.so


########################################################################
# Below is added by CT

tftpd-install:
	[ ! -d tftpd ] || install -D tftpd/tftpd $(INSTALLDIR)/tftpd/usr/sbin/tftpd
	$(STRIP) $(INSTALLDIR)/tftpd/usr/sbin/tftpd

cron-install:
	#install -d $(INSTALLDIR)/cron/etc/cron.d
	install -D cron/cron $(INSTALLDIR)/cron/usr/sbin/cron
	$(STRIP) $(INSTALLDIR)/cron/usr/sbin/cron

pptp-client-install:
	install -D pptp-client/pptp $(INSTALLDIR)/pptp-client/usr/sbin/pptp
	$(STRIP) $(INSTALLDIR)/pptp-client/usr/sbin/pptp

pppd:
	$(MAKE) -C pppd/pppd

pppd-clean:
	$(MAKE) -C pppd/pppd clean

pppd-install:
	install -D pppd/pppd/pppd $(INSTALLDIR)/pppd/usr/sbin/pppd
	$(STRIP) $(INSTALLDIR)/pppd/usr/sbin/pppd

ipupdate:
	[ ! -d $@ ] || [ -f $@/Makefile ] || ( cd $@ && aclocal && autoconf && automake --add-missing && $(CONFIGURE) && cd .. )
	$(MAKE) -C $@
	
ipupdate-install:
	install -D ipupdate/ez-ipupdate $(INSTALLDIR)/ipupdate/usr/sbin/ez-ipupdate
	$(STRIP) $(INSTALLDIR)/ipupdate/usr/sbin/ez-ipupdate

tzoupdate-1.11-install:
	install -D tzoupdate-1.11/tzoupdate-1.11 $(INSTALLDIR)/tzoupdate-1.11/usr/sbin/tzoupdate-1.11

zebra:
	[ ! -d $@ ] || ( cd $@ && CC=$(CC) $(CONFIGURE) --disable-bgpd --disable-ripngd --disable-ospfd --disable-ospf6d --disable-bgp-announce && cd .. )
	[ ! -d $@ ] || $(MAKE) -C zebra CC=$(CC) AR=$(AR) RANLIB=$(RANLIB)

zebra-install:
	install -D zebra/zebra/zebra $(INSTALLDIR)/zebra/usr/sbin/zebra
	install -D zebra/ripd/ripd $(INSTALLDIR)/zebra/usr/sbin/ripd
	install -D zebra/lib/libzebra.so $(INSTALLDIR)/zebra/usr/lib/libzebra.so
	$(STRIP) $(INSTALLDIR)/zebra/usr/sbin/zebra
	$(STRIP) $(INSTALLDIR)/zebra/usr/sbin/ripd
	$(STRIP) $(INSTALLDIR)/zebra/usr/lib/libzebra.so

openssl:
	$(MAKE) -C openssl AR="$(AR) r"
openssl-install:
	#install -D openssl/libcrypto.so $(INSTALLDIR)/openssl/usr/lib/libcrypto.so
	#$(STRIP) $(INSTALLDIR)/openssl/usr/lib/libcrypto.so
	#install -D openssl/libssl.so $(INSTALLDIR)/openssl/usr/lib/libssl.so
	#$(STRIP) $(INSTALLDIR)/openssl/usr/lib/libssl.so
	#install -D openssl/apps/openssl $(INSTALLDIR)/openssl/usr/sbin/openssl
	#$(STRIP) $(INSTALLDIR)/openssl/usr/sbin/openssl

ifeq ($(MATRIXSSL_SUPPORT),1)
matrixssl:
	$(MAKE) -C matrixssl/src
matrixssl-install:
	install -D matrixssl/src/libmatrixssl.so $(INSTALLDIR)/matrixssl/usr/lib/libmatrixssl.so
	$(STRIP) $(INSTALLDIR)/matrixssl/usr/lib/libmatrixssl.so
matrixssl-clean:
	$(MAKE) -C matrixssl/src clean
endif





rp-l2tp-install:
	install -d $(INSTALLDIR)/rp-l2tp/usr/lib/l2tp
	install rp-l2tp/handlers/*.so $(INSTALLDIR)/rp-l2tp/usr/lib/l2tp
	$(STRIP) $(INSTALLDIR)/rp-l2tp/usr/lib/l2tp/*.so
	install -D rp-l2tp/handlers/l2tp-control $(INSTALLDIR)/rp-l2tp/usr/sbin/l2tp-control
	$(STRIP) $(INSTALLDIR)/rp-l2tp/usr/sbin/l2tp-control
	install -D rp-l2tp/l2tpd $(INSTALLDIR)/rp-l2tp/usr/sbin/l2tpd
	$(STRIP) $(INSTALLDIR)/rp-l2tp/usr/sbin/l2tpd

	#install -D curl/CA/client.crt $(INSTALLDIR)/curl/etc/CA/client.crt
	#install -D curl/CA/client.key $(INSTALLDIR)/curl/etc/CA/client.key
#	install -D curl/CA/rms.crt $(INSTALLDIR)/curl/etc/CA/rms.crt
#endif
	#install -D curl/CA/ap.xml $(INSTALLDIR)/curl/etc/CA/ap.xml
#endif



bpalogin-install:
	install -D bpalogin/bpalogin $(INSTALLDIR)/bpalogin/usr/sbin/bpalogin
	$(STRIP) $(INSTALLDIR)/bpalogin/usr/sbin/bpalogin

$(PKG_IGMP_PROXY): libnet
	[ ! -d $(PKG_IGMP_PROXY) ] || $(MAKE) -C $(PKG_IGMP_PROXY)
$(PKG_IGMP_PROXY)-install:
	[ ! -d $(PKG_IGMP_PROXY) ] || install -D $(PKG_IGMP_PROXY)/igmprt $(INSTALLDIR)/$(PKG_IGMP_PROXY)/usr/sbin/igmprt
	$(STRIP) $(INSTALLDIR)/$(PKG_IGMP_PROXY)/usr/sbin/igmprt

ifeq ($(VERIZON_LAN_SUPPORT),1)
dhcprelay-install:
	install -D dhcprelay/dhcrelay $(INSTALLDIR)/dhcprelay/usr/sbin/dhcrelay
	$(STRIP) $(INSTALLDIR)/dhcprelay/usr/sbin/dhcrelay
endif





libnet:
	mkdir -p libnet/lib
	$(MAKE) -C libnet CC=$(CC) AR=$(AR) RANLIB=$(RANLIB)

libpcap:
	$(MAKE) -C libpcap CC=$(CC) AR=$(AR) RANLIB=$(RANLIB)


 
                                                                                 
lltd:
	$(MAKE) -C lltd
lltd-install:
	install -D lltd/lld2d $(INSTALLDIR)/lltd/usr/sbin/lld2d
	install -D lltd/lld2d.conf $(INSTALLDIR)/lltd/etc/lld2d.conf
	install -D lltd/$(LINKSYS_MODEL).ico $(INSTALLDIR)/lltd/etc/lld2d.ico
	$(STRIP) $(INSTALLDIR)/lltd/usr/sbin/lld2d

                


samba-3.2.15:
	[ ! -d samba-3.2.15 ] || $(MAKE) -C samba-3.2.15 CC=$(CC)

proftpd:
	$(MAKE) -C proftpd
proftpd-install:
	install -D proftpd/proftpd $(INSTALLDIR)/proftpd/usr/sbin/proftpd
	$(STRIP) $(INSTALLDIR)/proftpd/usr/sbin/proftpd


emf:
	$(MAKE) -C emf/emfconf CROSS=$(CROSS_COMPILE)

emf-install:
	#install -d $(TARGETDIR)
	#$(MAKE) -C emf/emfconf CROSS=$(CROSS_COMPILE) INSTALLDIR=$(INSTALLDIR) install

emf-clean:
	$(MAKE) -C emf/emfconf clean

igs:
	$(MAKE) -C emf/igsconf CROSS=$(CROSS_COMPILE)

igs-install:
	#install -d $(TARGETDIR)
	#$(MAKE) -C emf/igsconf CROSS=$(CROSS_COMPILE) INSTALLDIR=$(INSTALLDIR) install

igs-clean:
	$(MAKE) -C emf/igsconf clean

igmp:
	$(MAKE) -C igmp CROSS=$(CROSS_COMPILE)

igmp-install:
ifeq ($(CONFIG_IGMP_PROXY),y)
	install -d $(TARGETDIR)
	$(MAKE) -C igmp CROSS=$(CROSS_COMPILE) INSTALLDIR=$(INSTALLDIR) install
endif

igmp-clean:
	$(MAKE) -C igmp clean



traceroute:
	$(MAKE) -C traceroute CC=$(CC)
traceroute-install:
	install -D traceroute/traceroute $(INSTALLDIR)/traceroute/usr/sbin/traceroute
	$(STRIP) $(INSTALLDIR)/traceroute/usr/sbin/traceroute

#wuzh modify 2008-2-27
#ifeq ($(HW_QOS_SUPPORT),1)
$(PKG_IPROUTE2):
	$(MAKE) -C $(PKG_IPROUTE2) KERNEL_INCLUDE=$(LINUXDIR)/include CC=$(CC) AR=$(AR)
$(PKG_IPROUTE2)-install:
	install -D $(PKG_IPROUTE2)/tc/tc $(INSTALLDIR)/$(PKG_IPROUTE2)/usr/sbin/tc
	$(STRIP) $(INSTALLDIR)/$(PKG_IPROUTE2)/usr/sbin/tc
	install -D -m 755 $(PKG_IPROUTE2)/ip/ip $(INSTALLDIR)/$(PKG_IPROUTE2)/usr/sbin/ip
	$(STRIP) $(INSTALLDIR)/$(PKG_IPROUTE2)/usr/sbin/ip
	#install -D $(PKG_IPROUTE2)/tc/prio.sh $(INSTALLDIR)/$(PKG_IPROUTE2)/usr/sbin/prio.sh
	#install -D $(PKG_IPROUTE2)/tc/cbq.sh $(INSTALLDIR)/$(PKG_IPROUTE2)/usr/sbin/cbq.sh
	#install -D $(PKG_IPROUTE2)/tc/sfq.sh $(INSTALLDIR)/$(PKG_IPROUTE2)/usr/sbin/sfq.sh
	#install -D $(PKG_IPROUTE2)/tc/vlan1.sh $(INSTALLDIR)/$(PKG_IPROUTE2)/usr/sbin/vlan1.sh
#endif

ifeq ($(PPPOE_RELAY_SUPPORT),1)
rp-pppoe:
	$(MAKE) -C rp-pppoe/src/ pppoe-relay
rp-pppoe-install:
	install -D rp-pppoe/src/pppoe-relay $(INSTALLDIR)/rp-pppoe/usr/sbin/pppoe-relay
	$(STRIP) $(INSTALLDIR)/rp-pppoe/usr/sbin/pppoe-relay
endif




ifeq ($(CONFIG_UCLIBC),y)
#UCLIBC_IPV6=../lib/mipsel-uclibc/libc.so.0
UCLIBC_IPV6=$(SRCBASE)/lib/mipsel-uclibc/libc.so.0

radvd: flex dummy
	[ ! -d $@-1.x ] || [ -f $@-1.x/Makefile ] || ( touch $@-1.x/* )
	[ ! -d $@-1.x ] || [ -f $@-1.x/Makefile ] || ( cd $@-1.x && CC=$(CC) $(CONFIGURE) --host=mipsel-linux && cd .. )
	#[ ! -d $@-1.x ] || $(MAKE) -C radvd-1.x CC=$(CC) CPPFLAGS=-O2 radvd_LDADD="-L../flex -lfl"

radvd-install:
	[ ! -d radvd-1.x ] || install -D -m 755 radvd-1.x/radvd $(INSTALLDIR)/radvd/usr/sbin/radvd
	[ ! -d radvd-1.x ] || $(STRIP) $(INSTALLDIR)/radvd/usr/sbin/radvd

radvd-clean:
	[ ! -f radvd-1.x/Makefile ] || $(MAKE) -C radvd-1.x distclean

flex: dummy
	[ ! -d $@ ] || ( cd $@ && CC=$(CC) $(CONFIGURE) && cd .. )
	[ ! -d $@ ] || $(MAKE) -C flex CC=$(CC) RANLIB=$(RANLIB)

iputils:
	[ ! -d $@ ] || [ -f $@/include-glibc/bits/socket.h ] || ( cd $@/include-glibc/bits && ln -s ../socketbits.h socket.h && cd ../../.. )
	[ ! -d $@ ] || $(MAKE) -C iputils KERNEL_INCLUDE=$(LINUXDIR)/include CC=$(CC) LDLIBS=

iputils-install:
	[ ! -d iputils ] || install -D -m 755 iputils/ping6 $(INSTALLDIR)/iputils/usr/sbin/ping6
	[ ! -d iputils ] || $(STRIP) $(INSTALLDIR)/iputils/usr/sbin/ping6
	[ ! -d iputils ] || install -D -m 755 iputils/traceroute6 $(INSTALLDIR)/iputils/usr/sbin/traceroute6
	[ ! -d iputils ] || $(STRIP) $(INSTALLDIR)/iputils/usr/sbin/traceroute6
	[ ! -d iputils ] || install -D -m 755 iputils/tracepath6 $(INSTALLDIR)/iputils/usr/sbin/tracepath6
	[ ! -d iputils ] || $(STRIP) $(INSTALLDIR)/iputils/usr/sbin/tracepath6

dhcp: libbcmcrypto shared nvram libbcm
	[ ! -d dhcp ] || [ -d dhcp/client/.deps ] || ( cd dhcp && ./configure --host=mipsel-unknown-linux && cd .. )
	[ ! -d dhcp ] || $(MAKE) -C dhcp CC=$(CC) RANLIB=$(RANLIB) AR=$(AR) LIBS="-L$(SRCBASE)/router/libbcmcrypto -lbcmcrypto"

dhcp-install:
#shared libraries for dhclient & dhcpd (IPv4, IPv6)
	[ ! -d dhcp/common ] || install -D -m 755 dhcp/common/libdhcp.so $(INSTALLDIR)/dhcp/usr/lib/libdhcp.so
	[ ! -d dhcp/common ] || $(STRIP) $(INSTALLDIR)/dhcp/usr/lib/libdhcp.so
	[ ! -d dhcp/omapip ] || install -D -m 755 dhcp/omapip/libomapi.so $(INSTALLDIR)/dhcp/usr/lib/libomapi.so
	[ ! -d dhcp/omapip ] || $(STRIP) $(INSTALLDIR)/dhcp/usr/lib/libomapi.so
	[ ! -d dhcp/dst ] || install -D -m 755 dhcp/dst/libdst.so $(INSTALLDIR)/dhcp/usr/lib/libdst.so
	[ ! -d dhcp/dst ] || $(STRIP) $(INSTALLDIR)/dhcp/usr/lib/libdst.so
	[ ! -d dhcp/dhcpctl ] || install -D -m 755 dhcp/dhcpctl/libdhcpctl.so $(INSTALLDIR)/dhcp/usr/lib/libdhcpctl.so
	[ ! -d dhcp/dhcpctl ] || $(STRIP) $(INSTALLDIR)/dhcp/usr/lib/libdhcpctl.so
	[ ! -d dhcp/minires ] || install -D -m 755 dhcp/minires/libres.so $(INSTALLDIR)/dhcp/usr/lib/libres.so
	[ ! -d dhcp/minires ] || $(STRIP) $(INSTALLDIR)/dhcp/usr/lib/libres.so
#utilities of dhclient & dhcpd (IPv4, IPv6)
	[ ! -d dhcp/client ] || install -D -m 755 dhcp/client/dhclient $(INSTALLDIR)/dhcp/usr/sbin/dhclient
	[ ! -d dhcp/client ] || $(STRIP) $(INSTALLDIR)/dhcp/usr/sbin/dhclient
	[ ! -d dhcp/server ] || install -D -m 755 dhcp/server/dhcpd $(INSTALLDIR)/dhcp/usr/sbin/dhcpd
	[ ! -d dhcp/server ] || $(STRIP) $(INSTALLDIR)/dhcp/usr/sbin/dhcpd

dhcp6s dhcp6c: dummy
	[ ! -d dhcp6 ] || [ -f dhcp6/Makefile ] || ( cd dhcp6 && ./configure CC=gcc CFLAGS="-I../shared -O2" && cd .. )
ifeq ($(CONFIG_UCLIBC),y)
	[ ! -d dhcp6 ] || $(MAKE) -C dhcp6 CC=$(CC) LIBS="$(UCLIBC_IPV6) -L$(SRCBASE)/libbcmcrypto -lbcmcrypto -L$(INSTALLDIR)/libbcmcrypto/usr/lib" $@
else
	[ ! -d dhcp6 ] || $(MAKE) -C dhcp6 CC=$(CC) LIBS="-lresolv -L$(SRCBASE)/libbcmcrypto -lbcmcrypto -L$(INSTALLDIR)/libbcmcrypto/usr/lib" $@
endif

dhcp6s-install:
	[ ! -d dhcp6 ] || install -D -m 755 dhcp6/dhcp6s $(INSTALLDIR)/dhcp6s/usr/sbin/dhcp6s
	[ ! -d dhcp6 ] || $(STRIP) $(INSTALLDIR)/dhcp6s/usr/sbin/dhcp6s

dhcp6c-install:
	[ ! -d dhcp6 ] || install -D -m 755 dhcp6/dhcp6c $(INSTALLDIR)/dhcp6c/usr/sbin/dhcp6c
	[ ! -d dhcp6 ] || $(STRIP) $(INSTALLDIR)/dhcp6c/usr/sbin/dhcp6c

dhcp6s-clean dhcp6c-clean:
	[ ! -f dhcp6/Makefile ] || $(MAKE) -C dhcp6 distclean

arp:
	$(MAKE) -C arp

arp-install:
	install -D arp/arp $(INSTALLDIR)/arp/usr/sbin/arp
	$(STRIP) $(INSTALLDIR)/arp/usr/sbin/arp

#endif

#ifeq ($(SMB3025_SUPPORT),1)
#lib-install: samba-3.0.25c
#	install samba-3.0.25c/source/bin/libbigballofmud.so $(TARGETDIR)/lib/libbigballofmud.so
#	[ ! -d lib ] || $(MAKE) -C lib install INSTALLDIR=$(INSTALLDIR)/lib
#endif


igmp-x-mld:
	$(MAKE) -C igmp-x-mld

igmp-x-mld-install:
	[ ! -d igmp-x-mld ] || install -D igmp-x-mld/igmpxmld $(INSTALLDIR)/igmp-x-mld/usr/sbin/igmpxmld
	[ ! -d igmp-x-mld ] || $(STRIP) $(INSTALLDIR)/igmp-x-mld/usr/sbin/igmpxmld

igmp-x-mld-clean:
	$(MAKE) -C igmp-x-mld clean


ifeq ($(LINUXDIR), $(SRCBASE)/linux/linux-2.6)
udev:
	$(MAKE) -C udev CROSS_COMPILE=$(CROSS_COMPILE)

udev-install:
	install -d $(TARGETDIR)
	$(MAKE) -C udev CROSS_COMPILE=$(CROSS_COMPILE) DESTDIR=$(INSTALLDIR) prefix=/udev install-udevtrigger

udev-clean:
	$(MAKE) -C udev clean

hotplug2:
	$(MAKE) -C hotplug2 CROSS_COMPILE=$(CROSS_COMPILE)

hotplug2-install:
	install -d $(TARGETDIR)
	install -d $(INSTALLDIR)/hotplug2
	$(MAKE) -C hotplug2 CROSS_COMPILE=$(CROSS_COMPILE) PREFIX=$(INSTALLDIR) install

hotplug2-clean:
	$(MAKE) -C hotplug2 clean
endif



#
# Generic rules
#

%:
	[ ! -d $* ] || $(MAKE) -C $*

%-clean:
	[ ! -d $* ] || $(MAKE) -C $* clean

%-install:
	[ ! -d $* ] || $(MAKE) -C $* install INSTALLDIR=$(INSTALLDIR)/$*

#
#
#

quick: 
	$(LINUXDIR)/scripts/squashfs/mksquashfs-lzma $(TARGETDIR) $(PLATFORMDIR)/target.image -le -noappend; 
	cp $(LINUXDIR)/arch/mips/brcm-boards/bcm947xx/compressed/vmlinuz $(PLATFORMDIR)/ ;
	trx -o $(PLATFORMDIR)/linux.trx $(SRCBASE)/../tools/lzma-loader/loader.gz $(PLATFORMDIR)/vmlinuz $(PLATFORMDIR)/target.image ; 

%-quick:
	$(MAKE) -C $* 
	$(MAKE) -C $* install INSTALLDIR=$(INSTALLDIR)/$* 
	$(MAKE) quick

www-quick:
	$(MAKE) -C www/$(WEB_PAGE) install INSTALLDIR=$(INSTALLDIR)/www

kernel-quick:
	$(MAKE) -C $(LINUXDIR) zImage 
	$(MAKE) -C $(LINUXDIR) modules
	$(MAKE) -C $(LINUXDIR) modules_install DEPMOD=/bin/true INSTALL_MOD_PATH=$(TARGETDIR)
	cp $(LINUXDIR)/arch/mips/brcm-boards/bcm947xx/compressed/vmlinuz $(PLATFORMDIR)/ ;
	trx -o $(PLATFORMDIR)/linux.trx $(SRCBASE)/../tools/lzma-loader/loader.gz $(PLATFORMDIR)/vmlinuz $(PLATFORMDIR)/target.image ; 

$(obj-y) $(obj-n) $(obj-clean) $(obj-install): dummy

.PHONY: all clean distclean mrproper install package
.PHONY: conf mconf oldconf kconf kmconf config menuconfig oldconfig
.PHONY: dummy libnet libpcap
endif
