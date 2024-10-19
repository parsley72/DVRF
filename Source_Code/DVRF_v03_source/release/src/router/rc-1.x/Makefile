#
# Router rc control scripts Makefile
#
# Copyright 2007, Broadcom Corporation
# All Rights Reserved.
#
# THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
# KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
# SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
#
# $Id: Makefile,v 1.54 2007/09/13 08:34:53 emily Exp $
#

include $(TOP)/.config

ifneq ($(wildcard $(SRCBASE)/cy_conf.mak),)
  include $(SRCBASE)/cy_conf.mak
endif



all: 

clean:

install: all
	install -d $(INSTALLDIR)/sbin
	install rc $(INSTALLDIR)/sbin
	install qos_bw_detect $(INSTALLDIR)/sbin
	$(STRIP) $(INSTALLDIR)/sbin/rc
	install power_led $(INSTALLDIR)/sbin
	install diagwpsbutton $(INSTALLDIR)/sbin
	$(STRIP) $(INSTALLDIR)/sbin/diagwpsbutton
	$(STRIP) $(INSTALLDIR)/sbin/power_led
	$(STRIP) $(INSTALLDIR)/sbin/qos_bw_detect
	install 6rd_nud $(INSTALLDIR)/sbin
	$(STRIP) $(INSTALLDIR)/sbin/6rd_nud
	install diag_pingbutton $(INSTALLDIR)/sbin
	$(STRIP) $(INSTALLDIR)/sbin/diag_pingbutton
	install diag_tracertbutton $(INSTALLDIR)/sbin
	$(STRIP) $(INSTALLDIR)/sbin/diag_tracertbutton
ifeq ($(CONFIG_MONITOR_USB),y)
	install monitor_disk $(INSTALLDIR)/sbin
	$(STRIP) $(INSTALLDIR)/sbin/monitor_disk
endif
ifeq ($(CONFIG_WAN_DETECT),y)
	install wan_auto_detect $(INSTALLDIR)/sbin
	$(STRIP) $(INSTALLDIR)/sbin/wan_auto_detect
	install monitor_cable $(INSTALLDIR)/sbin
	$(STRIP) $(INSTALLDIR)/sbin/monitor_cable
endif
	cd $(INSTALLDIR)/sbin && ln -sf rc init
	cd $(INSTALLDIR)/sbin && ln -sf rc erase
	cd $(INSTALLDIR)/sbin && ln -sf rc write
	cd $(INSTALLDIR)/sbin && ln -sf rc restore
	cd $(INSTALLDIR)/sbin && ln -sf rc stats
	cd $(INSTALLDIR)/sbin && ln -sf rc hotplug
	cd $(INSTALLDIR)/sbin && ln -sf rc hotplug_2
	cd $(INSTALLDIR)/sbin && ln -sf rc preinit
ifeq ($(STORAGE_SUPPORT),1)
	cd $(INSTALLDIR)/sbin && ln -sf rc purgeshare
	cd $(INSTALLDIR)/sbin && ln -sf rc hotdiskadd
	cd $(INSTALLDIR)/sbin && ln -sf rc hotdiskremove
	cd $(INSTALLDIR)/sbin && ln -sf rc diskerror
endif

	cd $(INSTALLDIR)/sbin && ln -sf rc filter
	cd $(INSTALLDIR)/sbin && ln -sf rc resetbutton
	cd $(INSTALLDIR)/sbin && ln -sf rc filtersync
	cd $(INSTALLDIR)/sbin && ln -sf rc ntpd
	cd $(INSTALLDIR)/sbin && ln -sf rc ipupdated
	cd $(INSTALLDIR)/sbin && ln -sf rc redial
ifeq ($(HEARTBEAT_SUPPORT),1)
	cd $(INSTALLDIR)/sbin && ln -sf rc hb_connect
	cd $(INSTALLDIR)/sbin && ln -sf rc hb_disconnect
endif
	cd $(INSTALLDIR)/sbin && ln -sf rc disconnected_pppoe
	#cd $(INSTALLDIR)/sbin && ln -sf rc gpio
	cd $(INSTALLDIR)/sbin && ln -sf rc listen
	cd $(INSTALLDIR)/sbin && ln -sf rc check_ps
	#Jemmy port guest network function from WRT320N 2009.9.18
#ifeq ($(GUEST_NETWORK_SUPPORT),1)
#	cd $(INSTALLDIR)/sbin && ln -sf rc check_gn
#endif
	cd $(INSTALLDIR)/sbin && ln -sf rc ddns_success
	cd $(INSTALLDIR)/sbin && ln -sf rc process_monitor
ifeq ($(WL_STA_SUPPORT),1)
	cd $(INSTALLDIR)/sbin && ln -sf rc site_suvery
endif
ifeq ($(EOU_SUPPORT),1)
	cd $(INSTALLDIR)/sbin && ln -sf rc eou_status
endif
ifeq ($(SW_QOS_SUPPORT),1)
	cd $(INSTALLDIR)/sbin && ln -sf rc qos
endif
	cd $(INSTALLDIR)/sbin && ln -sf rc setreg
	cd $(INSTALLDIR)/sbin && ln -sf rc getreg
	cd $(INSTALLDIR)/sbin && ln -sf rc ppp_event
	cd $(INSTALLDIR)/sbin && ln -sf rc misc	
	cd $(INSTALLDIR)/sbin && ln -sf rc detectwan
	cd $(INSTALLDIR)/sbin && ln -sf rc check_wps_led
ifeq ($(PUSH_BUTTON_TEST_SUPPORT),1)
	cd $(INSTALLDIR)/sbin && ln -sf rc check_ses_led
	cd $(INSTALLDIR)/sbin && ln -sf rc ses_led
	cd $(INSTALLDIR)/sbin && ln -sf rc check_all_led
endif
	cd $(INSTALLDIR)/sbin && ln -sf rc sendudp
ifeq ($(T_MOBILE_SUPPORT),1)
	cd $(INSTALLDIR)/sbin && ln -sf rc check_tmobile_led
endif
ifeq ($(SYMC_OUTBREAK_SUPPORT),1)
	cd $(INSTALLDIR)/sbin && ln -sf rc oba
endif
	cd $(INSTALLDIR)/sbin && ln -sf rc gpio_check
	cd $(INSTALLDIR)/sbin && ln -sf rc ddns_checkip
	cd $(INSTALLDIR)/sbin && ln -sf rc ddns_error
	cd $(INSTALLDIR)/sbin && ln -sf rc generate_md5sum
ifeq ($(BOOTNV_SUPPORT),1)
	cd $(INSTALLDIR)/sbin && ln -sf rc bootnv
endif
ifeq ($(CONFIG_DHCPV6C), y)
	cd $(INSTALLDIR)/sbin && ln -sf rc dhclient
	cd $(INSTALLDIR)/sbin && ln -sf rc waninfo
endif
#ifeq ($(CONFIG_WIRELESS_WARNING_PAGE),y)
#	install wnbibn $(INSTALLDIR)/sbin
#	$(STRIP) $(INSTALLDIR)/sbin/wnbibn
#endif

rc: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

power_led: $(POWER_LED_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

qos_bw_detect: $(QOS_BW_DETECT_OBJS)
	$(CC) -o $@ $^ -L$(TOP)/nvram -lnvram -L$(TOP)/libbcmcrypto -lbcmcrypto -L$(TOP)/shared -lshared

6rd_nud: $(6RD_NUD_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)	

diag_pingbutton: $(DIAG_PING_BUTTON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

diag_tracertbutton: $(DIAG_TRACERT_BUTTON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

ifeq ($(CONFIG_MONITOR_USB),y)
monitor_disk: $(MONITOR_USB_DISK_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
endif

ifeq ($(CONFIG_WAN_DETECT),y)
wan_auto_detect: $(WAN_DETECTION_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
monitor_cable: $(MONITOR_CABLE_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
endif

diagwpsbutton: $(DIAG_WPS_BUTTON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
	
#ifeq ($(CONFIG_WIRELESS_WARNING_PAGE),y)
#wnbibn: $(WARNING_BLOCK_IP_BY_NAME_OBJS)
#	$(CC) -o $@ $^ $(LDFLAGS)
#endif

%.o: .%.depend
.%.depend: %.c
	$(CC) $(CFLAGS) -M $< > $@

-include $(OBJS:%.o=.%.depend)
