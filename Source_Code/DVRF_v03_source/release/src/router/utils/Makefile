#
# Miscellaneous utilities Makefile
#
# Copyright (C) 2009, Broadcom Corporation
# All Rights Reserved.
# 
# THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
# KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
# SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
#
# $Id: Makefile,v 1.37 2009-08-21 12:42:11 Exp $
#

ifeq ($(RWL),1)
WL_OBJS := wlu.o wlu_cmd.o wlu_iov.o wlu_linux.o bcmutils.o bcmwifi.o wlu_client_shared.o wlu_pipe.o wlu_pipe_linux.o miniopt.o bcm_app_utils.o
SERVER_OBJS := wlu_server_linux.o wlu_pipe_linux.o wlu_pipe.o wlu_server_shared.o shellproc_linux.o
APUT_OBJS := wfa_apcmdproc.o wfa_apcmdlib.o wfa_apcs.o wfa_apcmdresp.o wfa_apcmdvalid.o wfa_apcmdtbls.o wfa_apcmdcvt.o wfa_val2str.o wfa_apdiy.o wfa_sock.o wfa_aput_all.o

SOCKET_OBJS := $(SERVER_OBJS:%.o=socket/%.o)
WIFI_OBJS := $(SERVER_OBJS:%.o=wifi/%.o)
WL_OBJS := $(WL_OBJS:%.o=wl_obj/%.o) 
WFA_APUT_OBJS := $(APUT_OBJS:%.o=aput/%.o)

SERVER_SOCKET  := wl_server_socket
SERVER_WIFI  := wl_server_wifi
WFA_APUT_ALL := wfa_aput_all
WL_EXE  := wl
endif

ifneq ($(wildcard $(SRCBASE)/cy_conf.mak),)
  include $(SRCBASE)/cy_conf.mak
endif

ifdef IPV6_SUPPORT
#UTILS := epi_ttcp cal generate_pin generate_ula
# epi_ttcp & cal are useless for E2500
UTILS := generate_pin generate_ula
else
UTILS := epi_ttcp generate_pin
endif
CFLAGS += -s -O2 -I$(SRCBASE)/include
CFLAGS += -DBCMINTERNAL -DBCMDBG

CFLAGS += -DLINUX -I$(SRCBASE)/wl/exe

#ifdef WLCNT
CFLAGS += -DWLCNT
#endif

vpath %.c $(SRCBASE)/tools/misc

ifneq ($(wildcard $(SRCBASE)/et/linux/et.c),)
UTILS += et
vpath %.c $(SRCBASE)/et/linux
endif

ifdef WL_APP_SUPPORT
ifneq ($(wildcard $(SRCBASE)/wl/exe),)
CFLAGS += -I$(SRCBASE)/wl/exe
UTILS += wl
vpath %.c $(SRCBASE)/wl/exe $(SRCBASE)/shared
endif
endif

ifeq ($(RWL),1)
ifeq ($(BUILD_WFA_APUT),1)
ifneq ($(wildcard $(SRCBASE)/router/aput),)
CFLAGS += -I$(SRCBASE)/router/aput
UTILS += $(WFA_APUT_ALL)
vpath %.c $(SRCBASE)/router/aput
endif
endif

ifneq ($(wildcard $(SRCBASE)/wl/exe),)
UTILS += $(SERVER_SOCKET)
vpath %.c $(SRCBASE)/wl/exe $(SRCBASE)/shared
endif

ifneq ($(wildcard $(SRCBASE)/wl/exe),)
UTILS += $(SERVER_WIFI)
vpath %.c $(SRCBASE)/wl/exe $(SRCBASE)/shared
endif
endif

all: $(UTILS)

wl: wlu.o wlu_cmd.o wlu_iov.o wlu_linux.o bcmutils.o bcmwifi.o wlu_client_shared.o wlu_pipe.o wlu_pipe_linux.o miniopt.o bcm_app_utils.o
	$(CC) $^ -o $@ $(LDFLAGS)

ifeq ($(RWL),1)
$(WFA_APUT_ALL): $(WFA_APUT_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ 

aput/%.o: %.c
	@mkdir -p aput
	$(CC) -c $(CFLAGS) -o $@ $^
$(SERVER_SOCKET): $(SOCKET_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ 

socket/%.o: %.c
	@mkdir -p socket
	$(CC) -c $(CFLAGS) -DRWL_SOCKET -o $@ $^

$(SERVER_WIFI): $(WIFI_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

wifi/%.o: %.c
	@mkdir -p wifi
	$(CC) -c $(CFLAGS) -DRWL_WIFI -o $@ $^
endif

clean:
	rm -f *.o *~ $(UTILS)

install: all
	install -d $(INSTALLDIR)/usr/sbin
	install $(UTILS) $(INSTALLDIR)/usr/sbin
	$(STRIP) $(foreach file,$(UTILS),$(INSTALLDIR)/usr/sbin/$(file))

generate_pin:
	$(CC) -s -o generate_pin generate_pin.c -Wall -I$(TOP)/shared -I$(TOP)/busybox -I$(SRCBASE)/include -I$(SRCBASE)/ -L$(TOP)/nvram -L$(TOP)/shared -lnvram -lshared

generate_ula:
ifeq ($(POLARSSL_SUPPORT),1)
	$(CC) -s -o generate_ula generate_ula.c \
		-Wall -I$(SRCBASE) -I$(SRCBASE)/include -I$(TOP)/polarssl/include \
		-L$(TOP)/nvram -lnvram \
		-L$(TOP)/polarssl/library -lpolarssl
else
	$(CC) -s -o generate_ula generate_ula.c \
		-Wall -I$(SRCBASE) -I$(SRCBASE)/include -I$(TOP)/polarssl/include \
		-L$(TOP)/nvram -lnvram \
		-L$(TOP)/openssl -lcrypto
endif


