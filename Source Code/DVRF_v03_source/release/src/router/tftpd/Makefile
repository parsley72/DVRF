
ifneq ($(wildcard $(SRCBASE)/cy_conf.mak),)
  include $(SRCBASE)/cy_conf.mak
endif
ifeq ($(LINUX_VERSION),2_6)
PKG_RC := rc-1.x
else
PKG_RC := rc
endif

CFLAGS	+= -I. -I$(TOP)/shared -I$(SRCBASE)/include -I$(SRCBASE)/router/$(PKG_RC) -Wall -I$(SRCBASE)/ -I$(TOP)/busybox
CFLAGS	+= -s -O2
LDFLAGS	+= -L$(TOP)/libbcmcrypto -lbcmcrypto
LDFLAGS	+= -L$(TOP)/nvram -L$(INSTALLDIR)/nvram/usr/lib -lnvram -L$(TOP)/shared -lshared

OBJS := misc.o recvfrom.o tftpd.o tftpsubs.o xmalloc.o xstrdup.o bsdsignal.o remap.o
OBJS += $(TOP)/$(PKG_RC)/writeimage.o $(TOP)/$(PKG_RC)/bootnv.o $(TOP)/$(PKG_RC)/mtd.o $(TOP)/$(PKG_RC)/http.o

ifeq ($(T_CERT_SUPPORT),1) 
OBJS += $(TOP)/$(PKG_RC)/tmobile.o
endif 


all: 
