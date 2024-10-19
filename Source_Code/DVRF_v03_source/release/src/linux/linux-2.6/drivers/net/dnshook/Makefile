#
# Makefile for the Cybertan DNSHOOK filter
#
SRCBASE := ../../../../../
ifneq ($(wildcard $(SRCBASE)/cy_conf.mak),)
  include $(SRCBASE)/cy_conf.mak
endif

TOPDIR := $(shell /bin/pwd)
#SRCDIR := ../../../../../dnshook/sys
SRCDIR := $(SRCBASE)/dnshook/sys

obj-$(CONFIG_DNSHOOK) += dnshook.o

dnshook-objs := \
	$(SRCDIR)/skb.o \
	$(SRCDIR)/decode.o \
	$(SRCDIR)/tcp_table.o \
	$(SRCDIR)/pct_table.o \
	#$(SRCDIR)/pct6_table.o \
	$(SRCDIR)/dns_table.o \
	$(SRCDIR)/netlink.o \
	$(SRCDIR)/ssl_table.o \
	#$(SRCDIR)/ssl6_table.o \
	$(SRCDIR)/tblock.o \
	$(SRCDIR)/unblock.o \
	$(SRCDIR)/hook.o

EXTRA_CFLAGS	+= -DDMA -Werror
EXTRA_CFLAGS	+= -I$(TOPDIR)/include
ifeq ($(CONFIG_IPV6),1)
EXTRA_CFLAGS	+= -D__CONFIG_IPV6__=1
endif

# Search for sources under src/et/sys or objects under src/et/linux
EXTRA_CFLAGS    += -I$(SRCDIR)/
#vpath %.c $(SRCDIR)/dnshook/sys
