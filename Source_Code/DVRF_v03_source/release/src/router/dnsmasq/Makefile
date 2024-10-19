ifneq ($(wildcard $(SRCBASE)/cy_conf.mak),)
  include $(SRCBASE)/cy_conf.mak
endif

OBJS = cache.o rfc1035.o dhcp.o util.o option.o forward.o network.o dnsmasq.o
BINDIR = /usr/local/sbin
MANDIR = /usr/local/man


#ifeq ($(LINUX_VERSION),2_6)
#CFLAGS  += -DLINUX26
#endif

ifeq ($(DNS_SUPPORT),1)
CFLAGS  += -I. -I$(TOP)/shared -Wall -DDNS_SUPPORT=1
#ifeq ($(CONFIG_IPV6),y)
#CFLAGS += -DHAVE_IPV6 -DHAVE_LINUX_IPV6_PROC
#endif
LIBS += -L$(TOP)/nvram -L$(INSTALLDIR)/nvram/usr/lib -lnvram -L$(TOP)/libbcmcrypto -lbcmcrypto -L$(TOP)/shared -L$(INSTALLDIR)/shared/usr/lib -lshared
endif

#ifeq ($(CUSTOM404_SUPPORT),1)
CFLAGS  += -I. -I$(TOP)/shared -Wall -I$(SRCBASE)/include
LIBS += -L$(TOP)/nvram -L$(INSTALLDIR)/nvram/usr/lib -lnvram -L$(TOP)/libbcmcrypto -lbcmcrypto -L$(TOP)/shared -L$(INSTALLDIR)/shared/usr/lib -lshared
#endif


all : dnsmasq

clean :
	rm -f *~ $(OBJS) dnsmasq

.c.o: dnsmasq.h
	$(CC) $(CFLAGS) -O2 -Wall -W -c $*.c 


dnsmasq : $(OBJS) dnsmasq.h config.h
	$(CC) -o $@  $(OBJS) $(LIBS)

install : dnsmasq
	install -d $(BINDIR) -d $(MANDIR)
	install -m 644 dnsmasq.8 $(MANDIR)/man8 
	install -m 755 dnsmasq $(BINDIR)

*.o: $(CY_DEPS)


