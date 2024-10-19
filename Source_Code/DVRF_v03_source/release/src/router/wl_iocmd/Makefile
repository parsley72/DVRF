all: 

install: all
	install -d $(INSTALLDIR)/sbin
	install wl_iocmd $(INSTALLDIR)/sbin
	$(STRIP) $(INSTALLDIR)/sbin/wl_iocmd

clean:

#ifneq ($(wildcard $(SRCBASE)/cy_conf.mak),)
  #include $(SRCBASE)/cy_conf.mak
#endif

#CFLAGS	+= -I. -I$(TOP)/shared -I$(SRCBASE)/include -Wall -I$(SRCBASE)/
#LDFLAGS	+= -L$(TOP)/nvram -L$(TOP)/shared

#OBJS = wl_iocmd.o

#vpath %.c $(TOP)/shared $(SRCBASE)/shared/nvram 

#all:  wl_iocmd

#clean:
	#rm -f $(OBJS) *~ wl_iocmd 

#install: all
	#install -d $(INSTALLDIR)/sbin
	#install wl_iocmd $(INSTALLDIR)/sbin
	#$(STRIP) $(INSTALLDIR)/sbin/wl_iocmd

#wl_iocmd: $(OBJS)
	#$(CC) -o $@ $^ $(LDFLAGS) -lnvram -lshared

#$(OBJS): $(CY_DEPS)
