# Makefile for nlinkd
# 
# Configure this with the following environment variables:
#

ifneq ($(wildcard $(SRCBASE)/cy_conf.mak),)
	include $(SRCBASE)/cy_conf.mak
endif

ifeq ($(LINUXDIR), $(SRCBASE)/linux/linux-2.6)
CFLAGS += -DLINUX26
endif

# where to install
INSTDIR     := $(INSTALLDIR)/usr/sbin/

# GNU target string 
#CROSS      := mipsel-uclibc-
CROSS       := $(CROSS_COMPILE)

# nothing to configure below this line... ---8<---8<---8<---

PROGS     = nlinkd

INSTMODE  = 0755
INSTOWNER = root
INSTGROUP = root

OBJS      = comm.o cyParentalCTRL.o nlinkd.o 

CC        = $(CROSS)gcc
INSTALL   = install

CFLAGS   += -I$(TOP)/shared -I$(SRCBASE)/include -I$(SRCBASE)/
LDFLAGS  += -L$(TOP)/libbcmcrypto -lbcmcrypto
LDFLAGS  += -L$(TOP)/nvram -L$(INSTALLDIR)/nvram/usr/lib -lnvram -L$(TOP)/shared -L$(INSTALLDIR)/shared/usr/lib -lshared -lpthread

CFLAGS   += -I. -Wall

ifneq ("","$(DEBUG)")
	CFLAGS   += -DDEBUG -g -Os
	STRIP     = \#
else
	CFLAGS   += -fomit-frame-pointer
	STRIP     = $(CROSS)strip
endif

ifeq ("1", "$(BSD)")
	CFLAGS   += -DBSD
endif


all: $(PROGS)

$(PROGS): $(OBJS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@
	$(STRIP) --remove-section=.comment --remove-section=.note $@

.PHONY: install
install: $(PROGS)
	$(INSTALL) -d $(INSTDIR)
	$(INSTALL) -m $(INSTMODE) $(PROGS) $(INSTDIR)

.PHONY: clean
clean:
	rm -f $(PROGS) *.o $(CORE)

