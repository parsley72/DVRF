#makefile for selfsign

ifneq ($(wildcard $(SRCBASE)/cy_conf.mak),)
  include $(SRCBASE)/cy_conf.mak
endif

prefix=/usr
SBINDIR=/sbin
USRSBINDIR=${prefix}/sbin
USRBINDIR=${prefix}/bin
USRSHAREDIR=${prefix}/share
TOP=..


#ifdef DEBUG_SELFSIGN
# Uncomment this for extra output and to compile with debugging symbols
#DEBUG=1
#endif
#SYSLOG=1
#LOG_SELFSIGN=1
ifdef LOG_SELFSIGN
# Uncomment this to output messages to syslog, otherwise, messages go to stdout
endif
ifdef SYSLOG
CFLAG += -DSYSLOG
endif


CROSS_COMPILE?=mipsel-linux-
export CC = $(CROSS_COMPILE)gcc
export LD = $(CROSS_COMPILE)gcc
export AR = $(CROSS_COMPILE)ar r
export RANLIB = $(CROSS_COMPILE)ranlib
STRIP=$(CROSS_COMPILE)strip
INSTALL = install
MAKEDEPEND=	$(TOP)/util/domd 

INCLUDE = -I$(SRCBASE)/include/ -I$(SRCBASE)/router/shared/ -I$(SRCBASE)/ -I../include/ -I../../include/ -I../MacOS/ -I../crypto/ -I. -I..
CFLAG += $(INCLUDE)
CFLAG += -W -Wall -Wstrict-prototypes -static
ifdef DEBUG
CFLAG += -g -DDEBUG -DMY_DEBUG
STRIP=true
else
CFLAG += -Wall
CFLAG += -DL_ENDIAN -DTERMIO -O3 -fomit-frame-pointer
endif
#LDFLAGS =  -L$(TOP)/shared -lshared  -L$(TOP)/nvram -lnvram
LDFLAGS =  -L../ -lcrypto

EXEC = selfsign

OBJS_SHARED = selfsign.o
OBJS = $(OBJS_SHARED)
DIRS=   crypto
# dirs in crypto to build
SDIRS=  \
	md2 md4 md5 sha mdc2 hmac ripemd \
	des rc2 rc4 rc5 idea bf cast \
	bn rsa dsa dh dso \
	buffer bio stack lhash rand err objects \
	evp asn1 pem x509 x509v3 conf txt_db pkcs7 pkcs12 comp
	
LIB= ../libcrypto.a

LIBOBJ= ../crypto/cryptlib.o ../crypto/mem.o ../crypto/mem_dbg.o ../crypto/cversion.o ../crypto/ex_data.o ../crypto/tmdiff.o ../crypto/cpt_err.o ../crypto/ebcdic.o ../crypto/uid.o

all: $(EXEC)
	$(STRIP) --remove-section=.note --remove-section=.comment $(EXEC)

$(EXEC): Makefile $(OBJS) $(LIB)
	$(LD) $(OBJS) -o $(EXEC) $(LDFLAGS) 

$(OBJS): *.h Makefile $(CY_DEPS)

$(LIB): *.h Makefile $(LIBOBJ)
	@for i in $(SDIRS) ;\
	do \
	(echo "making libs in ../crypto/$$i ..."; \
	make -C ../crypto/$$i CC='$(CC)' CFLAG='${CFLAG}' INSTALL_PREFIX='${INSTALL_PREFIX}' INSTALLTOP='${INSTALLTOP}' PEX_LIBS='${PEX_LIBS}' EX_LIBS='${EX_LIBS}' AR='${AR}'  all ) || exit 1; \
	done;
	$(AR) $(LIB) $(LIBOBJ)
	@echo You may get an error following this line.  Please ignore.
	- $(RANLIB) $(LIB)
	@touch lib
	
.c.o:
	$(CC) $(CFLAG) -c -o $@ $< 

install: all
	$(INSTALL) $(EXEC) $(USRBINDIR)

clean:
	-rm -f selfsign *.o core $(LIB) ../crypto/*.o ../crypto/lib
	@for i in $(SDIRS) ;\
	do \
	(echo "making clean in ../crypto/$$i ..."; \
	make -C ../crypto/$$i clean ); \
	done;

