# I assume that cc will be in your path.
# If not, you have to change the following to point to it.
#CC = /opt/brcm/hndtools-mipsel-linux/bin/mipsel-linux-gcc
#CC = cc
#CFLAGS_COMMON = -g -I../mDNSCore -I. -DHAVE_MSGHDR_MSG_CONTROL -DMDNS_POSIX -DMDNS_DEBUGMSGS=2
#CFLAGS_COMMON = -g -I../mDNSCore -I. -DHAVE_MSGHDR_MSG_CONTROL -DMDNS_POSIX
#Down Size
CFLAGS_COMMON = -g -I../mDNSCore -I. -DHAVE_MSGHDR_MSG_CONTROL -DMDNS_POSIX -DMDNS_DEBUGMSGS=2 -DDOWN_SIZE
#CFLAGS_COMMON = -g -I../mDNSCore -I. -DHAVE_MSGHDR_MSG_CONTROL -DMDNS_POSIX -DDOWN_SIZE

ifeq ($(os),solaris)
CFLAGS_OS = -D_XPG4_2 -D__EXTENSIONS__ -lsocket
else
ifeq ($(os),linux)
CFLAGS_OS = -DHAVE_DAEMON -DHAVE_SOCKLEN_T
else
ifeq ($(os),openbsd)
CFLAGS_OS = -DHAVE_SOCKADDR_SA_LEN -DHAVE_DAEMON -DHAVE_SOCKLEN_T -DHAVE_BROKEN_RECVDSTADDR
else
ifeq ($(os),osx)
CFLAGS_OS = -no-cpp-precomp -Wall -DHAVE_SOCKADDR_SA_LEN -DHAVE_DAEMON
else
cantbuild:
	echo "Error: Must specify target OS on command-line, e.g. \"make os=osx\" or \"make os=linux\""
endif
endif
endif
endif

CFLAGS = $(CFLAGS_COMMON) $(CFLAGS_OS)

#COMMON = objects/mDNSPosix.c.o objects/ExampleClientApp.c.o objects/mDNSUNP.c.o objects/mDNS.c.o
COMMON = objects/mDNSPosix.c.o objects/mDNSUNP.c.o objects/mDNS.c.o objects/HostNameList.c.o

HEADERS = Makefile mDNSUNP.h mDNSPosix.h HostNameList.h  \
../mDNSCore/mDNSDebug.h                    \
../mDNSCore/mDNSClientAPI.h                \
../mDNSCore/mDNSPlatformFunctions.h 

#all: setup Client Responder ProxyResponder
all: setup mDNS

setup:
	if test ! -d objects ; then mkdir objects ; fi
	if test ! -d build   ; then mkdir build   ; fi

Client: setup build/mDNSClientPosix
	echo "Client done!"

Responder: setup build/mDNSResponderPosix
	echo "Responder done!"

mDNS: setup build/mDNS
	echo "mDNS done!"
ProxyResponder: setup build/mDNSProxyResponderPosix
	echo "ProxyResponder done!"

build/mDNSClientPosix: $(COMMON) objects/Client.c.o
	$(CC) $(CFLAGS) $(COMMON) objects/Client.c.o -o build/mDNSClientPosix

build/mDNSResponderPosix: $(COMMON) objects/Responder.c.o
	$(CC) $(CFLAGS) $(COMMON) objects/Responder.c.o -o build/mDNSResponderPosix

build/mDNS: $(COMMON) objects/Responder.c.o
	$(CC) $(CFLAGS) $(COMMON) objects/Responder.c.o -o build/mDNS

build/mDNSProxyResponderPosix: $(COMMON) objects/ProxyResponder.c.o
	$(CC) $(CFLAGS) $(COMMON) objects/ProxyResponder.c.o -o build/mDNSProxyResponderPosix

objects/Client.c.o: $(HEADERS) Client.c
	$(CC) -c $(CFLAGS) -o objects/Client.c.o Client.c

objects/Responder.c.o: $(HEADERS) Responder.c
	$(CC) -c $(CFLAGS) -o objects/Responder.c.o Responder.c

objects/ProxyResponder.c.o: $(HEADERS) ProxyResponder.c
	$(CC) -c $(CFLAGS) -o objects/ProxyResponder.c.o ProxyResponder.c

objects/mDNSPosix.c.o: $(HEADERS) mDNSPosix.c
	$(CC) -c $(CFLAGS) -o objects/mDNSPosix.c.o mDNSPosix.c

objects/HostNameList.c.o: $(HEADERS) HostNameList.c
	$(CC) -c $(CFLAGS) -o objects/HostNameList.c.o HostNameList.c

objects/ExampleClientApp.c.o: $(HEADERS) ExampleClientApp.c
	$(CC) -c $(CFLAGS) -o objects/ExampleClientApp.c.o ExampleClientApp.c

objects/mDNSUNP.c.o: $(HEADERS) mDNSUNP.c
	$(CC) -c $(CFLAGS) -o objects/mDNSUNP.c.o mDNSUNP.c

objects/mDNS.c.o: $(HEADERS) ../mDNSCore/mDNS.c
	$(CC) -c $(CFLAGS) -o objects/mDNS.c.o ../mDNSCore/mDNS.c

clean:
	-rm -rf objects
	-rm -rf build
	-rm -f .gdb_history
