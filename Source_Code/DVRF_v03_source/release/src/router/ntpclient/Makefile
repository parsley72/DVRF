# Under Solaris, you need to 
#    CFLAGS += -xO2 -Xc
#    LDLIBS += -lnsl -lsocket
# Some versions of Linux may need
#    CFLAGS += -D_GNU_SOURCE
# To cross-compile
#    CC = arm-linux-gcc

CFLAGS += -Wall -O

all: clean ntpclient

test: ntpclient
	./ntpclient -d -r <test.dat

ntpclient.o:
#	$(CC) $(CFLAGS) -I$(SRCBASE)/include -muclibc -c ntpclient.c
	$(CC) $(CFLAGS) -I$(SRCBASE)/include -c ntpclient.c
phaselock.o:
#	$(CC) $(CFLAGS) -muclibc -c phaselock.c
	$(CC) $(CFLAGS) -c phaselock.c

#ntpclient: ntpclient.o phaselock.o
#	$(CC) -muclibc -L$(SRCBASE)/router/nvram -lnvram $(OBJS) -o $@
OBJS = ntpclient.o phaselock.o
ntpclient: $(OBJS)
	$(CC) -L$(SRCBASE)/router/nvram -lnvram $(OBJS) -o $@

clean:
	rm -f ntpclient *.o
