# tzoupdate - a minimalist dynamic DNS update client for TZO.COM
# Copyright 2007 Tzolkin Corp.
#
# LICENSE: GNU GPL v2
# ADDITIONAL TERMS: Use of the tzoupdate dynamic DNS client with Tzolkin (TZO.COM) servers
# is granted provided activity follows the TZO Developer Guidelines and 
# TZO.COM Terms Of Service (TOS), found at ttp://www.tzo.com/
#
# If this application is modified or built on untested (by TZO) platforms, please execute the
# tzoupdate testplan found at the TZO Developer website.
#
# This code requires GCC and gmake. Use of non-GNU toolchains is not supported by TZO.
# Patches and modifications to tzoupdate for untested platforms, etc. are appreciated
# and will be considered for official merging (send diff to devsupport@tzo.com)
#
# HOW TO
# make tzoupate (as non-root user)
# make install (as root)
#
# End users should be using TZO provided installation packages, if provided for their OS.
#

# Source, Executable, Includes, Library Defines
INCL   = tzoupdate.h
SRC    = tzoupdate.c
OBJ    = $(SRC:.c=.o)
LIBS   = 
#EXE    = tzoupdate
EXE    = tzoupdate-1.11
#CC      = /usr/bin/gcc
#CC      = mipsel-uclibc-gcc
#CFLAGS  = -Wall -O2
CFLAGS  = -Wall -O2 -I../../ -I../../include
LIBPATH = -L.
LDFLAGS = -o $(EXE) $(LIBPATH) $(LIBS)
#CFDEBUG = -Wall -g -DDEBUG $(LDFLAGS)
CFDEBUG = -Wall $(LDFLAGS)

# misc
#RM      	= /bin/rm -rfi 	
RM      	= /bin/rm -rf 	
CP		= /bin/cp -f
MKDIR		= /bin/mkdir
RMDIR		= /bin/rm -rf
MV		= /bin/mv
TAR		= /bin/tar
ZIP		= /usr/bin/zip
TAROPT 		= -czf
#INSTALL		= /usr/bin/install 
INSTALL		= /usr/bin/install -c

# Release, Packaging Defines used for rpms
NAME		= tzoupdate
# Get "version" from C file
VERSION		= $(shell grep 'VERSION\[' tzoupdate.c | cut -d\" -f2 | cut -d_ -f1)
RELEASE 	= $(shell cat RELEASE)

# Locations
RELEASEDIR 	= tzoupdate-$(VERSION)



#default if 'make' only
#all: tzoupdate
all: tzoupdate-1.11

# tzoupdate
$(EXE): $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ)

# Objects depend on these Libraries
$(OBJ): $(INCL)

# debug (with gdb/dbx Capable and  DEBUG flags turned on)
debug:
	$(CC) $(CFDEBUG) $(SRC)

# tzoupdate installer
install: $(EXE)
	$(INSTALL) -m 755 $(EXE) /usr/local/bin/
	$(INSTALL) -m 755 tzowrapper.sh /usr/local/bin/
	$(INSTALL) -m 755 tzodetect.sh /usr/local/bin/
	$(INSTALL) -m 644 tzoupdate.conf /etc/


## CLEANUP
clean:
#	$(RM) $(OBJ) $(EXE) $(RELEASEDIR) $(RELEASEDIR)_.tar.gz core a.out 
#	$(RM) $(RELEASEDIR)	
	$(RM) $(OBJ) $(EXE)

# Below are targets mostly intended for TZO, or package managers

# binary release macro
# TODO - Resolve .spec issue for source tarball name (allow appname-ver.src.tar.gz)
release: $(EXE)
	$(MKDIR) $(RELEASEDIR)
	$(CP) $(EXE) tzowrapper.sh tzodetect.sh tzoupdate.conf INSTALL FAQ README HISTORY $(RELEASEDIR)
	$(TAR) $(RELEASEDIR).tar.gz $(RELEASEDIR)
	$(RMDIR) $(RELEASEDIR)

# bundle sources for redistribution
tar-source:
	$(RMDIR)  $(RELEASEDIR)
	$(MKDIR) $(RELEASEDIR)
	$(CP) tzowrapper.sh tzodetect.sh tzoupdate.conf INSTALL README FAQ HISTORY Makefile *.c *.h $(RELEASEDIR) 
	$(TAR) $(TAROPT) $(RELEASEDIR).src.tar.gz $(RELEASEDIR)

# vanilla binary tarball
tar-binary: $(EXE)
	$(RMDIR) $(RELEASEDIR)
	$(MKDIR) $(RELEASEDIR)
	$(CP) $(EXE) tzowrapper.sh tzodetect.sh tzoupdate.conf INSTALL README FAQ HISTORY $(RELEASEDIR)
	$(TAR) $(TAROPT) $(RELEASEDIR).tar.gz $(RELEASEDIR)

zip-source: 
	$(RMDIR)  $(RELEASEDIR)
	$(MKDIR) $(RELEASEDIR)
	$(CP) tzowrapper.sh tzodetect.sh tzoupdate.conf INSTALL README FAQ HISTORY Makefile *.c *.h $(RELEASEDIR)
	$(ZIP) -r  $(RELEASEDIR).zip $(RELEASEDIR)

# rpm assumes you are NOT building rpms as root (ex: you use /home/user/rpmbuild/...)
rpm: tar-source tar-binary
	rpmbuild -ba ~/rpmbuild/SPECS/tzoupdate.spec




# EXPERIMENTAL Windows support via cugwin1.dll.
# Due to license conflicts we can't actually distribute cygwin1.dll. See http://cygwin.com. 
# Note you do NOT need full cygwin (you only need cygwin1.dll in the same dir as tzoupdate)
# This assumes Make was run under a Cygwin shell..
cygwin-release: release
	$(MV) $(RELEASEDIR) $(RELEASEDIR)-cygwin
	$(MV) $(RELEASEDIR)-cygwin/$(EXE) $(RELEASEDIR)-cygwin/tzoupdate.exe
	$(CP) /bin/cygwin1.dll $(RELEASEDIR)-cygwin
#
