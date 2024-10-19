#
# C library Makefile
# 
# Copyright 2007, Broadcom Corporation
# All Rights Reserved.
# 
# THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
# KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
# SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
#
# $Id: Makefile,v 1.15 2007/11/12 11:07:48 mark Exp $
#
include $(TOP)/.config
ifneq ($(wildcard ../../cy_conf.mak),)
  include ../../cy_conf.mak
endif

# Extra libraries
lib-$(CONFIG_WSC) += libstdc++
lib-$(CONFIG_LIBCRYPT) += libcrypt
lib-$(CONFIG_LIBDL) += libdl
lib-$(CONFIG_LIBM) += libm
lib-$(CONFIG_LIBNSL) += libnsl
lib-$(CONFIG_LIBPTHREAD) += libpthread
lib-$(CONFIG_LIBRESOLV) += libresolv
lib-$(CONFIG_LIBUTIL) += libutil
lib-$(CONFIG_LIBDNS) += libnss_dns
lib-$(CONFIG_LIBNSS_FILES) += libnss_files

ifeq ($(CONFIG_UCLIBC),y)
# uClibc names
LINKER := ld-uClibc.so.0
LIBC := libc.so.0
MAP := uClibc.map
else
# GNU libc names
LINKER := $(foreach lib,ld.so.* ld-linux.so.*,$(notdir $(wildcard $(LIBDIR)/$(lib))))
LIBC := libc.so.6
MAP := libc.map
endif

LIBGCC_S = $(notdir $(wildcard $(TOOLCHAIN)/lib/libgcc_s.so.?))

# it looks like some versions of gcc (3.2.3 and up for sure) have split
# gcc into 2 parts - libgcc.a and libgcc_eh.a. Since some things reference
# __register_frame_info, we need to link with -libgcc_eh if it is present - BBB 07/27/04
LIBGCC_DIR = $(dir $(shell $(CROSS_COMPILE)gcc --print-libgcc-file))
EXTRA_LIBS = -lgcc
ifneq ($(wildcard $(LIBGCC_DIR)/libgcc_eh.a),)
EXTRA_LIBS += -lgcc_eh
endif

# Nothing to do until installation

# wuzh port from vista-premium BSP 2008-2-27
# Nothing to do until installation
#all: mipsel-uclibc/libc.a
all:

ifeq ($(CONFIG_LIBOPT),y)
# Find all ELF binaries (including extra libraries)
BINARIES := $(shell find $(TARGETDIR) -path $(TARGETDIR)/lib -prune -o -type f -print | file -f - | grep ELF | cut -d':' -f1)
BINARIES += $(wildcard $(foreach lib,$(LINKER) $(lib-y),$(LIBDIR)/$(lib) $(LIBDIR)/$(lib).so.?))
BINARIES += $(TARGETDIR)/lib/libbigballofmud.so

#BINARIES += $(TOOLCHAIN)/lib/libstdc++.so.5.0.3

ifeq ($(CONFIG_GLIBC),y)
# remove?  the same lib..  Gavin
#BINARIES += $(TOOLCHAIN)/lib/$(LIBGCC_S)
BINARIES += $(TOOLCHAIN)/lib/libgcc_s.so.1
endif

ifneq ($(wildcard $(LIBDIR)/optinfo),)
# Try the toolchain directory first for precursors
OPTINFO := $(LIBDIR)/optinfo
else
# Fall back on platform directory
OPTINFO := $(PLATFORM)
endif

ifeq ($(CONFIG_UCLIBC),y)
# uClibc precursors
OBJS := $(wildcard $(foreach file,libgcc-need.a libc.a interp.o,$(OPTINFO)/$(file)))

ifeq ($(LINUX_VERSION),2_6)
CUSTOM_UCLIBC := $(TOOLCHAIN)/lib/libc.a
else
CUSTOM_UCLIBC :=  mipsel-uclibc/libc.a
endif

# wuzh port from vista-premium BSP 2008-2-27
ifeq ($(LINUX_VERSION),2_6)
ifeq ($(CONFIG_UCLIBC),y)
OBJS := $(wildcard $(foreach file,libgcc-need.a interp.o,$(OPTINFO)/$(file))) $(CUSTOM_UCLIBC)
UCLIBC_SRC=../../uClibc
mipsel-uclibc/libc.a:
	[ -f $@ ] || ( [ ! -d $(UCLIBC_SRC) ] || $(MAKE) -C $(UCLIBC_SRC) ) || \
	( mkdir -p mipsel-uclibc && cp $(UCLIBC_SRC)/lib/libc.a $@ && cp $(UCLIBC_SRC)/lib/libc.so.0 mipsel-uclibc/libc.so.0 )
endif
else #($(LINUX_VERSION),2_6)
OBJS := $(wildcard $(foreach file,libgcc-need.a interp.o,$(OPTINFO)/$(file))) $(CUSTOM_UCLIBC)
UCLIBC_SRC=../../uClibc
mipsel-uclibc/libc.a:
	[ -f $@ ] || ( [ ! -d $(UCLIBC_SRC) ] || $(MAKE) -C $(UCLIBC_SRC) ) || \
	( mkdir -p mipsel-uclibc && cp $(UCLIBC_SRC)/lib/libc.a $@ && cp $(UCLIBC_SRC)/lib/libc.so.0 mipsel-uclibc/libc.so.0 )
endif

# uClibc link parameters
ENTRY := __uClibc_init
LDFLAGS := -s -shared --warn-common --warn-once -z combreloc  -soname=$(LIBC) -init $(ENTRY)
LIBGCC := $(shell $(CC) -print-libgcc-file-name)

# wuzh port from vista-premium BSP 2008-2-27
ifeq ($(LINUX_VERSION),2_6)
ifeq ($(CONFIG_UCLIBC),y)
$(MAP): $(CUSTOM_UCLIBC)
else
$(MAP): $(OPTINFO)/libc.a
endif
	$(NM) -o --defined-only --no-sort $< | cut -d' ' -f3 > $@
else #($(LINUX_VERSION),2_6)
$(MAP): $(CUSTOM_UCLIBC)
	$(NM) -o --defined-only --no-sort $< | cut -d' ' -f3 > $@
endif

# Find all unresolved symbols that uClibc could resolve
.symbols: $(MAP) $(BINARIES)
	#rm -f $@

	for symbol in `$(NM) --dynamic -u --no-sort $(BINARIES) | sort -u` ; do \
	    grep -q "^$${symbol}$$" $(MAP) && echo "-u $${symbol}" >> $@ ; \
	    true ; \
	done
#	@echo "*******************"
#	./find_syms.pl --map $(MAP) $(addprefix --bin ,$(BINARIES)) > $@
#	@echo "^^^^^^^^^^^^^^^^^^^^^^^^^^"
# Re-link uClibc
$(LIBC): .symbols $(OBJS)
	xargs -t $(LD) $(LDFLAGS) -o $@ $(OBJS) $(LIBGCC) < .symbols

else

# GNU libc precursors
OBJS := $(wildcard $(foreach file,soinit.os libc_pic.a sofini.os,$(OPTINFO)/$(file)))

# GNU libc link parameters
ENTRY := __libc_main
CFLAGS := -shared -Wl,-O1 -Wl,-dynamic-linker=$(LINKER) -Wl,--version-script=$(MAP) -Wl,-soname=$(LIBC) -nostdlib -nostartfiles -e $(ENTRY)

$(MAP): $(OPTINFO)/libc.map
	cp $< $@

# Find all unresolved symbols that GNU libc could resolve
.symbols: $(MAP) $(BINARIES)
	./find_syms.pl --map $(MAP) $(addprefix --bin ,$(BINARIES)) > $@
	echo "INCLUDE \"ldscripts/elf32ltsmip.xs\"" >> $@
#	rm -f $@
#	for symbol in `$(NM) --dynamic -u --no-sort $(BINARIES) | sort -u` ; do \
#	    grep -q "$${symbol};" $(MAP) && echo "-u $${symbol}" >> $@ ; \
#	   done

# Re-link GNU libc
$(LIBC): .symbols $(OBJS) $(LIBDIR)/$(LINKER)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBDIR)/$(LINKER) $(EXTRA_LIBS) -T .symbols
#	xargs $(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBDIR)/$(LINKER) -lgcc < .symbols

endif

# @@@ We want a very limited version of libgcc_s, with only the symbols listed
# @@@ below.  That's so we don't accidentally pull in a bunch of floating-point
# @@@ stuff.  If any code starts using floating point, we want to modify it to
# @@@ stop using floating point since that is very slow.
./$(LIBGCC_S):
	cp $(TOOLCHAIN)/lib/$(LIBGCC_S) $@
#	$(CC) $(CFLAGS) -o $@ -Wl,-soname=$(LIBGCC_S) $(LIBDIR)/$(LINKER) -lgcc_s -u __udivdi3 -u __floatdidf


#./libstdc++.so.5.0.3:
#	cp $(TOOLCHAIN)/lib/libstdc++.so.5.0.3 $@

# Install optimized C library & extra libraries
#install: ./libstdc++.so.5.0.3
install: $(LIBC) $(LIBGCC_S) $(wildcard $(foreach lib,$(LINKER) $(lib-y),$(LIBDIR)/$(lib) $(LIBDIR)/$(lib).so.?))
else
# Install default C library & extra libraries
install: $(LIBDIR)/$(LIBC) $(wildcard $(foreach lib,$(LINKER) $(lib-y),$(LIBDIR)/$(lib) $(LIBDIR)/$(lib).so.?))
endif #($(CONFIG_LIBOPT),y)
	install -d $(TARGETDIR)/lib
	install $^ $(TARGETDIR)/lib/
	$(STRIP) $(TARGETDIR)/lib/*.so.*

clean:
	rm -f $(LIBC) $(MAP) .symbols
