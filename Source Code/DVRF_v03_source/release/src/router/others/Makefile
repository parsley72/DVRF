ifneq ($(wildcard $(SRCBASE)/cy_conf.mak),)
  include $(SRCBASE)/cy_conf.mak
endif

all:
	# do nothing

install: 
	install -d $(INSTALLDIR)/etc
	install -d $(INSTALLDIR)/sbin
	install -d $(INSTALLDIR)/usr/sbin
	install -d $(INSTALLDIR)/lib
	install -d $(INSTALLDIR)/pwnable
	install -d $(INSTALLDIR)/pwnable/Intro
	install -d $(INSTALLDIR)/pwnable/ShellCode_Required

	#install -d $(INSTALLDIR)/foreign_shares

	# Pwnables
	# Intro
	install -m 777 pwnable/Intro/stack_bof_01 $(INSTALLDIR)/pwnable/Intro/
	install -m 777 pwnable/Intro/heap_overflow_01 $(INSTALLDIR)/pwnable/Intro/
	install -m 777 pwnable/Intro/uaf_01 $(INSTALLDIR)/pwnable/Intro/
	install -m 755 pwnable/Intro/README $(INSTALLDIR)/pwnable/Intro/

	# Pwnables
	# ShellCode_Required

	install -m 777 pwnable/ShellCode_Required/stack_bof_02 $(INSTALLDIR)/pwnable/ShellCode_Required/
	install -m 777 pwnable/ShellCode_Required/socket_bof $(INSTALLDIR)/pwnable/ShellCode_Required/
	install -m 777 pwnable/ShellCode_Required/socket_cmd $(INSTALLDIR)/pwnable/ShellCode_Required/
	install -m 755 pwnable/ShellCode_Required/README $(INSTALLDIR)/pwnable/ShellCode_Required/

	
	install -m 755 fdisk_fat32_claim_commands.txt $(INSTALLDIR)/etc
	install services $(INSTALLDIR)/etc
	install protocols $(INSTALLDIR)/etc
	ln -sf /tmp/resolv.conf $(INSTALLDIR)/etc/resolv.conf
	ln -sf /tmp/hosts $(INSTALLDIR)/etc/hosts
	ln -sf /tmp/cron.d $(INSTALLDIR)/etc/cron.d

	install -m 755 rotatelog.sh $(INSTALLDIR)/usr/sbin

	install -m 755 check_http.sh $(INSTALLDIR)/usr/sbin

clean:

