#
# create by marcel.liao@cybertan.com.tw 2010.10.08
#

all:
	$(MAKE) -C source

install: all
	rm -rf $(INSTALLDIR)/usr/local/samba/private
	rm -rf $(INSTALLDIR)/usr/local/samba/var/locks
	rm -rf $(INSTALLDIR)/usr/local/samba/lib/*
	rm -rf $(INSTALLDIR)/usr/local/samba/bin/*
	rm -rf $(INSTALLDIR)/usr/local/samba/sbin/*
	$(MAKE) -C source install
	install -D $(INSTALLDIR)/usr/local/samba/bin/libbigballofmud.so $(INSTALLDIR)/lib/libbigballofmud.so
	cd $(INSTALLDIR)/lib && ln -snf libbigballofmud.so libbigballofmud.so.0
	rm -rf $(INSTALLDIR)/usr/local/samba/bin/libbigballofmud.so
	$(STRIP) -R.comment $(INSTALLDIR)/lib/libbigballofmud.so
	$(STRIP) -R.comment $(INSTALLDIR)/usr/local/samba/sbin/nmbd
	$(STRIP) -R.comment $(INSTALLDIR)/usr/local/samba/sbin/smbd
	$(STRIP) -R.comment $(INSTALLDIR)/usr/local/samba/bin/smbpasswd
	rm -f $(INSTALLDIR)/usr/local/samba/lib/smb.conf
	cd $(INSTALLDIR)/usr/local/samba/lib && ln -sf /tmp/samba/lib/smb.conf smb.conf
	rm -rf $(INSTALLDIR)/usr/local/samba/private
	cd $(INSTALLDIR)/usr/local/samba && ln -sf /tmp/samba/private private
	rm -rf $(INSTALLDIR)/usr/local/samba/var/locks
	cd $(INSTALLDIR)/usr/local/samba/var && ln -sf /tmp/samba/var/locks locks
	install -D smb-adduser $(INSTALLDIR)/usr/local/samba/bin/smbadduser

clean:
	$(MAKE) -C source clean
