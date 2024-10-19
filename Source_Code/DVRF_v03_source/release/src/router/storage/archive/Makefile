all: 

clean:

install: all
	install -d $(INSTALLDIR)/sbin
	install store_machine_password $(INSTALLDIR)/sbin
	$(STRIP) $(INSTALLDIR)/sbin/store_machine_password
	install store_domain_sid $(INSTALLDIR)/sbin
	$(STRIP) $(INSTALLDIR)/sbin/store_domain_sid

