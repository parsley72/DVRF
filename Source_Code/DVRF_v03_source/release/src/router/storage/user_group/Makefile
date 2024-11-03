all: 

clean:

install: all
	install -d $(INSTALLDIR)/sbin
	install tmpuseradd $(INSTALLDIR)/sbin
	$(STRIP) $(INSTALLDIR)/sbin/tmpuseradd
	install tmpuserdel $(INSTALLDIR)/sbin
	$(STRIP) $(INSTALLDIR)/sbin/tmpuserdel
	install tmpuseraddgroup $(INSTALLDIR)/sbin
	$(STRIP) $(INSTALLDIR)/sbin/tmpuseraddgroup
	install tmpuserdelgroup $(INSTALLDIR)/sbin
	$(STRIP) $(INSTALLDIR)/sbin/tmpuserdelgroup
	install tmpgroupadd $(INSTALLDIR)/sbin
	$(STRIP) $(INSTALLDIR)/sbin/tmpgroupadd
	install tmpgroupdel $(INSTALLDIR)/sbin
	$(STRIP) $(INSTALLDIR)/sbin/tmpgroupdel
	install tmpusersetgroup $(INSTALLDIR)/sbin
	$(STRIP) $(INSTALLDIR)/sbin/tmpusersetgroup


