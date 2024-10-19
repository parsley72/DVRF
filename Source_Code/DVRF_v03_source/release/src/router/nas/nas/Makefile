all: 


# install to target
install: all
	install -D nas $(INSTALLDIR)/usr/sbin/nas
	$(STRIP) $(INSTALLDIR)/usr/sbin/nas
	cd $(INSTALLDIR)/usr/sbin && ln -sf nas nas4not

# clean up mess
clean:
