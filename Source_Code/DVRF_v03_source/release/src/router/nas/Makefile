#
# 802.1x Linux Builds Makefile
#
# Copyright (C) 2002 Broadcom Corporation
#
# $Id: Makefile,v 1.17 2003/08/11 23:18:43 Exp $
#
# targets/builds
BUILDS = nas

${BUILDS} ::
	$(MAKE) -C $@

# clean up
BUILDS-CLEAN = ${BUILDS:=-clean}

clean : ${BUILDS-CLEAN}

${BUILDS-CLEAN} ::
	$(MAKE) -C ${@:-clean=} clean

# default build
all : ${BUILDS}

# install
BUILDS-INSTALL = ${BUILDS:=-install}

install : ${BUILDS-INSTALL}

${BUILDS-INSTALL} ::
	$(MAKE) -C ${@:-install=} install
