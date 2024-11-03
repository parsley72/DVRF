#!/bin/sh
# Detects which OS Distribution and Release
#
# Author: anonymous
# modified: Feb 07, Scott Prive: moved redhat-release test to END of Linux
#  block, which is more accurate because Fedora and Mandriva etc distros 
#  symlink /etc/redhat-release to their own *release file.

#set -x

OS=`uname -s`
REV=`uname -r`
MACH=`uname -m`


if [ "${OS}" = "SunOS" ] ; then
    OS=Solaris
    ARCH=`uname -p` 
    OSSTR="${OS} ${REV}(${ARCH} `uname -v`)"
elif [ "${OS}" = "AIX" ] ; then
    OSSTR="${OS} `oslevel` (`oslevel -r`)"
elif [ "${OS}" = "Linux" ] ; then
    KERNEL=`uname -r`
    if [ -f /etc/SuSE-release ] ; then
        DIST=`cat /etc/SuSE-release | tr "\n" ' '| sed s/VERSION.*//`
        REV=`cat /etc/SuSE-release | tr "\n" ' ' | sed s/.*=\ //`
	elif [ -f `which lsb_release` ] ; then
		#ex Gentoo 6, Fedora Core 6, others LSB like distros
		# bug: this introduces a prefixed space
		DIST=`lsb_release -i|cut -d: -f2`
		PSEUDONAME=`lsb_release -i|cut -d: -f2`
		REV=`lsb_release -r|cut -d: -f2`
    elif [ -f /etc/mandrake-release ] ; then
        DIST='Mandrake'
        PSUEDONAME=`cat /etc/mandrake-release | sed s/.*\(// | sed s/\)//`
        REV=`cat /etc/mandrake-release | sed s/.*release\ // | sed s/\ .*//`
    elif [ -f /etc/debian_version ] ; then
        DIST="Debian `cat /etc/debian_version`"
        REV=""
    elif [ -f /etc/redflag-release ] ; then
        DIST="RedFlag"
        PSEUDONAME=`cat /etc/redflag-release | sed s/.*\(// | sed s/\)//`
        REV=`cat /etc/redflag-release | sed s/.*release\ // | sed s/\ .*//`
    elif [ -f /etc/UnitedLinux-release ] ; then
        DIST="${DIST}[`cat /etc/UnitedLinux-release | tr "\n" ' ' | sed s/VERSION.*//`]"
    elif [ -f /etc/fedora-release ] ; then
		# Needed. Prior to Fc4 (?), lsb_release was not a guaranteed install
        DIST='Fedora Core'
        PSUEDONAME=`cat /etc/fedora-release | sed s/.*\(// | sed s/\)//`
        REV=`cat /etc/fedora-release | sed s/.*release\ // | sed s/\ .*//`
    elif [ -f /etc/redhat-release ] ; then
        DIST='RedHat'
        PSUEDONAME=`cat /etc/redhat-release | sed s/.*\(// | sed s/\)//`
        REV=`cat /etc/redhat-release | sed s/.*release\ // | sed s/\ .*//`
    fi
    OSSTR="${OS} <${DIST} ${REV}> (${PSUEDONAME} ${KERNEL} ${MACH})"
elif [ "${OS}" = "FreeBSD" ] ; then
    ARCH=`uname -p`
    OSSTR="${OS} ({$ARCH} `uname -v`)"
elif [ "${OS}" = "CYGWIN_NT-5.1" ] ; then
    ARCH=`uname -m`
    OSSTR="${OS} ({$ARCH} `uname -v`)"
elif [ "${OS}" = "Darwin" ] ; then
    ARCH=`uname -m`
    REV=`uname -v|cut -d' ' -f4|tr -d ':'`
    OSSTR="${OS} <{$REV}> ({$ARCH})"
else
    OSSTR=`uname -v`
fi


echo ${OSSTR}
