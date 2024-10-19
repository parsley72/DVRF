#!/bin/sh

# WRAPPER SCRIPT FOR TZO COMMAND LINE CLIENT
#
# Copyright 2007 Tzolkin Corporation.
# Licensed under terms of GNU GPL version 2
# Alternate licensing is available if requested.
#
# Version: Same as tzoupdate --help
#
# Author: Scott Prive
#
# This Wrapper contains important features which ensure best TZO
# performance, as well as to prevent accidental account abuse.
#
# End users need only edit their TZO Config file (tzoupdate.conf)
# End Users on mainstream UNIX or Linux platforms SHOULD NOT 
# need to edit THIS file.
# If you are using something less than /bin/sh (such as busybox), you
# may need to tweak this. Please send platform specific contributions
# or updates to devsupport@tzo.com
#
# If the killfile is created, first thing you should check is your
# account (is it mis-entered in config? Expired?)
#
# If your shell is "less" than standard /bin/sh (such as is with busybox), 
# you may need to debug/tweak this wrapper.
#
# DEBUG NOTE: several of the 'if' tests have expanded variables
# ex: xx$FOO = "xx1 when testing if $FOO = 1
# This is to avoid difficult to debug errors if the variable were undefined
# (unary shell test errors).
# 
#
# BEGIN FUNCTIONS -- SCROLL DOWN FOR THE MAIN CODE

# detect_os attempts to gather OS and distro-specific info
# This is helpful information for TZO Support.
detect_os()
{
    # The purpose of detect_os is to enhance the HTTP User-Agent strings provided by
    # the tzoupdate.c function. The extra information gathered here is the OS provider,
    # distribution name, kernel-version, and CPU type.
    #
    # Because there is no universal function for gathering these details, and because
    # the rules for detecting OS's are rather 'dynamic', these shell helpers must exist.
    # The information gathered is standard per the HTTP RFC, and is used by TZO to
    # improve services, proactively monitor and alert customers to problems, etc.
    #
    # OEMS and systems providers will most likely know the full OS/versions/platform information
    # therefore this USER-AGENT helper shell function may be redundant...
    #
    # End users running tzoupdate/tzowrapper on as-yet unsupported systems may encounter
    # cases where tzoupdate does not detect their OS details. Patches that improve the checking for their OS
    # are gratefully accepted.
    # Returns OSSTRING in format of:  [ OS <distribution release> (kernel-version CPU-arch) ]
    
    if [ -f ${LSBRELEASE} ]; then
	# Info not currently provided by lsb_release
	OS=`uname -s` 				# OS name: "Linux" 

	DIST=`lsb_release -i|cut -d: -f2`	# distributor: "CentOS"
	REV=`lsb_release -r|cut -d: -f2`	# release: "4.4"

	PSEUDONAME=`lsb_release -d|cut -d: -f2`
	KERNEL=`uname -r`
	MACH=`uname -m`

	# Final string
	OSSTRING="${OS} <${DIST} ${REV}> (${PSUEDONAME} ${KERNEL} ${MACH})"
    elif [ -r ${TZODETECT} ]; then
	# It's not clear why, but sometimes this results in sh:not found (ex: Ubuntu 7.04). 
	# (Code since updated to use lsb_release if it exists, but TZODETECT is provided
	# to give support to pre-LSB Linux, such as Red Hat 9.
        OSSTRING=`${TZODETECT}`
    else
        echo "ERROR: TZO update library file (${TZODETECT}) seems missing; lsb_release not found. Aborting.."
	exit 127
    fi
}

# get the location of IPFILE (IP cache holder)
detect_log_filename()
{
    # if -f supplied,  grep that file for the log name.
    if [ -f "${TZOCONFIG}" ]; then
        # This may not be portable. I did not put any effort into
        # stripping end of line for Windows or MacOS
        IPTMP=`grep IPFILE ${TZOCONFIG}`
        IPFILE=`echo $IPTMP | tr -d 'IPFILE='|tr -d '\015'` #also eliminate \r
    else
        echo "ERROR: Could not open TZO config file (${TZOCONFIG}). Aborting.."
    fi
}

# detects age of ip cache file in seconds - This helps prevent accidental abuse,
# and helps avoid exposing the user to an unexpected 'IP blocked for 60 seconds'
# (This may innocently occur if the user updates once with mistyped credentials -
# example: bad spelling of domain - and the user fixes this and re-sends the update.
# The server does not like the second update due to traffic load, even if the
# update is correctly formed [client should guarantee a 60 second span between
# any two updates, be the update good or bad]. ).
# It is simple to avoid this error althogether, so we do so here...
detect_ipfile_age()
{
    if [ -f ${IPFILE} ]; then
        TIME_FILE=`stat --format='%Y' $IPFILE`
	#workaround if OS has no 'stat' command (Solaris, Scratchbox, OS X)
	if [ "x${TIME_FILE}" == "x" ]; then
		TIME_FILE = 0
	fi
        TIME_CLOCK=`date +%s`
        IPFILE_AGE=`expr ${TIME_CLOCK} "-" ${TIME_FILE}`
    else 
        # file does not exist, so make assumption this is a new install (no wait)
        IPFILE_AGE=60
    fi
    # Is IPFILE age < 60 seconds? Force 60 second wait to be safe..
    if [ $IPFILE_AGE -lt 60 ]; then
        #echo "Hmm. You just tried updating the server 60 seconds ago."
        #echo "To prevent server abuse, script will pause for 60 seconds."
        sleep 60
    fi
}

detect_killfile()
{
	# shutdown file. Used if server issues permanent fail
	# Also used currently if server returns 'expired'
	# Owner of installation must fix the problem AND remove the killfile    
	if [ -f ${KILLFILE} ]; then
		# We don't suppress this error even if QUIETMODE
	    MESSAGE="ERROR: Killfile found (${KILLFILE}). Please FIX your TZO config/account (then remove killfile)."
		echo "${MESSAGE}" > ${TZOLOG}
	    exit 3
	fi
}

create_killfile()
{
	# This function is for your protection: if there is a fatal error with your
	# account or account info, this shutdown prevents abuse of TZO and waste of
	# your server bandwidth. This also covers situations where the TZO account
	# is left to expire but the client was not uninstalled. 
	if [ $RETURNCODE -eq 2 ]; then
		MSG="TZO Account shutdown. Reason: tzoupdate exited with code 2. Expired TZO??"
	elif [ $RETURNCODE -eq 3 ]; then
		MSG="TZO Account shutdown. Reason: tzoupdate exited with code 3. Bad host/key/email email in tzoconfig??"
	fi
	echo "${MSG}" > ${KILLFILE}
	echo "${OUTPUT}" >> ${KILLFILE}
}

detect_args()
{
	# This function is depricated, left in for test purposes. This is a holdover from
	# older tzoupdate that did not assume .conf file would be in /etc
	if [ $# -eq 0 ]; then
	    # no arguments? OK asume TZOCONFIG is in same dir
	    TZOARGS="-f ${TZOCONFIG}"
	else
	    TZOARGS="$@"
	fi
}

invoke_tzoupdate()
{
    if [ ! -x "${TZOUPDATE}" ]; then
        echo "ERROR: The TZO file (${TZOUPDATE}) is NOT executable. Exiting.."
        exit 127
    fi
	OUTPUT=`${TZOUPDATE} ${TZOARGS} -u "${OSSTRING}" -v`   #verbose output of tzoupdate
	RETURNCODE=$?           # exit code
}



###########################################################
# START WRAPPER SCRIPT
# FILE PATH VARS - DO NOT CHANGE UNLESS YOU TEST CAREFULLY
###########################################################
# NOTE:
# If running via cron, check both:
# 1) be sure this is NOT running as a daemon (or you'll get multiple
# copies running, memory issues, and TZO suspended for client abuse)., you MUST use fully-qualified paths
# 2) verify all file paths are fully qualified, 
# eg /usr/local/bin/tzoupdate or /home/exampleuser/bin/tzoupdate
# You must not make radical changes unless you can test
# that those changes won't cause extra/abuse updates.
# 

# DAEMON mode:
# possible values: 1 or 0
# #
# "daemon" (daemon = 1) mode means tzowrapper.sh will run in a constant loop, and every 10 minutes (600 seconds) tzowrapper
# will invoke the tzoupdate library (to check/update the IP).
#
# Practically speaking, DAEMON="0" has usefulness limited to MANUALLY installing
# the tzoupdate components on a non-"desktop" Linux, such as a Busybox or Maemo
# (until I get around to packaging for Maemo anyways). Point being here that
# Daemon=1 is encouraged as it is more robust and easier to support (ie,
# no one has to examine your `crontab -l` output which leads to distro-specific
# technical support). If you use DAEMON=0, you'll have to use crontab to invoke
# tzowrapper, and be prepared to own any resulting support issues.
#
DAEMON="1"

#TODO - use prefix vars to more easily support alternate-location installs
KILLFILE="/tmp/tzo-killfile"    # cookie/killfile if major/fatal update error
TZOUPDATE="/usr/local/bin/tzoupdate"         # path to TZO Update
TZOCONFIG="/etc/tzoupdate.conf"  	# Place for all TZO settings
IPFILE=""                       # This location gets set later (parsed from TZOCONFIG).
TZOLOG="/tmp/tzolog.txt"        # Save the output of this client here
# OS info
LSBRELEASE="/usr/bin/lsb_release"  	# Detecting OS on newer (LSB-compliant) Linux
TZODETECT="/usr/local/bin/tzodetect.sh" # Detecting OS on non-LSB compliant Linux, and other UNIX

# Get the domain name. We don't do much with $DOMAIN inside the wrapper, but we want to at least sanity-check
# that the $DOMAIN is not the TZO-default "example.tzo.com". Finding this indicates the end user is trying
# to run tzoupdate without actually configuring it (server abuse...)
DOMAIN=`grep DOMAIN $TZOCONFIG|cut -f2 -d=`
if [ $DOMAIN = "example.tzo.com" ]; then
	# Error - $TZOCONFIG is is still configured with example.tzo.com. User must fix config
	echo "ERROR: Config file $TZOCONFIG is invalid (contains domain $DOMAIN)."
	echo "Please enter your TZO domain into $TZOCONFIG. Now exiting.."
	exit 127
fi


# DAEMON CHECKING
# DO NOT EDIT THE 'KEEPRUNNING' VARIABLE, NOR BYPASS THESE CHECKS! 
# TROUBLESHOOTING TIP: If the script is stopping here, the update is failing "already". Check the tzo logs/output in /tmp to see "why"
# the update failed, or contact TZO Support for help. The killfile will never appear on its own for no reason, and disabling this
# built in error detection would cause the script to abuse the TZO servers, resulting in suspension of your account. 
if [ $DAEMON -eq 1 ] && [ ! -f "$KILLFILE" ]; then
	KEEPRUNNING=1
else
	KEEPRUNNING=0
fi


while [ $KEEPRUNNING -eq 1 ] && [ ! -f "$KILLFILE" ]
do
# END SCARY 'KEEPRUNNING' WARNING :-)
# the 'do' continues to end of script...

# IF $returncode exists, this is the second (or greater) pass through the loop... meaning we are in daemon
# mode and at least 1 pass. Therefore this is a good place to put the mandatory 10 minute waite between
# each 'run' of tzoupdate. The mandatory 10 minute wait prevents runaway execution or client abuse.
if [ "xr$RETURNCODE" != "xr" ]; then
#        echo " sleeping 600"
#	date
        sleep 600
	# DEBUG
#	ls -l /tmp/tzo*
else 
#	echo "NOT sleeping 600.."
	sleep 1
#	date
#	ls -l /tmp/tzo
fi

# TIP: For cron installs, usually the OS 'cron' will email root if a cron'd job outputs any text.
# QUIETMODE affetcs this script not tzoupdate itself. What we do here is run tzoupdate -v ("verbose") and capture output
# instead of printing it. If there's NO error in the update, the wrapper is quiet - otherwise print to STDOUT.
# The captured output from -v is ALWAYS saved to $TZOLOG however.
QUIETMODE=1;					# QUIETMODE=1 suppresses all output EXCEPT major errors (0 for full output)

# IMPORTANT VARS - SHOULD NOT BE CHANGED
RETURNCODE=""                       # Exit code ($?) of tzoupdate
OUTPUT=""                       # This gets set later. Cotains Verbose output of tzoupdate
TZOARGS=""                      # This gets set later

#set -x		# debug, set -x will trace execution of shell code
detect_args			# error checking
detect_killfile		# abuse-avoidance logic (terminates in event of prior error)
detect_log_filename # set $IPFILE
#detect_ipfile_age   # set $IPFILE_AGE. Detects if we've run >1x within 60 secs.
detect_os           # set $OSSTRING
invoke_tzoupdate	# set $OUTPUT, $RETURNCODE. 

# post-processing - RETURNCODE indicates state of the update
# create and set $MESSAGE
#
if [ "r$RETURNCODE" = "r0" ]; then
	# GOOD
	MESSAGE="Success: tzoupdate reports no errors."
    if [ $QUIETMODE -ne 1 ]; then
		echo "${MESSAGE}"
	fi
elif [ "r$RETURNCODE" = "r1" ]; then
	# WARNING
	MESSAGE="Error: Update Abuse (another update attempt from this IP in last 60 seconds). Retry/recovery is possible." 
	if [ $QUIETMODE -ne 1 ]; then
        echo "${MESSAGE}"
    fi
	sleep 60;
elif [ $RETURNCODE -eq 2 ]; then
	# FATAL ERROR (EXPIRED TZO!)
	# We don't suppress this error even if QUIETMODE
	MESSAGE="Error $RETURNCODE: TZO indicates Account EXPIRED. Please see $TZOLOG for details."
	echo "${MESSAGE}"
	create_killfile
elif [ $RETURNCODE -eq 3 ]; then
	# FATAL ERROR (CHECK ACCOUNT CONFIG)
	# We don't suppress this error even if QUIETMODE
	MESSAGE="Error $RETURNCODE: Fatal error with your TZO Account. Please see $TZOLOG for details."
	# NOTE: remove the killfile AFTER you have resolved the account
	echo "${MESSAGE}"
	create_killfile
elif [ $RETURNCODE -eq 4 ]; then
	# WARNING (typo in script or installation, usage problem?)
	# We don't suppress this error even if QUIETMODE
    MESSAGE="Error $RETURNCODE: tzoupdate Usage Error. Please see --help option"
	echo "${MESSAGE}"
fi

# LOG OUR RESULTS 
# Philosophy: only keep most recent log so we don't require logrotate 
echo "* TZO client helper/wrapper script execution results." > ${TZOLOG}
DATE=`date`
HOST=`hostname`
echo "* Local system's time is: ${DATE}, and local hostname is: ${HOST}." >> ${TZOLOG}
echo "* 'tzoupdate' return code: ${RETURNCODE}. Actual output follows:" >> ${TZOLOG}
echo "${OUTPUT}">> ${TZOLOG}
    
# done from while... daemon
done


