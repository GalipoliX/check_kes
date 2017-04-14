#!/bin/bash
#################################################################################
# Script:       check_kes
# Author:       Michael Geschwinder (Maerkischer-Kreis) 
# Description:  Plugin for Nagios to check Kaspersky Endpoint Security Server
#                                
# History:                                                          
# 20170323      Created plugin (types: lastagentconnect, lastfullscan, lastupdate, licensinfo, viruscount)
# 20170324	Fixed Update Check, Added Jobstatus, Added parameter taskid
# 20170410	Added Cached Hostfile, Modified Viruscount Check
#
#################################################################################################################
# Usage:        ./check_kes.sh -H host -S DBServer -t type [-w warning] [-c critical] [-D debug] [-i JobID]
##################################################################################################################

help="check_kes (c) 2017 Michael Geschwinder published under GPL license
\nUsage: ./check_kes.sh -H host -S DBServer -t type [-i jobid] [-w warning] [-c critical] [-D debug]
\nRequirements: sqlcmd, awk, sed, grep\n
\nOptions: \t-H hostname of the Host you want to check\n\t\t-S DBServer where the  status of the host should be found (most common your KES Server)\n\t\t-D enable Debug \n\t\t-t Type to check, see list below\n\t\t-i comma seperated list of job ids (Check your database!)
\t\t-w Warning Threshold (optional)\n\t\t-c Critical Threshold (optional)\n
\nTypes:\t\tlastagentconnect -> Checks when the adminagent was last connected\n 
\t\tlastfullscan -> Checks when the last fullscan ran\n
\t\tlastupdate -> Checks when the virus definitions have been updated\n
\t\tlicensinfo -> Checks if the license is near of expiring\n
\t\tviruscount -> Checks how many viruses are detected"

##########################################################
# Nagios exit codes and PATH
##########################################################
STATE_OK=0              # define the exit code if status is OK
STATE_WARNING=1         # define the exit code if status is Warning
STATE_CRITICAL=2        # define the exit code if status is Critical
STATE_UNKNOWN=3         # define the exit code if status is Unknown
PATH=$PATH:/usr/local/bin:/usr/bin:/bin # Set path


##########################################################
# Enable Debug permanently (NOT FOR PRODUCTION!)
##########################################################
DEBUG=0

##########################################################
# Debug output function
##########################################################
function debug_out {
	if [ $DEBUG -eq "1" ]
	then
		datestring=$(date +%d%m%Y-%H:%M:%S) 
		echo -e $datestring DEBUG: $1
	fi
}

###########################################################
# Check if programm exist $1
###########################################################
function check_prog {
	if ! `which $1 1>/dev/null`
	then
		echo "UNKNOWN: $1 does not exist, please check if command exists and PATH is correct"
		exit ${STATE_UNKNOWN}
	else
		debug_out "OK: $1 does exist"
	fi
}

############################################################
# Check Script parameters and set dummy values if required
############################################################
function check_param {
	if [ ! $host ]
	then
		echo "No Host specified... exiting..."
		exit $STATE_UNKNOWN
	fi
	if [ ! $type ]
	then
		echo "No Type specified... exiting..."
		exit $STATE_UNKNOWN
	fi
	if [ ! $dbserver ]
	then
		echo "No DBServer specified... exiting..."
		exit $STATE_UNKNOWN
	fi

	if [ ! $warning ]
	then
		debug_out "Setting dummy warn value "
		warning=999
	fi
	if [ ! $critical ]
	then
		debug_out "Setting dummy critical value "
		critical=999
	fi
	if [ ! $taskid ]
	then
		debug_out "Setting dummy taskid "
		taskid=999
	fi
}


############################################################
# Get time difference
############################################################
function gettimespan {
	if [ $now ] && [ $last ]
	then
		span=$(echo $now-$last | bc)
		debug_out "timespan is $span seconds"
		hours=$((span /3600))
		minutes=$((span % 3600 /60))
		debug_out "hours: $hours minutes:$minutes"
	else
		cleanup
		debug_out "Timespan not defined"
		exit $STATE_UNKNOWN
	fi

}



############################################################
# Get a list of Hosts from KES DBServer
############################################################
function gethosts {
	if [ -f $hostfileraw ]; then rm $hostfileraw;fi


        if [ -f $lockfile ]
        then
                debug_out "Hostfile is locked .... waiting $timeout seconds"
                sleep $timeout
                if [ -f $lockfile ]
                then
                        echo "Data is locked!"
                        exit $STATE_UNKNOWN
                fi
        fi

	if [ -f $hostfile ]
        then
                fileage=$(( `date +%s` - `stat -L --format %Y $hostfile` ))
        else
                fileage=999999999999
        fi

	debug_out "File is $fileage seconds old"
        if [ $fileage -gt $cachetime ]
        then
                debug_out "hostfile ($hostfile) is older than defined cachetime ($cachetime)"
                debug_out "Loading NEW"
                debug_out "Locking Host file!"
                touch $lockfile
		rm $hostfile
		sqlcmd -S $dbserver -U $dbuser -P $dbpass -Q "select * from [KAV].[dbo].[Hosts]" -o $hostfileraw -h-1 -s"," -w 65535
		if [ ! $? == 0 ]
		then
			cleanup
			echo "No Data Received from KES Database (Hostlist)"
		        exit $STATE_UNKNOWN
		fi

		debug_out "Reding Hosts"
		hostlines=$(cat $hostfileraw | grep "rows affected" | cut -d " " -f 1 | cut -d "(" -f2)
		debug_out "Got $hostlines lines from SQL DB (Hostlist)"
		if [ $hostlines -lt 1 ]
		then
			cleanup
			echo "No Data Received from UDP Database (Hostlist)"
			exit $STATE_UNKNOWN
		fi
		debug_out "Sorting data ...."
		IFSold=$IFS
		IFS=$'\n'
		cat $hostfileraw >> $hostfile
		IFS=$IFSold
		debug_out "done!"
        	rm $hostfileraw
		debug_out "Unlocking Hostfile"
                rm $lockfile

	else
		debug_out "Using Cached file!"
	fi

}



############################################################
# Get license info from KES DBServer
############################################################
function getlicinfo {
	debug_out "Getting License information from server ..."
	if [ -f $licfile ]; then rm $licfile;fi
	if [ -f $licfileraw ]; then rm $licfileraw;fi


sqlcmd -S $dbserver -U $dbuser -P $dbpass -Q "select * from [KAV].[dbo].[apphostskeys]" -o $licfileraw -h-1 -s"," -w 65535
if [ ! $? == 0 ]
then
	cleanup
	echo "No Data Received from KES Database (License Info)"
        exit $STATE_UNKNOWN
fi

		debug_out "Reding License info"
		liclines=$(cat $licfileraw | grep "rows affected" | cut -d " " -f 1 | cut -d "(" -f2)
		if [ $liclines -lt 1 ]
		then
			cleanup
			echo "No Data Received from KES Database (Hostlist)"
			exit $STATE_UNKNOWN
		fi
		debug_out "Sorting data ...."
		IFSold=$IFS
		IFS=$'\n'
		cat $licfileraw >> $licfile

		IFS=$IFSold
		debug_out "done!"
	 #       rm $licfileraw
}


function getjobinfo {
	debug_out "Getting job information from server ..."

sqlcmd -S $dbserver -U $dbuser -P $dbpass -Q "select * from [KAV].[dbo].[tsk_host_state] where [nhostid] like $1 and task_id in ($2)" -o $jobfile -h-1 -s","
if [ ! $? == 0 ]
then
	cleanup
	echo "No Data Received from KES Database (Job Info)"
        exit $STATE_UNKNOWN
fi
		debug_out "Reding Job info"
		joblines=$(cat $jobfile | grep "rows affected" | cut -d " " -f 1 | cut -d "(" -f2)
		if [ $joblines -lt 1 ]
		then
			cleanup
			echo "No Data Received from KES Database (jobinfo)"
			exit $STATE_UNKNOWN
		fi
		#debug_out "Sorting data ...."
		#IFSold=$IFS
		#IFS=$'\n'
		#cat $licfileraw >> $licfile

		#IFS=$IFSold
		#debug_out "done!"
	 #       rm $licfileraw


}

############################################################
# Cleanup function  for temporary files 
############################################################
function cleanup {
	#if [ $DEBUG -eq "0" ]
	#then
		debug_out "Cleaning up files"
		#debug_out "deleteing hostfile $hostfile"
	        #if [ -f $hostfile ]; then rm $hostfile;fi
	        if [ -f $hostfileraw ]; then rm $hostfileraw;fi
	        if [ -f $licfileraw ]; then rm $licfileraw;fi
	        if [ -f $licfile ]; then rm $licfile;fi
	        if [ -f $jobfile ]; then rm $jobfile;fi
	#fi
}

#################################################################################
# Display Help screen
#################################################################################
if [ "${1}" = "--help" -o "${#}" = "0" ];
       then
       echo -e "${help}";
       exit $STATE_UNKNOWN;
fi

################################################################################
# check if requiered programs are installed
################################################################################
for cmd in sqlcmd date cat sed grep ;do check_prog ${cmd};done;

################################################################################
# Get user-given variables
################################################################################
while getopts "H:S:t:w:c:i:D" Input;
do
       case ${Input} in
       H)      host=${OPTARG};;
       S)      dbserver=${OPTARG};;
       t)      type=${OPTARG};;
       w)      warning=${OPTARG};;
       c)      critical=${OPTARG};;
       i)      taskid=${OPTARG};;
       D)      DEBUG=1;;
       *)      echo "Wrong option given. Use --help"
               exit $STATE_UNKNOWN
               ;;
       esac
done

debug_out "Host=$host, DBServer=$dbserver, Warning=$warning, Critical=$critical, taskid=$taskid"

check_param



################################################################################
# Variables
################################################################################
rand=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10 | head -n 1)
dbuser="nagios"
dbpass="+#nagios"
dbport="0000"
basedir=/tmp/kes_check
hostfileraw="$basedir/$dbserver-kes-hosts-raw-$rand.csv"
hostfile="$basedir/$dbserver-kes-hosts.csv"
lockfile="$basedir/$dbserver-kes-hosts.lock"
licfileraw="$basedir/$host-licstate-raw-$rand.csv"
licfile="$basedir/$host-licstate-$rand.csv"
jobfile="$basedir/$host-jobstate-$rand.csv"
now=$(date +%s)
timezone="+2"
cutdomain=".mk.de"
cachetime=30
timeout=5
#################################################################################

if [ ! -d $basedir ]; then mkdir $basedir; fi;

debug_out "Getting Host Data and writing to $hostfile"
gethosts
host=$(echo $host | sed s/$cutdomain// | sed s/\ //)


debug_out "Looking up hostid for host $host"
hostdata=$(grep -iE ",$host[[:blank:]]" $hostfile | cut -d ";" -f 1)

if [  "$hostdata" == "" ]
then
	cleanup
	echo "Host not found in DB!"
	exit $STATE_UNKNOWN
fi
debug_out "Got hostdata $hostdata for $host"


#################################################################################
# Switch Case for different check types
#################################################################################
case ${type} in


lastagentconnect)
        lastagentconnect=$(echo $hostdata | cut -d "," -f22 | sed -e 's/^[[:space:]]*//')
        if [ "$lastagentconnect" == "NULL" ]
        then
                echo "CRITICAL: Agent was never connected!"
                exit $STATE_CRITICAL
        fi
        debug_out "Last Agent connect: $lastagentconnect"
        t_lastagentconnect=$(date --date="$lastagentconnect" +"%s")
        debug_out "Last Agent connect (timestamp): $t_lastagentconnect"
	real_t_lastagentconnect=$(echo $t_lastagentconnect$timezone*60*60 | bc -l)
        debug_out "Last agent connect (real timestamp): $real_t_lastagentconnect"
	real_lastagentconnect=$(date -d @$real_t_lastagentconnect "+%x %R")
	debug_out "Last agent connect real finished $real_lastagentconnect"

        last=$real_t_lastagentconnect
        set -e
        gettimespan
        set +e
	mtime=$(echo "$hours * 60  + $minutes" | bc -l)
	perf="| lastagentconnect=${mtime}m;$warning;$critical"
	cleanup
        if [ $mtime -ge $critical ]
        then
                echo "CRITICAL: Last agent Connect was $mtime minutes ago which exceedes $critical hours! ($real_lastagentconnect) $perf"
                exit $STATE_CRITICAL
        elif [ $mtime -ge $warning ]
        then
                echo "WARNING: Last agent Connect was $mtime minutes ago which exceedes $warning hours! ($real_lastagentconnect) $perf"
                exit $STATE_WARNING
        else
                echo "OK: Last agent Connect was $mtime minutes ago ($real_lastagentconnect) $perf"
                exit $STATE_OK
        fi

;;

lastfullscan)
        lastfullscan=$(echo $hostdata | cut -d "," -f24 | sed -e 's/^[[:space:]]*//')
        if [ "$lastfullscan" == "NULL" ]
        then
                echo "CRITICAL: No fullscan recorded!"
                exit $STATE_CRITICAL
        fi
        debug_out "Last Fullscan: $lastfullscan"
        t_lastfullscan=$(date --date="$lastfullscan" +"%s")
        debug_out "Last Fullscan (timestamp): $t_lastfullscan"
	real_t_lastfullscan=$(echo $t_lastfullscan$timezone*60*60 | bc -l)
        debug_out "Last Fullscan (real timestamp): $real_t_lastfullscan"
	real_lastfullscan=$(date -d @$real_t_lastfullscan "+%x %R")
	debug_out "Last fullscan real finished $real_lastfullcan"

        last=$real_t_lastfullscan
        set -e
        gettimespan
        set +e
	perf="| lastfullscan=${hours}h;$warning;$critical"
	cleanup
        if [ $hours -ge $critical ]
        then
                echo "CRITICAL: Last fullscan was $hours hours and $minutes minutes ago which exceedes $critical hours!($real_lastfullscan) $perf"
                exit $STATE_CRITICAL
        elif [ $hours -ge $warning ]
        then
                echo "WARNING: Last fullscan was $hours hours and $minutes minutes ago which exceedes $warning hours! ($real_lastfullscan) $perf"
                exit $STATE_WARNING
        else
                echo "OK: Last fullscan was $hours hours and $minutes minutes ago ($real_lastfullscan) $perf"
                exit $STATE_OK
        fi

;;
 
lastupdate)
        hostid=$(echo $hostdata | cut -d "," -f1)
	debug_out "hostid is $hostid"
	getjobinfo $hostid $taskid 
	line=$(head -n 1 $jobfile)
      	debug_out "Using jobline $line" 
	state=$(head -n 1 $jobfile | cut -d "," -f6 | tr -d '[:space:]')
	finish=$(head -n 1 $jobfile | cut -d "," -f9)
	perc=$(head -n 1 $jobfile | cut -d "," -f10 | tr -d '[:space:]')

	case ${state} in
	1)
		echo "changed"
		cleanup
		exit $STATE_UNKNOWN
	;;
	2)
		debug_out "is running"
		echo "OK: Update is currently running ($perc%)"
		cleanup
                exit $STATE_CRITICAL

	;;
	4)
		debug_out "finished"
	;;
	8)
		debug_out "finished with warning"
		echo "WARNING: Last update finished with warning ($finish)"
		cleanup
                exit $STATE_WARNING
	;;
	16)
		debug_out "finished with error"
		echo "CRITICAL: Last update finished with errors ($finish)"
		cleanup
                exit $STATE_CRITICAL

	;;
	32)
		debug_out "waiting for start"
		echo "WARNING: Update is waiting for start"
		cleanup
                exit $STATE_WARNING
	;;
	64)
		debug_out "paused"
		echo "WARNING: Update job is paused"
		cleanup
                exit $STATE_WARNING
	;;
	*)
		echo UNKNOWN
		cleanup
		exit $STATE_UNKNOWN
	esac


        if [ "$finish" == "NULL" ]
        then
                echo "CRITICAL: System was never updated!"
                exit $STATE_CRITICAL
        fi
        debug_out "Last Update  Job  finished: $finish"
        t_lastupdate=$(date --date="$finish" +"%s")
        debug_out "Last Update (timestamp): $t_lastupdate"
        real_t_lastupdate=$(echo $t_lastupdate$timezone*60*60 | bc -l)
        debug_out "Last Update (real timestamp): $real_t_lastupdate"
	real_finish=$(date -d @$real_t_lastupdate "+%x %R")
	debug_out "Last Update real finished $real_finish"

        last=$real_t_lastupdate
        set -e
        gettimespan
        set +e
	perf="| lastupdate=${hours}h;$warning;$critical"
	cleanup
        if [ $hours -ge $critical ]
        then
                echo "CRITICAL: Last update was $hours hours and $minutes minutes ago which exceedes $critical hours! ($real_finish) $perf" 
                exit $STATE_CRITICAL
        elif [ $hours -ge $warning ]
        then
                echo "WARNING: Last update was $hours hours and $minutes minutes ago which exceedes $warning hours! ($real_finish) $perf"
                exit $STATE_WARNING
        else
                echo "OK: Last update finished successfully $hours hours and $minutes minutes ago ($real_finish) $perf"
                exit $STATE_OK
        fi

;;
licenseinfo)
	getlicinfo
        hostid=$(echo $hostdata | cut -d "," -f1)
	debug_out "hostid is $hostid"
	licline=$(cat $licfile | grep $hostid)

	expdate=$(echo $licline | cut -d "," -f8)
	debug_out "License expires at $expdate"
        t_expdate=$(date --date="$expdate" +"%s")
	debug_out "License expires at (timestamp) $t_expdate"
	last=$t_expdate
	gettimespan
	days=$(echo "scale=0; ($hours / 24) * -1" | bc -l)
	debug_out "Expiring in $days days"
	perf="| licenseexpires=${days}d;$warning;$critical"
	cleanup

        if [ $days -le $critical ]
        then
                echo "CRITICAL: License will expire in $days days! ($expdate) $perf"
                exit $STATE_CRITICAL
        elif [ $days -le $warning ]
        then
                echo "WARNING: License will expire in $days days! ($expdate) $perf"
              exit $STATE_WARNING
        else
                echo "OK: License will expire in $days days! ($expdate) $perf"
               exit $STATE_OK
        fi
;;

viruscount)
        vircnt=$(echo $hostdata | cut -d "," -f25 | sed -e 's/^[[:space:]]*//')
        vircntbase=$(echo $hostdata | cut -d "," -f26 | sed -e 's/^[[:space:]]*//')

	vircnt=$(echo $vircnt - $vircntbase | bc -l)

	perf="|viruses=$vircnt"
	cleanup

        if [ $vircnt -ge $critical ]
        then
                echo -e "CRITICAL: System has $vircnt Viruses!!!!! Please check this immediately!!!!! If you think this is an error please reset matching counter in Kaspersky Admin Console or check quarantine!$perf"
                exit $STATE_CRITICAL
        elif [ $vircnt -ge $warning ]
        then
                echo -e "WARNING: System has $vircnt Viruses!!!!! Please check this immediately!!!!! If you think this is an error please reset matching counter in Kaspersky Admin Console or check quarantine!$perf"
              exit $STATE_WARNING
        else
                echo "OK: System is clean.$perf"
               exit $STATE_OK
        fi
;;


*)
	cleanup
        echo -e "${help}";
        exit $STATE_UNKNOWN;

esac




