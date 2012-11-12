#!/usr/local/bin/bash
# Copyright (C) 2012 Edson Brandi <ebrandi@FreeBSD.org>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
###############################################################
#    Change following variables to match your environment     #
###############################################################

Hostname=example
Domain=fug.com.br
ttl=15
ZoneID=
AccesskeyID=
SecretAPIKey=
fail_host=www.fug.com.br.
script_path=/usr/local/route53-failover
logfile=$script_path/$(basename $0 .sh).log.$(date +"%Y-%m")
lockfile=$script_path/$(basename $0 .sh).lock
test_file=status
test_string="Error 200 OK"

###############################################################
#    You should not need to change anything bellow this point #
###############################################################

# Enable some bash traps in order to avoid problems
set -o nounset   # avoid breaking everything in case of an uninitialised variable
set -o pipefail  # always set exit code to 1 when a piped subcommand fails

# Logging function
log() {
	echo "[$(date +"%D %T")] $2" | tee -a $logfile
	if [[ $1 == "error" ]]; then
		exit 1
	fi
}

# Make sure some tools are installed correctly
for i in dig lynx wget awk base64 diff openssl lockfile xmllint; do
	which $i >/dev/null || log error "Error: Please install $i before proceeding"
done

# Test if this script has write permission on $script_path
if [ ! -w $script_path ]; then
	log error "Error: I don't have write permission on $script_path, please fix and try again"
fi

# Create lockfile and avoid more than one script execution ('lockfile(1)' is used to avoid race conditions)
if ! lockfile -r 0 $lockfile; then
	log error "Error: script already running, exiting..."
fi

# Remove lockfile if some other error causes the script to exit
trap 'rm -f "$lockfile"; exit $?' INT TERM EXIT

# Set variables with DNS Record Values to create DELETE API request
AuthServer=$(dig NS $Domain | awk "/^$Domain/ { print \$5 }" | head -1) || log error "Error retrieving domain info, check dns resolution"

if [ "$(echo $AuthServer | grep awsdns)" == "" ]; then
	echo "Error: Your domain is not hosted on Route 53, exiting..."
	exit 1
fi

OldType=$(dig @$AuthServer A $Hostname.$Domain | awk "/^$Hostname.$Domain/ { print \$4 }" | head -1) || log error "Error while running dig"
OldTTL=$(dig @$AuthServer A $Hostname.$Domain | awk "/^$Hostname.$Domain/ { print \$2 }" | head -1) || log error "Error while running dig"
OldRecord=$(dig @$AuthServer A $Hostname.$Domain | awk "/^$Hostname.$Domain/ { print \$5 }" | sed s/\ //g) || log error "Error while running dig"

# Create temporary files needed by this script

touch $script_path/ips.tmp.old || log error "Error manipulating temporary files"
touch $script_path/ips.tmp || log error "Error manipulating temporary files"
mv -f $script_path/ips.tmp $script_path/ips.tmp.old || log error "Error manipulating temporary files"
touch $script_path/ips.tmp || log error "Error manipulating temporary files"

# Connect to webserver and search for a specific string to
# check if webserver are up and running for each address 
# listed in ips.master file. Than print multiple lines
# for each IP address based in fixed weight seted in ips.master

for i in $(cat $script_path/ips.master | grep -v "#")
do
  ip=$(echo $i | awk -F":" '{print $2}')
  condition=$(lynx -connect_timeout=1 -dump http://$ip/$test_file 2>&1 | grep "$test_string" | wc -l | cut -d ' ' -f 8)
  if [ "$condition" -eq "1" ]
  then
     peso=$(echo $i | awk -F":" '{print $1}')
     counter=1
     while [ $counter -le $peso ]
       do
         echo $ip >> $script_path/ips.tmp
         counter=$(( $counter + 1 ))
       done
  fi
done

# Check if file ips.tmp are empty (empty file = no webserver available)

if [ -s "$script_path/ips.tmp" ]
then

  # If file ips.tmp has any content, compare it with previous version of this file.
  # If both files has same content, script will quit
  # If not ot procede with route 53 update using IPs from ips.tmp file

  if $(diff $script_path/ips.tmp.old $script_path/ips.tmp >/dev/null)
    then
      echo
      log info "Update is not necessary, nothing changed since last execution"
      echo
    else
      echo
      # Show which hosts have been added or removed
      # TODO: Send this information by email
      addHosts[0]="$(diff -u $script_path/ips.tmp.old $script_path/ips.tmp | sort -u | awk "/^\+[0-9]+/ {printf \$0 \" \";}" | sed -e s/\+//g -e s/\ $//)"
      j=1
      for i in ${addHosts[0]}; do
            # use fake multidimensional array in bash v3
            # ip address for each added host
            addHosts[j*1000+1]=$i
            # previous weight for this host
            addHosts[j*1000+2]="$(grep $i $script_path/ips.tmp.old | wc -l | sed -e 's/\ //g')"
            # new weight for this host
            addHosts[j*1000+3]="$(grep $i $script_path/ips.master | grep -v '^#' | awk -F":" '{print $1}')"
            # check if previous and new weight are equal
            if [[ ${addHosts[j*1000+2]} -ne ${addHosts[j*1000+3]} ]] && [[ ${addHosts[j*1000+2]} -ne 0 ]] ; then
                  # weight changed? 1=yes / 0=no
                  addHosts[j*1000+4]=1
            else
                  addHosts[j*1000+4]=0
            fi
            j=$(($j+1))
      done

      showAddedHosts=""
      increasedHostWeight=""
      increasedHostWeightCount=0
      if [ -n "${addHosts[0]}" ]; then
            # which hosts had its weight increased? grab this info and notify the user
            for i in $(seq 1 $(($j-1))); do
                  if [ ${addHosts[i*1000+4]} -eq 0 ]; then
                        showAddedHosts=$showAddedHosts", "${addHosts[i*1000+1]}
                  else
                        increasedHostWeight=$increasedHostWeight"| "${addHosts[i*1000+1]}"|"${addHosts[i*1000+2]}"|"${addHosts[i*1000+3]}
                        increasedHostWeightCount=$(($increasedHostWeightCount+1))
                  fi
            i=$(($i+1))
            done
      showAddedHosts="$(echo $showAddedHosts | sed -e s/^\,\ //)"
      increasedHostWeight="$(echo $increasedHostWeight | sed -e 's/^\| //')"
      fi

      if [ -n "$showAddedHosts" ]; then
            log info "Hosts ADDED: $showAddedHosts"
      else
            log info "Hosts ADDED: none"
      fi

      removeHosts[0]="$(diff -u $script_path/ips.tmp.old $script_path/ips.tmp | sort -u | awk "/^\-[0-9]+/ {printf \$0 \" \";}" | sed -e s/\-//g -e s/\ $//)"
      j=1
      for i in ${removeHosts[0]}; do
            # use fake multidimensional array in bash v3
            # ip address for each removed host
            removeHosts[j*1000+1]=$i
            # previous weight for this host
            removeHosts[j*1000+2]="$(grep $i $script_path/ips.tmp.old | wc -l | sed -e 's/\ //g')"
            # new weight for this host
            removeHosts[j*1000+3]="$(grep $i $script_path/ips.master | grep -v '^\#' | awk -F":" '{print $1}')"
            if [ "${removeHosts[j*1000+3]}" == "" ]; then
                  # host was removed, new weight is 0
	          removeHosts[j*1000+3]=0
            fi
            # check if previous and new weight are equal
            if [[ ${removeHosts[j*1000+2]} -ne ${removeHosts[j*1000+3]} ]] && [[ ${removeHosts[j*1000+2]} -ne 0 ]] && [[ ${removeHosts[j*1000+3]} -ne 0 ]] ; then
                  # weight changed? 1=yes / 0=no
                  removeHosts[j*1000+4]=1
            else
                  removeHosts[j*1000+4]=0
            fi
            j=$(($j+1))
      done

      showRemovedHosts=""
      decreasedHostWeight=""
      decreasedHostWeightCount=0
      if [ -n "${removeHosts[0]}" ]; then
            # which hosts had its weight decreased? grab this info and notify the user
            for i in $(seq 1 $(($j-1))); do
                  if [ ${removeHosts[i*1000+4]} -eq 0 ]; then
                        showRemovedHosts=$showRemovedHosts", "${removeHosts[i*1000+1]}
                  else
                        decreasedHostWeight=$decreasedHostWeight"| "${removeHosts[i*1000+1]}"|"${removeHosts[i*1000+2]}"|"${removeHosts[i*1000+3]}
                        decreasedHostWeightCount=$(($decreasedHostWeightCount+1))
                  fi
            i=$(($i+1))
            done
      showRemovedHosts="$(echo $showRemovedHosts | sed -e s/^\,\ //)"
      decreasedHostWeight="$(echo $decreasedHostWeight | sed -e 's/^\| //')"
      fi

      if [ -n "$showRemovedHosts" ]; then
            log info "Hosts REMOVED: $showRemovedHosts"
      else
            log info "Hosts REMOVED: none"
      fi

      if [ -n "$increasedHostWeight" ]; then
            increasedHostWeightMsg=""
            for j in $(seq 1 $increasedHostWeightCount); do
                  increasedHostWeightMsg="$(echo "$increasedHostWeight" | awk "{ print \$${j} }" | awk -F"|" "{ print \"Weight INCREASE: \" \$1 \" (previous:\" \$2  \" new:\" \$3 \")\"}" )"
                  log info "$increasedHostWeightMsg"
            done
      fi

      if [ -n "$decreasedHostWeight" ]; then
            decreasedHostWeightMsg=""
            for j in $(seq 1 $decreasedHostWeightCount); do
                  decreasedHostWeightMsg="$(echo "$decreasedHostWeight" | awk "{ print \$${j} }" | awk -F"|" "{ print \"Weight DECREASE: \" \$1 \" (previous:\" \$2  \" new:\" \$3 \")\"}" )"
                  log info "$decreasedHostWeightMsg"
            done
      fi

      log info "Starting update process..."
      echo

      # Generate ResourceRecord for IPs listed in ips.tmp file

      NewRecord=$(cat $script_path/ips.tmp | awk '{print "<ResourceRecord><Value>"$1"</Value></ResourceRecord>"}')

      # Create Route 53 Changeset data set
      Changeset=""
      Changeset=$Changeset"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      Changeset=$Changeset"<ChangeResourceRecordSetsRequest xmlns=\"https://route53.amazonaws.com/doc/2010-10-01/\">"
      Changeset=$Changeset"<ChangeBatch><Comment>Update $Hostname.$Domain</Comment><Changes>"

      # Delete previous DNS records
      Changeset=$Changeset"<Change>"
      Changeset=$Changeset"<Action>DELETE</Action>"
      Changeset=$Changeset"<ResourceRecordSet>"
      Changeset=$Changeset"<Name>$Hostname.$Domain.</Name>"
      Changeset=$Changeset"<Type>$OldType</Type>"
      Changeset=$Changeset"<TTL>$OldTTL</TTL>"
      Changeset=$Changeset"<ResourceRecords>"
      for i in $OldRecord; do
            Changeset=$Changeset"<ResourceRecord><Value>$i</Value></ResourceRecord>"
      done
      Changeset=$Changeset"</ResourceRecords>"
      Changeset=$Changeset"</ResourceRecordSet>"
      Changeset=$Changeset"</Change>"

      # Create new DNS records
      Changeset=$Changeset"<Change>"
      Changeset=$Changeset"<Action>CREATE</Action>"
      Changeset=$Changeset"<ResourceRecordSet>"
      Changeset=$Changeset"<Name>$Hostname.$Domain.</Name>"
      Changeset=$Changeset"<Type>A</Type>"
      Changeset=$Changeset"<TTL>$ttl</TTL>"
      Changeset=$Changeset"<ResourceRecords>"
      Changeset=$Changeset"`echo $NewRecord | sed s/\ //g`"
      Changeset=$Changeset"</ResourceRecords>"
      Changeset=$Changeset"</ResourceRecordSet>"
      Changeset=$Changeset"</Change>"

      # Close Route 53 changeset data set
      Changeset=$Changeset"</Changes>"
      Changeset=$Changeset"</ChangeBatch>"
      Changeset=$Changeset"</ChangeResourceRecordSetsRequest>"

      # Submit Route 53 changeset data set 
 
      CurrentDate=$(wget --no-check-certificate -q -S https://route53.amazonaws.com/date -O /dev/null 2>&1 | grep Date | sed 's/.*Date: //') || log error "Error retrieving current date from AWS"
      Signature=$(echo -n $CurrentDate | openssl dgst -binary -sha1 -hmac $SecretAPIKey | base64) || log error "Error generating AWS signature"
      DateHeader="Date: "$CurrentDate
      AuthHeader="X-Amzn-Authorization: AWS3-HTTPS AWSAccessKeyId=$AccesskeyID,Algorithm=HmacSHA1,Signature=$Signature"
      Result=$(wget --no-check-certificate -nv --header="$DateHeader" --header="$AuthHeader" --header="Content-Type: text/xml; charset=UTF-8" --post-data="$Changeset" -O /dev/stdout -o /dev/stdout https://route53.amazonaws.com/2010-10-01/hostedzone/$ZoneID/rrset | grep -v WARNING | grep -v locally)
      log info "API Output:"
      log info "$Result"
      echo
      log info "Changeset submited:"
      Changeset=$(echo $Changeset | xmllint --format -)
      log info "$Changeset"
      echo
    fi
    else
 
    # File ips.tmp is empty, you dont have any webserver UP
    # script will change DNS to failover your website to your backup site 

    # First let's make sure the failover host is OK
    # This avoids a false positive if the probe machine has connectivity problems

    condition=$(lynx -connect_timeout=1 -dump http://$fail_host/$test_file 2>&1 | grep "$test_string" | wc -l | cut -d ' ' -f 8)
    if [ "$condition" -ne "1" ]; then
	log error "Error: failover host is also down, I don't know what else to do. Make sure my network connectivity is OK. Exiting..."
    fi

    # Failover host is OK, let's proceed with the update

    if $(diff $script_path/ips.tmp.old $script_path/ips.tmp >/dev/null)
    then
      echo
      log info "Update is not necessary, nothing changed since last execution"
      echo
    else
      echo
      log info "Activating FAILOVER host"
      log info "Starting update process..."
      echo

      # Create Route 53 Changeset data set
      Changeset=""
      Changeset=$Changeset"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      Changeset=$Changeset"<ChangeResourceRecordSetsRequest xmlns=\"https://route53.amazonaws.com/doc/2010-10-01/\">"
      Changeset=$Changeset"<ChangeBatch><Comment>Update $Hostname.$Domain</Comment><Changes>"

      # Delete previous DNS records
      Changeset=$Changeset"<Change>"
      Changeset=$Changeset"<Action>DELETE</Action>"
      Changeset=$Changeset"<ResourceRecordSet>"
      Changeset=$Changeset"<Name>$Hostname.$Domain.</Name>"
      Changeset=$Changeset"<Type>$OldType</Type>"
      Changeset=$Changeset"<TTL>$OldTTL</TTL>"
      Changeset=$Changeset"<ResourceRecords>"
      for i in $OldRecord; do
            Changeset=$Changeset"<ResourceRecord><Value>$i</Value></ResourceRecord>"
      done
      Changeset=$Changeset"</ResourceRecords>"
      Changeset=$Changeset"</ResourceRecordSet>"
      Changeset=$Changeset"</Change>"

      # Create new DNS records
      Changeset=$Changeset"<Change>"
      Changeset=$Changeset"<Action>CREATE</Action>"
      Changeset=$Changeset"<ResourceRecordSet>"
      Changeset=$Changeset"<Name>$Hostname.$Domain.</Name>"
      Changeset=$Changeset"<Type>CNAME</Type>"
      Changeset=$Changeset"<TTL>$ttl</TTL>"
      Changeset=$Changeset"<ResourceRecords>"
      Changeset=$Changeset"<ResourceRecord>"
      Changeset=$Changeset"<Value>$fail_host</Value>"
      Changeset=$Changeset"</ResourceRecord>"
      Changeset=$Changeset"</ResourceRecords>"
      Changeset=$Changeset"</ResourceRecordSet>"
      Changeset=$Changeset"</Change>"

      # Close Route 53 changeset data set
      Changeset=$Changeset"</Changes>"
      Changeset=$Changeset"</ChangeBatch>"
      Changeset=$Changeset"</ChangeResourceRecordSetsRequest>"

      # Submit Route 53 changeset data set

      CurrentDate=$(wget --no-check-certificate -q -S https://route53.amazonaws.com/date -O /dev/null 2>&1 | grep Date | sed 's/.*Date: //') || log error "Error retrieving current date from AWS"
      Signature=$(echo -n $CurrentDate | openssl dgst -binary -sha1 -hmac $SecretAPIKey | base64) || log error "Error generating AWS signature"
      DateHeader="Date: "$CurrentDate
      AuthHeader="X-Amzn-Authorization: AWS3-HTTPS AWSAccessKeyId=$AccesskeyID,Algorithm=HmacSHA1,Signature=$Signature"
      Result=$(wget --no-check-certificate -nv --header="$DateHeader" --header="$AuthHeader" --header="Content-Type: text/xml; charset=UTF-8" --post-data="$Changeset" -O /dev/stdout -o /dev/stdout https://route53.amazonaws.com/2010-10-01/hostedzone/$ZoneID/rrset | grep -v WARNING | grep -v locally)
      log info "API Output:"
      log info "$Result"
      echo
      log info "Changeset submited:"
      Changeset=$(echo $Changeset | xmllint --format -)
      log info "$Changeset"
      echo
    fi
 fi      

# Remove lockfile
rm -f "$lockfile"

