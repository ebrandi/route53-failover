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
connect_timeout=2
retries=3
mailnotification=0 # [1]=on / [0]=off
mailfrom=noreply@yourdomain.com
mailto=noc@yourdomain.com,admin@anotherdomain.com
mailsmtp=smtp.yourdomain.com
multisiteprobe=0 # [1]=on / [0]=off
probeonly=0
remoteprobe[1]=isp1
remoteprobefile[1]=scp://route53@server1.yourdomain.com:/usr/local/route53-failover/probe/proberesult
remoteprobe[2]=isp2
remoteprobefile[2]=http://server2.yourdomain.com/probe/proberesult

###############################################################
#    You should not need to change anything bellow this point #
###############################################################

# Create lockfile and avoid more than one script execution ('lockfile(1)' is used to avoid race conditions)
if ! lockfile -r 0 $lockfile; then
	echo "Error: script already running, exiting..."
    exit 1
fi

# Remove lockfile if some other error causes the script to exit
trap "{ rm -f "$lockfile"; exit $?; }" HUP INT TERM EXIT

# Test if this script has write permission on $script_path
if [ -z $script_path ]; then
	echo "Error: Please set the \$script_path variable"
    exit 1
else
	if [ ! -w $script_path ]; then
		echo "Error: I don't have write permission on $script_path, please fix and try again"
        exit 1
	fi
fi

# Make sure some tools are installed correctly
for i in dig awk curl diff openssl lockfile xmllint; do
	which $i >/dev/null 2>&1 || { echo "Error: Please install $i before proceeding" && exit 1; }
done

if [[ $mailnotification -eq 1 ]] && [[ $probeonly -ne 1 ]]; then
    which nail >/dev/null 2>&1 || { echo "Error: Please install \"nail\" before proceeding (usually found in the \"mailx\" package)" && exit 1; }
fi

# Enable some bash traps in order to avoid problems
set -o nounset  # avoid breaking everything in case of an uninitialised variable
set -o pipefail # always set exit code to 1 when a piped subcommand fails

mkdir $script_path/log/ >/dev/null 2>&1 

# Our logging function requires GNU awk [`gawk(1)'].
# The code bellow tries to find a suitable binary on non-Linux platforms.
echo | awk '{ print systime() }' >/dev/null 2>&1
if [ $? -eq 0 ]; then
	gawk=$(which awk)
else
	echo | gawk '{ print systime() }' >/dev/null 2>&1
	if [ $? -eq 0 ]; then
		gawk=$(which gawk)
	else
		echo && echo "Error: Please install GNU awk (gawk)"
		echo && exit 1
	fi
fi

# Logging function
log() {
	echo "$2" | $gawk '{ print "[" strftime("%Y-%m-%d %H:%M:%S") "]" "\t" $0; }' | tee -a $logfile
	if [[ $1 == "error" ]]; then
        mailNotification
		echo && exit 1
	fi
}

# Initialize the mail notification variables
for i in $(seq 1 8); do
	mailNotificationStatus[i]=0
done

# Mail notification function

mailNotification() {

# During script execution we set special status codes (described bellow)
# depending on which problems were encountered.
# These status codes are later processed to decide which notifications should be sent.
#
# mailNotificationStatus[1] = DNS resolution problems
# mailNotificationStatus[2] = Failed to generate AWS signature or validate AWS credentials
# mailNotificationStatus[3] = Failed to submit AWS zoneset update
# mailNotificationStatus[4] = Host down
# mailNotificationStatus[5] = Host up
# mailNotificationStatus[6] = Failover activated (problems)
# mailNotificationStatus[7] = Failover disabled (back to normal)
# mailNotificationStatus[8] = All hosts down, failover also down
#
# For status 4 and 5 (hosts up/down) we also store the amount of affected hosts.
#
# For example:
#
# mailNotificationStatus[4]=2 means we have 2 hosts down.
# The IP address for the affected hosts will be stored on mailNotificationStatus[4*10+1] and mailNotificationStatus[4*10+2]
# The reason for each problem will be stored on mailNotificationStatus[4*100+1] and mailNotificationStatus[4*100+2]
# The string test for each host will be stored on mailNotificationStatus[4*1000+1] and mailNotificationStatus[4*1000+2]
#
# mailNotificationStatus[5]=3 means 3 hosts are back online (up)
# The IP address for each host back online will be stored on mailNotificationStatus[5*10+1] until mailNotificationStatus[5*10+3]
#

    if [[ $mailnotification -eq 1 ]] && [[ $probeonly -ne 1 ]]; then

        rm -f "$script_path/mail.out" >/dev/null 2>&1

        if [[ -z $mailto ]]; then
            echo "Error: Please provide a comma separated list of email recipients (\$mailto)"
            exit 1
        fi
        if [[ -z $mailsmtp ]]; then
            echo "Error: Please provide a valid SMTP server (\$mailsmtp)"
            exit 1
        fi

        serviceProblems=0
        serviceOK=0

        for i in 4 6; do
            if [[ ${mailNotificationStatus[i]} -ne 0 ]] && [[ $probeonly -ne 1 ]]; then
                serviceProblems=1
            fi
        done

        for i in 5 7; do
            if [[ ${mailNotificationStatus[i]} -ne 0 ]] && [[ $probeonly -ne 1 ]]; then
                serviceOK=1
            fi
        done

        if [[ $serviceProblems -eq 1 ]]; then

            mailsubject="[route53-failover] $Hostname.$Domain service trouble"

            echo "There has been a change in your monitored service at $Hostname.$Domain" > $script_path/mail.out
            echo "Current status: trouble" >> $script_path/mail.out
            echo >> $script_path/mail.out
            if [[ ${mailNotificationStatus[6]} -ne 0 ]]; then
                echo "All hosts are DOWN, switching to failover host" >> $script_path/mail.out
                echo "==> $fail_host" >> $script_path/mail.out
                echo >> $script_path/mail.out
            fi
            if [[ ${mailNotificationStatus[4]} -ne 0 ]]; then
                for i in $(seq 1 ${mailNotificationStatus[4]}); do
                    printf "%s reported down; " "${mailNotificationStatus[4*10+i]}" >> $script_path/mail.out
                    case "${mailNotificationStatus[4*100+i]}" in
                          000)	printf "connection error\n" >> $script_path/mail.out
                                ;;
                          200)	if [[ ${mailNotificationStatus[4*1000+i]} -eq 0 ]]; then
                                    printf "test string not found\n" >> $script_path/mail.out
                                else
                                    printf "connection error\n" >> $script_path/mail.out
                                fi
                                ;;
                          400)	printf "bad request (error 400)\n" >> $script_path/mail.out
                                ;;
                          403)	printf "access forbidden (error 403)\n" >> $script_path/mail.out
                                ;;
                          404)	printf "page not found (error 404)\n" >> $script_path/mail.out
                                ;;
                          503)	printf "internal server error (503)\n" >> $script_path/mail.out
                                ;;
                            *)  printf "connection error\n" >> $script_path/mail.out
                                ;;
                    esac
                done
                if [[ ${mailNotificationStatus[5]} -ne 0 ]]; then
                    for i in $(seq 1 ${mailNotificationStatus[5]}); do
                        printf "%s reported up" "${mailNotificationStatus[5*10+i]}" >> $script_path/mail.out
                    done
                fi
                echo >> $script_path/mail.out
                echo "*** Current production hosts (up):" >> $script_path/mail.out
                if [[ -n $NewRecordSorted ]]; then
                    for i in $NewRecordSorted; do
                        echo "$i" >> $script_path/mail.out
                    done
                else
                    echo "none" >> $script_path/mail.out
                fi
                echo >> $script_path/mail.out
                echo "*** Current impacted hosts (down):" >> $script_path/mail.out
                HostsDownList="$(echo $HostsDownList | sed -e 's;^,;;' | tr ',' '\n')"
                if [[ -n $HostsDownList ]]; then
                    echo "$HostsDownList" >> $script_path/mail.out
                else
                    echo "none" >> $script_path/mail.out
                fi
            fi
        fi

        if [[ $serviceOK -eq 1 ]] && [[ $serviceProblems -eq 0 ]]; then

            mailsubject="[route53-failover] $Hostname.$Domain service ok"

            echo "There has been a change in your monitored service at $Hostname.$Domain" > $script_path/mail.out
            echo "Current status: ok" >> $script_path/mail.out
            echo >> $script_path/mail.out
            if [[ ${mailNotificationStatus[7]} -ne 0 ]]; then
                echo "Disabling failover state, returning to normal operation" >> $script_path/mail.out
                echo >> $script_path/mail.out
            fi
            if [[ ${mailNotificationStatus[5]} -ne 0 ]]; then
                for i in $(seq 1 ${mailNotificationStatus[5]}); do
                    printf "%s reported up\n" "${mailNotificationStatus[5*10+i]}" >> $script_path/mail.out
                done
                echo >> $script_path/mail.out
                echo "*** Current production hosts (up):" >> $script_path/mail.out
                if [[ -n $NewRecordSorted ]]; then
                    for i in $NewRecordSorted; do
                        echo "$i" >> $script_path/mail.out
                    done
                else
                    echo "none" >> $script_path/mail.out
                fi
                echo >> $script_path/mail.out
                echo "*** Current impacted hosts (down):" >> $script_path/mail.out
                HostsDownList="$(echo $HostsDownList | sed -e 's;^,;;' | tr ',' '\n')"
                if [[ -n $HostsDownList ]]; then
                    echo "$HostsDownList" >> $script_path/mail.out
                else
                    echo "none" >> $script_path/mail.out
                fi
            fi
        fi

        if [[ -s $script_path/mail.out ]] && [[ -n $mailsubject ]]; then

            if [[ -n "$AWSResult" ]] && [[ -n "$AWSChangeset" ]]; then
                echo >> $script_path/mail.out
                echo "*** Route53 API Output:" >> $script_path/mail.out
                echo >> $script_path/mail.out
                echo "$AWSResult" >> $script_path/mail.out
                echo >> $script_path/mail.out
                echo "*** Changeset submited:" >> $script_path/mail.out
                echo >> $script_path/mail.out
                echo "$AWSChangeset" >> $script_path/mail.out
                echo >> $script_path/mail.out
            fi

            nail -r "Route53 Failover <${mailfrom}>" -s "$mailsubject" -S smtp="$mailsmtp" "$mailto" < $script_path/mail.out
            
            if [[ $? -eq 0 ]]; then
                log info "Mail sent to $mailto"
            else
                log info "Error while sending mail to $mailto"
            fi
            
            rm -f "$script_path/mail.out" >/dev/null 2>&1
        fi
    fi

}

# Enforce script permission to 700 for improved security (avoid leaking AWS credentials)
if [[ -z "$(find $script_path/$(basename $0) -perm 700)" ]]; then
	log error "Error: This script should NOT be accessible to other users since it contains sensitive information, please chmod it to 700"
fi

# The "ips.master" file cannot be empty
if [ ! -s $script_path/ips.master ]; then
	log error "Please create the \"ips.master\" file according to the documentation. Aborting..."
fi

# Set variables with DNS Record Values to create DELETE API request
AuthServer=$(dig NS $Domain | awk "/^$Domain/ { print \$5 }" | head -1) || { mailNotificationStatus[1]=1 && log error "Error retrieving domain info, check dns resolution"; }

# Test DNS resolution and check if our domain is actually hosted on Route53
if [ -z $AuthServer ]; then
	mailNotificationStatus[1]=1 && log error "Error retrieving domain info, check dns resolution"
else
	if [ "$(echo $AuthServer | grep awsdns)" == "" ]; then
		log error "Error: Your domain is not hosted on Route 53, exiting..."
	fi
fi

# Function: Generate AWS signature
awssignature() {
	  if [ -z $AWSZoneID ] || [ -z $AWSAccesskeyID ] || [ -z $AWSSecretAPIKey ]; then
		  log error "Error: Please provide a valid set of AWS credentials"
	  else
		  AWSCurrentDate="$(curl -sS -I --connect-timeout $connect_timeout --retry $retries --retry-delay 5 --stderr /dev/null https://route53.amazonaws.com/date | grep Date | sed 's/.*Date: //' | tr -d '\r')" || { mailNotificationStatus[2]=1 && log error "Error retrieving current date from AWS"; }
		  AWSSignature=$(printf "$AWSCurrentDate" | openssl dgst -binary -sha256 -hmac $AWSSecretAPIKey | openssl enc -base64) || { mailNotificationStatus[2]=1 && log error "Error generating AWS signature"; }
		  AWSDateHeader="Date: $AWSCurrentDate"
		  AWSAuthHeader="X-Amzn-Authorization: AWS3-HTTPS AWSAccessKeyId=$AWSAccesskeyID,Algorithm=HmacSHA256,Signature=$AWSSignature"
	  fi
}

# Function: Submit Route53 update
submitroute53() {
	awssignature # call our signature generation function	  
	AWSResult=$(curl -sS -w ";;%{http_code}" --connect-timeout $connect_timeout --retry $retries --retry-delay 5 -H "$AWSDateHeader" -H "$AWSAuthHeader" -H "Content-Type: text/xml; charset=UTF-8" -d "$AWSChangeset" https://route53.amazonaws.com/2012-02-29/hostedzone/$AWSZoneID/rrset)
	AWSResultHTTPCode=$(echo $AWSResult | awk -F ";;" "{ print \$2 }")

	case "$AWSResultHTTPCode" in
		000)	echo "error" > $script_path/awsresult || log error "Error manipulating temporary files"
			    mailNotificationStatus[3]=1
			    log error "Error: Connection timeout while submitting Route53 update to AWS, aborting..."
			    ;;
		200)	echo "ok" > $script_path/awsresult || log error "Error manipulating temporary files"
			    log info "Successfully updated \"$Hostname.$Domain\" on Route53"
			    echo
			    log info "*** Current production hosts:"
			    if [[ -n $NewRecordSorted ]]; then
				  for i in $NewRecordSorted; do
					  log info "$i"
				  done
			    else
				  log info "$fail_host [failover activated]"
			    fi
			    ;;
		400)	echo "error" > $script_path/awsresult || log error "Error manipulating temporary files"
			    mailNotificationStatus[3]=1
			    log error "Error: \"Bad request\" while updating \"$Hostname.$Domain\" on Route53, double-check AWS credentials. Aborting..."
			    ;;
		403)	echo "error" > $script_path/awsresult || log error "Error manipulating temporary files"
			    mailNotificationStatus[3]=1
			    log error "Error: \"Access forbidden\" while updating \"$Hostname.$Domain\" on Route53, double-check AWS credentials. Aborting..."
			    ;;
		*)		echo "error" > $script_path/awsresult || log error "Error manipulating temporary files"
			    mailNotificationStatus[3]=1
			    log error "Error: Unknown error while submitting Route53 update to AWS, aborting..."
			    ;;
	esac

	echo
	log info "*** API Output:"
	AWSResult=$(echo $AWSResult | awk -F ";;" "{ print \$1 }" | xmllint --format -)
	log info "$AWSResult"
	echo
	log info "*** Changeset submited:"
	AWSChangeset=$(echo $AWSChangeset | xmllint --format -)
	log info "$AWSChangeset"
	echo
}


# Validate AWS credentials (once per hour)
# This validation makes sure your AWS credentials are always working,
# even if we rarely update our zone records.

touch $script_path/awslastvalidation || log error "Error manipulating temporary files"

if [[ ! "$(date +"%H")" = "$(cat $script_path/awslastvalidation)" ]] && [[ $probeonly -ne 1 ]]; then

	  awssignature # call our signature generation function	  
	  AWSResult=$(curl -sS -w ";;%{http_code}" --connect-timeout $connect_timeout --retry $retries --retry-delay 5 -H "$AWSDateHeader" -H "$AWSAuthHeader" -H "Content-Type: text/xml; charset=UTF-8" https://route53.amazonaws.com/2012-02-29/hostedzone?marker=$AWSZoneID)
	  AWSResultHTTPCode=$(echo $AWSResult | awk -F ";;" "{ print \$2 }")

	  case "$AWSResultHTTPCode" in
		000)	mailNotificationStatus[2]=1
			log error "Error: Connection timeout while validating AWS credentials, aborting..."
			;;
		200)	if [[ -n "$(echo "$AWSResult" | awk -F ";;" "{ print \$1 }" | xmllint --format - | grep $AWSZoneID)" ]]; then
				log info "Validating AWS credentials... OK"
				echo "$(date +"%H")" > $script_path/awslastvalidation || log error "Error manipulating temporary files"
			else
				mailNotificationStatus[2]=1
				log error "Error: AWS credentials are OK, but you don't have access to the $AWSZoneID zoneset"
			fi
			;;
		400)	mailNotificationStatus[2]=1
			log error "Error: \"Bad request\" while validating AWS credentials. Aborting..."
			;;
		403)	mailNotificationStatus[2]=1
			log error "Error: \"Access forbidden\" while validating AWS credentials. Aborting..."
			;;
		*)	mailNotificationStatus[2]=1
			log error "Error: Unknown error while validating AWS credentials, aborting..."
			;;
	  esac
fi

OldType=$(dig @$AuthServer A $Hostname.$Domain | awk "/^$Hostname.$Domain/ { print \$4 }" | head -1) || { mailNotificationStatus[1]=1 && log error "Error while running dig"; }
OldTTL=$(dig @$AuthServer A $Hostname.$Domain | awk "/^$Hostname.$Domain/ { print \$2 }" | head -1) || { mailNotificationStatus[1]=1 && log error "Error while running dig"; }
OldRecord=$(dig @$AuthServer A $Hostname.$Domain | awk "/^$Hostname.$Domain/ { print \$5 }" | sed s/\ //g) || { mailNotificationStatus[1]=1 && log error "Error while running dig"; }

# Create temporary files needed by this script

touch $script_path/ips.tmp.old || log error "Error manipulating temporary files"
touch $script_path/ips.tmp || log error "Error manipulating temporary files"
mv -f $script_path/ips.tmp $script_path/ips.tmp.old || log error "Error manipulating temporary files"
touch $script_path/ips.tmp || log error "Error manipulating temporary files"
mkdir $script_path/probe/ >/dev/null 2>&1 
touch $script_path/awsresult || log error "Error manipulating temporary files"

# Fetch remote probe file if $multisiteprobe is enabled

if [[ $multisiteprobe -eq 1 ]] && [[ $probeonly -ne 1 ]]; then

    for i in 1 2; do

        if [[ -z ${remoteprobe[i]} ]] || [[ -z ${remoteprobefile[i]} ]]; then
            log error "Error: You have enabled multisite probe/health check therefore you must provide two valid probe names (\$remoteprobe) and two result URLs (\$remoteprobefile)"
        fi

        touch "$script_path/probe/proberesult.${remoteprobe[i]}"
        mv -f "$script_path/probe/proberesult.${remoteprobe[i]}" "$script_path/probe/proberesult.${remoteprobe[i]}.old"
        touch "$script_path/probe/proberesult.${remoteprobe[i]}"

        remoteprobefiletype[i]=${remoteprobefile[i]:0:1} # unix file, scp or http? let's see the first letter

        case "${remoteprobefiletype[i]}" in
            /)  if [[ -s "${remoteprobefile[i]}" ]]; then
                    cp -f "${remoteprobefile[i]}" "$script_path/probe/proberesult.${remoteprobe[i]}" >/dev/null 2>&1
                else
                    log error "Error: ${remoteprobefile[i]} not found"
                fi
                ;;
            s)  scpusername=$(echo ${remoteprobefile[i]} | sed -e "s;scp://\(.*\)\@.*:/.*;\1;") # scp://username@myserver.com:/path/to/file
                scphost=$(echo ${remoteprobefile[i]} | sed -e "s;scp://.*\@\(.*\):/.*;\1;")
                scpfile=$(echo ${remoteprobefile[i]} | sed -e "s;scp://.*\@.*:\(.*\);\1;")
                if [[ -n $scpusername ]] && [[ -n $scphost ]] && [[ -n $scpfile ]]; then
                    scp -q -B $scpusername@$scphost:$scpfile "$script_path/probe/proberesult.${remoteprobe[i]}" >/dev/null 2>&1
                    if [[ $? -ne 0 ]]; then
                        log error "Error during SCP copy. Please test the connection manually first and also make sure you set the variable like this: \$remoteprobefile[N]=scp://username@myserver.com:/path/to/file"
                    fi
                else
                    log error "Error: If you want to use SCP please set \$remoteprobefile[N]=scp://username@myserver.com:/path/to/file"
                fi
                ;;
            h)  curl -sS --connect-timeout $connect_timeout --retry $retries --retry-delay 5 -o "$script_path/probe/proberesult.${remoteprobe[i]}" ${remoteprobefile[i]} >/dev/null 2>&1
                if [[ $? -ne 0 ]]; then
                    log error "Error fetching HTTP file: ${remoteprobefile[i]}"
                fi
                ;;
            *)  log error "Please use a valid format for \$remoteprobefile: unix file, scp or http"
                ;;
        esac
        
        if [[ -s "$script_path/probe/proberesult.${remoteprobe[i]}" ]]; then
            echo "ok" > "$script_path/probe/fetchstatus.remote.${remoteprobe[i]}"
            remoteprobetimestamp[i]=$(awk "/Timestamp/ { print \$3 }" < "$script_path/probe/proberesult.${remoteprobe[i]}")
            if [[ -n ${remoteprobetimestamp[i]} ]]; then
                timestampdelta[i]=$(($(date +%s)-${remoteprobetimestamp[i]}))
            else
                log error "Error: no timestamp found on remote probe file"
            fi
            if [[ ${timestampdelta[i]} -gt 30000 ]]; then
                log error "Error: remote timestamp difference is greater than 5 minutes for ${remoteprobe[i]}, make sure the script is running on the remote host and also double check the clock/NTP settings"
            fi
        else
            echo "error" > "$script_path/probe/fetchstatus.remote.${remoteprobe[i]}"
            log error "Error fetching remote proberesult (${remoteprobefile[i]})"
        fi
    done
fi

# Compare probe results
# If multisite is enabled, compare all three results
# If multisite is disabled, no comparison is done

multiSiteCompare () {

    webserverip="$1"
    webserverstatus="$2"
    
    if [[ $multisiteprobe -eq 1 ]] && [[ $probeonly -ne 1 ]]; then
        multisite_up_webserver=0
        if [[ $webserverstatus == "up" ]]; then
            multisite_up_webserver=$(( $multisite_up_webserver + 1 ))
        fi
        for z in 1 2; do
            if [[ ! -s "$script_path/probe/proberesult.${remoteprobe[z]}" ]]; then
                log error "Error reading proberesult.${remoteprobe[z]}"
            fi
            remoteprobe[z*10]=$(grep "^[0-9]" "$script_path/probe/proberesult.${remoteprobe[z]}" | grep "^$webserverip:200:1$" | uniq | wc -l | cut -d ' ' -f 8)
            if [[ ${remoteprobe[z*10]} -ne 1 ]]; then # 1=up / 0=down
                remoteprobe[z*100]=$(grep "^[0-9]" "$script_path/probe/proberesult.${remoteprobe[z]}" | grep "^$webserverip" | awk -F \: "{ print \$2 }")
                log info "${remoteprobe[z]} is reporting $webserverip as DOWN"
            else
                multisite_up_webserver=$(( $multisite_up_webserver + 1 ))
            fi
        done
        if [[ $multisite_up_webserver -ge 2 ]]; then
            return 1 #up
        elif [[ $multisite_up_webserver -lt 2 ]]; then
            return 0 #down
        fi
    else
        if [[ $webserverstatus == "up" ]]; then
            return 1 #up
        elif [[ $webserverstatus == "down" ]]; then
            return 0 #down
        fi
    fi
}


# Connect to webserver and search for a specific string to
# check if webserver are up and running for each address 
# listed in ips.master file. Than print multiple lines
# for each IP address based in fixed weight seted in ips.master

HostsUpAmount=0
HostsDownAmount=0
HostsDisabledAmount=$(cat $script_path/ips.master | egrep "^#.*[0-9]" | wc -l | cut -d ' ' -f 8)
HostsDownList=""

echo "# Timestamp: $(date +%s) [$(date)]" > $script_path/probe/proberesult.tmp
echo "# Format: <Webserver IP>:<Returned HTTP Code>:<String Found>" >> $script_path/probe/proberesult.tmp
echo "# HTTP Code \"000\" means timeout or connection refused" >> $script_path/probe/proberesult.tmp

for i in $(cat $script_path/ips.master | grep -v "#"); do
    ip=$(echo $i | awk -F":" '{print $2}')
    webserverprobe=$(curl -sS -w ";;%{http_code}" --connect-timeout $connect_timeout --retry $retries --retry-delay 5 http://$ip/$test_file 2>&1)
    webserverprobeHTTPcode=$(echo $webserverprobe | awk -F ";;" "{ print \$2 }")
    webserverprobecondition=$(echo "$webserverprobe" | grep "$test_string" | wc -l | cut -d ' ' -f 8)
    echo "$ip:$webserverprobeHTTPcode:$webserverprobecondition" >> $script_path/probe/proberesult.tmp
    if [ "$webserverprobecondition" -eq "1" ]; then
        multiSiteCompare "$ip" up
        if [[ $? -eq 1 ]]; then
            HostsUpAmount=$(( $HostsUpAmount + 1 ))     
            peso=$(echo $i | awk -F":" '{print $1}')
            counter=1
            while [ $counter -le $peso ]; do
                echo $ip >> $script_path/ips.tmp
                counter=$(( $counter + 1 ))
            done
        else
            log info "Host $ip is UP for me, but is DOWN from both other locations"
            HostsDownAmount=$(( $HostsDownAmount + 1 ))
            HostsDownList=$HostsDownList",$ip"
        fi
    else
        multiSiteCompare "$ip" down
        if [[ $? -eq 1 ]]; then
            log info "Host $ip is DOWN for me, but is UP from both other locations"
            HostsUpAmount=$(( $HostsUpAmount + 1 ))     
            peso=$(echo $i | awk -F":" '{print $1}')
            counter=1
            while [ $counter -le $peso ]; do
                echo $ip >> $script_path/ips.tmp
                counter=$(( $counter + 1 ))
            done
        else
            HostsDownAmount=$(( $HostsDownAmount + 1 ))
            HostsDownList=$HostsDownList",$ip"
            log info "Host $ip is DOWN"
        fi
    fi
done

# Move tmp file to its correct location (avoid race condition)
mv -f $script_path/probe/proberesult.tmp $script_path/probe/proberesult

# Exit if we detect this is a probe-only host. Probing has finished, nothing else needs to be done.
if [[ $probeonly -eq 1 ]]; then
    log info "Probe result: [up:$HostsUpAmount][down:$HostsDownAmount][disabled:$HostsDisabledAmount]"
    echo "# Last successful execution: $(date +%s) [$(date)]" > $script_path/monit.status
    rm -f "$lockfile"
    exit 0
fi

# Check if file ips.tmp are empty (empty file = no webserver available)

if [ -s "$script_path/ips.tmp" ]
then

  # Let's decide if we need to update our zone or not
  #
  # Script will quit if ALL of the following conditions are met:
  #   1) ips.tmp has the same content as the previous version (ips.tmp.old)
  #   2) last AWS update was successfull
  #   3) current records returned by `dig' perfectly match our probe result
  #
  # If any of the above is false, we procede with Route53 update.

  OldRecordSorted=$(echo "$OldRecord" | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n)
  NewRecordSorted=$(cat $script_path/ips.tmp | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n)

  if [[ "$OldRecordSorted" == "$NewRecordSorted" ]] && [[ ! "${1:-unset}" = "--force" ]]; then
	echo
	log info "Update not needed [up:$HostsUpAmount][down:$HostsDownAmount][disabled:$HostsDisabledAmount]"
	echo
	echo "You may force an update to Route53 by using the '--force' argument"
	echo
    echo "# Last successful execution: $(date +%s) [$(date)]" > $script_path/monit.status
    rm -f "$lockfile"
    exit 0
  fi

  if [[ -z $(diff $script_path/ips.tmp.old $script_path/ips.tmp >/dev/null) ]] && [[ -n $(grep ok $script_path/awsresult) ]] && [[ "$OldRecordSorted" == "$NewRecordSorted" ]] && [[ ! "${1:-unset}" = "--force" ]]
    then
	if [ "$OldType" == "CNAME" ]; then
		echo
		log info "Update not needed [failover activated]"
	else
      		echo
      		log info "Update not needed [up:$HostsUpAmount][down:$HostsDownAmount][disabled:$HostsDisabledAmount]"
	fi
	echo
	echo "You may force an update to Route53 by using the '--force' argument"
	echo

  else

	if [[ "$OldType" == "CNAME" ]] && [[ -n "$NewRecordSorted" ]]; then
		echo
		log info "Disabling failover state, returning to normal operation"
		mailNotificationStatus[7]=1
		echo
	fi

      # Show which hosts have been added or removed
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
		mailNotificationStatus[5]=0
            for i in $(seq 1 $(($j-1))); do
                  if [ ${addHosts[i*1000+4]} -eq 0 ]; then
                        showAddedHosts=$showAddedHosts", "${addHosts[i*1000+1]}
				mailNotificationStatus[5]=$((${mailNotificationStatus[5]}+1)) # increase host added count
				mailNotificationStatus[5*10+i]=${addHosts[i*1000+1]} # ip address for each added host
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
		mailNotificationStatus[4]=0
            for i in $(seq 1 $(($j-1))); do
                  if [ ${removeHosts[i*1000+4]} -eq 0 ]; then
                        showRemovedHosts=$showRemovedHosts", "${removeHosts[i*1000+1]}
				mailNotificationStatus[4]=$((${mailNotificationStatus[4]}+1)) # increase host removed count
				mailNotificationStatus[4*10+i]=${removeHosts[i*1000+1]} # ip address for each removed host
				mailNotificationStatus[4*100+i]=$(awk -F \: "/^${removeHosts[i*1000+1]}/ { print \$2 }" < $script_path/probe/proberesult) # http error code (reason)
				mailNotificationStatus[4*1000+i]=$(awk -F \: "/^${removeHosts[i*1000+1]}/ { print \$3 }" < $script_path/probe/proberesult) # string test
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
      AWSChangeset=""
      AWSChangeset=$AWSChangeset"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      AWSChangeset=$AWSChangeset"<ChangeResourceRecordSetsRequest xmlns=\"https://route53.amazonaws.com/doc/2012-02-29/\">"
      AWSChangeset=$AWSChangeset"<ChangeBatch><Comment>Update $Hostname.$Domain</Comment><Changes>"

      # Delete previous DNS records
      AWSChangeset=$AWSChangeset"<Change>"
      AWSChangeset=$AWSChangeset"<Action>DELETE</Action>"
      AWSChangeset=$AWSChangeset"<ResourceRecordSet>"
      AWSChangeset=$AWSChangeset"<Name>$Hostname.$Domain.</Name>"
      AWSChangeset=$AWSChangeset"<Type>$OldType</Type>"
      AWSChangeset=$AWSChangeset"<TTL>$OldTTL</TTL>"
      AWSChangeset=$AWSChangeset"<ResourceRecords>"
      for i in $OldRecord; do
            AWSChangeset=$AWSChangeset"<ResourceRecord><Value>$i</Value></ResourceRecord>"
      done
      AWSChangeset=$AWSChangeset"</ResourceRecords>"
      AWSChangeset=$AWSChangeset"</ResourceRecordSet>"
      AWSChangeset=$AWSChangeset"</Change>"

      # Create new DNS records
      AWSChangeset=$AWSChangeset"<Change>"
      AWSChangeset=$AWSChangeset"<Action>CREATE</Action>"
      AWSChangeset=$AWSChangeset"<ResourceRecordSet>"
      AWSChangeset=$AWSChangeset"<Name>$Hostname.$Domain.</Name>"
      AWSChangeset=$AWSChangeset"<Type>A</Type>"
      AWSChangeset=$AWSChangeset"<TTL>$ttl</TTL>"
      AWSChangeset=$AWSChangeset"<ResourceRecords>"
      AWSChangeset=$AWSChangeset"`echo $NewRecord | sed s/\ //g`"
      AWSChangeset=$AWSChangeset"</ResourceRecords>"
      AWSChangeset=$AWSChangeset"</ResourceRecordSet>"
      AWSChangeset=$AWSChangeset"</Change>"

      # Close Route 53 changeset data set
      AWSChangeset=$AWSChangeset"</Changes>"
      AWSChangeset=$AWSChangeset"</ChangeBatch>"
      AWSChangeset=$AWSChangeset"</ChangeResourceRecordSetsRequest>"

      # Submit Route 53 changeset data set 
 
	submitroute53	

      fi
      else
 
    # File ips.tmp is empty, you dont have any webserver UP
    # script will change DNS to failover your website to your backup site 

    # First let's make sure the failover host is OK
    # This avoids a false positive if the probe machine has connectivity problems

    condition=$(curl -sS -w ";;%{http_code}" --connect-timeout $connect_timeout --retry $retries --retry-delay 5 http://$fail_host/$test_file 2>&1 | grep "$test_string" | wc -l | cut -d ' ' -f 8)
    if [ "$condition" -ne "1" ]; then
	mailNotificationStatus[8]=1
	log error "Error: failover host is also down, I don't know what else to do. Make sure my network connectivity is OK. Exiting..."
    fi

    # Failover host is OK, let's proceed with the update

    if [[ -z $(diff $script_path/ips.tmp.old $script_path/ips.tmp >/dev/null) ]] && [[ -n $(grep ok $script_path/awsresult) ]] && [[ "$OldType" == "CNAME" ]] && [[ ! "${1:-unset}" = "--force" ]]
    then
      echo
      log info "Update not needed [failover activated]"
      echo

    else

	if [[ ! "$OldType" == "CNAME" ]]; then
		echo
		log info "All hosts are down, enabling failover state"
		mailNotificationStatus[6]=1
		echo
	fi

      log info "Starting update process..."
      echo

	NewRecordSorted=""

      # Create Route 53 Changeset data set
      AWSChangeset=""
      AWSChangeset=$AWSChangeset"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      AWSChangeset=$AWSChangeset"<ChangeResourceRecordSetsRequest xmlns=\"https://route53.amazonaws.com/doc/2012-02-29/\">"
      AWSChangeset=$AWSChangeset"<ChangeBatch><Comment>Update $Hostname.$Domain</Comment><Changes>"

      # Delete previous DNS records
      AWSChangeset=$AWSChangeset"<Change>"
      AWSChangeset=$AWSChangeset"<Action>DELETE</Action>"
      AWSChangeset=$AWSChangeset"<ResourceRecordSet>"
      AWSChangeset=$AWSChangeset"<Name>$Hostname.$Domain.</Name>"
      AWSChangeset=$AWSChangeset"<Type>$OldType</Type>"
      AWSChangeset=$AWSChangeset"<TTL>$OldTTL</TTL>"
      AWSChangeset=$AWSChangeset"<ResourceRecords>"
      for i in $OldRecord; do
            AWSChangeset=$AWSChangeset"<ResourceRecord><Value>$i</Value></ResourceRecord>"
      done
      AWSChangeset=$AWSChangeset"</ResourceRecords>"
      AWSChangeset=$AWSChangeset"</ResourceRecordSet>"
      AWSChangeset=$AWSChangeset"</Change>"

      # Create new DNS records
      AWSChangeset=$AWSChangeset"<Change>"
      AWSChangeset=$AWSChangeset"<Action>CREATE</Action>"
      AWSChangeset=$AWSChangeset"<ResourceRecordSet>"
      AWSChangeset=$AWSChangeset"<Name>$Hostname.$Domain.</Name>"
      AWSChangeset=$AWSChangeset"<Type>CNAME</Type>"
      AWSChangeset=$AWSChangeset"<TTL>$ttl</TTL>"
      AWSChangeset=$AWSChangeset"<ResourceRecords>"
      AWSChangeset=$AWSChangeset"<ResourceRecord>"
      AWSChangeset=$AWSChangeset"<Value>$fail_host</Value>"
      AWSChangeset=$AWSChangeset"</ResourceRecord>"
      AWSChangeset=$AWSChangeset"</ResourceRecords>"
      AWSChangeset=$AWSChangeset"</ResourceRecordSet>"
      AWSChangeset=$AWSChangeset"</Change>"

      # Close Route 53 changeset data set
      AWSChangeset=$AWSChangeset"</Changes>"
      AWSChangeset=$AWSChangeset"</ChangeBatch>"
      AWSChangeset=$AWSChangeset"</ChangeResourceRecordSetsRequest>"

      # Submit Route 53 changeset data set

	submitroute53

      echo
    fi
fi      

mailNotification

# Update monitoring file.
# You should use a monitoring tool to check if this file was updated in the last 5 minutes.
# (and generate a critical alarm otherwise)
echo "# Last successful execution: $(date +%s) [$(date)]" > $script_path/monit.status

# Remove lockfile
rm -f "$lockfile"

