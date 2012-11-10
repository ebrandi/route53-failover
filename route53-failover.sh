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
test_file=status
test_string="Error 200 OK"

###############################################################
#    You should not need to change anything bellow this point #
###############################################################

# Set variables with DNS Record Values to create DELETE API request

AuthServer=`dig NS $Domain | grep -v ';' | grep -m 1 awsdns | grep $Domain | cut -f 6`
OldType=`dig @$AuthServer A $Hostname.$Domain | grep -v ";" | grep "$Hostname\.$Domain" | awk -F " " '{print $4}' | head -1`
OldTTL=`dig @$AuthServer A $Hostname.$Domain | grep -v ";" | grep "$Hostname\.$Domain" | awk -F " " '{print $2}' | head -1`
OldRecord=`dig @$AuthServer A $Hostname.$Domain | grep -v ";" | grep "$Hostname\.$Domain" | awk -F" " '{print "<ResourceRecord><Value>"$5"</Value></ResourceRecord>"}'`

# Create temporary files needed by this script

touch $script_path/ips.tmp.old
touch $script_path/ips.tmp
mv $script_path/ips.tmp $script_path/ips.tmp.old
touch $script_path/ips.tmp

# Connect to webserver and search for a specific string to
# check if webserver are up and running for each address 
# listed in ips.master file 

for i in `cat $script_path/ips.master`
do
  condition=`lynx -connect_timeout=1 -dump http://$i/$test_file 2>&1 | grep "$test_string" | wc -l | cut -d ' ' -f 8`
  if [ "$condition" -eq "1" ]
  then
     echo $i >> $script_path/ips.tmp
  fi
done

# Check if file ips.tmp are empty (empty file = no webserver available)

if [ -s "$script_path/ips.tmp" ]
then

  # If file ips.tmp has any content, compare it with previous version of this file.
  # If both files has same content, script will quit
  # If not ot procede with route 53 update using IPs from ips.tmp file

  if `diff $script_path/ips.tmp $script_path/ips.tmp.old >/dev/null`
    then
      echo
      echo "Update is not necessary, nothing changed since last execution"
      echo
    else
      echo
      echo "Starting update process..."
      echo

      # Generate ResourceRecord for IPs listed in ips.tmp file

      NewRecord=`cat $script_path/ips.tmp | awk '{print "<ResourceRecord><Value>"$1"</Value></ResourceRecord>"}'`

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
      Changeset=$Changeset"`echo $OldRecord| sed s/\ //g`"
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

      echo "Changeset submited:"
      echo $Changeset
      echo

      # Submit Route 53 changeset data set 
 
      CurrentDate=`/usr/local/bin/wget --no-check-certificate -q -S https://route53.amazonaws.com/date -O /dev/null 2>&1 | grep Date | sed 's/.*Date: //'`
      Signature=`echo -n $CurrentDate | openssl dgst -binary -sha1 -hmac $SecretAPIKey | /usr/local/bin/base64`
      DateHeader="Date: "$CurrentDate
      AuthHeader="X-Amzn-Authorization: AWS3-HTTPS AWSAccessKeyId=$AccesskeyID,Algorithm=HmacSHA1,Signature=$Signature"
      Result=`/usr/local/bin/wget --no-check-certificate -nv --header="$DateHeader" --header="$AuthHeader" --header="Content-Type: text/xml; charset=UTF-8" --post-data="$Changeset" -O /dev/stdout -o /dev/stdout https://route53.amazonaws.com/2010-10-01/hostedzone/$ZoneID/rrset`
      echo "API Output:"
      echo "$Result" | grep -v WARNING | grep -v locally
      echo
    fi
    else
 
    # File ips.tmp is empty , you dosent have any webserver UP
    # script will change DNS to failover your website to your backup site 

    if `diff $script_path/ips.tmp $script_path/ips.tmp.old >/dev/null`
    then
      echo
      echo "Update is not necessary, nothing changed since last execution"
      echo
    else
      echo
      echo "Starting update process..."
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
      Changeset=$Changeset"`echo $OldRecord| sed s/\ //g`"
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

      echo "Changeset submited:"
      echo $Changeset
      echo

      # Submit Route 53 changeset data set

      CurrentDate=`/usr/local/bin/wget --no-check-certificate -q -S https://route53.amazonaws.com/date -O /dev/null 2>&1 | grep Date | sed 's/.*Date: //'`
      Signature=`echo -n $CurrentDate | openssl dgst -binary -sha1 -hmac $SecretAPIKey | /usr/local/bin/base64`
      DateHeader="Date: "$CurrentDate
      AuthHeader="X-Amzn-Authorization: AWS3-HTTPS AWSAccessKeyId=$AccesskeyID,Algorithm=HmacSHA1,Signature=$Signature"
      Result=`/usr/local/bin/wget --no-check-certificate -nv --header="$DateHeader" --header="$AuthHeader" --header="Content-Type: text/xml; charset=UTF-8" --post-data="$Changeset" -O /dev/stdout -o /dev/stdout https://route53.amazonaws.com/2010-10-01/hostedzone/$ZoneID/rrset`
      echo "API Output:"
      echo "$Result" | grep -v WARNING | grep -v locally
      echo
    fi
 fi      
