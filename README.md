route53-failover
================

Shell scripts to implement server failover using Amazon Route53, for more information visit:

http://blog.ebrandi.eti.br/2012/11/como-implementar-um-traffic-manager-com-funcionalidade-de-failover-baseado-no-amazon-route53/


**********************
Additional information
**********************

I) Multi-site probing

This script supports two different probing methods: single site and multi site.
You should use the multi site option on mission critical DNS zones related to a URL where
maximum uptime and availability are absolutely required.

In order to use the multi site method you must choose 3 different servers:
one will be the master node, responsible for doing webserver probes and updating the
Route53 API whenever a host goes down.
The other two nodes will act as slave nodes: they'll check your hosts and
send their result back to the master node.

The master node will update your DNS zone if (and only if) any given host
is reported "down" or "up" from at least 2 different locations (out of 3).

How to configure: set "multisiteprobe" to "1" on all three locations,
set "probeonly" to "0" on the master node and on the slave nodes set 
"probeonly" to "1".

On the master node set a friendly name for each slave node using "remoteprobe[1-2]"
For instante, give each slave node the name of the hosting company where each
server is located.

Then set "remoteprobefile[1-2]" pointing to the "proberesult" file on each node.
You may use a SCP url such as scp://username@my.server.com:/home/route53-failover/probe/proberesult
A HTTP url or UNIX path are also accepted (useful for NFS exports between servers)

Please note that each "proberesult" file has a timestamp and the master node
requires that these files have been generated less than 5 minutes in the past.

