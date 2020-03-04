#!/bin/bash
( echo "cat <<EOF" ; cat /kea-ctrl-agent.conf ; echo EOF ) | sh > /etc/kea/kea-ctrl-agent.conf
#  clean up
sed -i 's/EOF//g' /etc/kea/kea-ctrl-agent.conf
#  helpful for future debugging
cat /etc/kea/kea-ctrl-agent.conf
# what we use to run isc kea
/usr/sbin/kea-ctrl-agent -c /etc/kea/kea-ctrl-agent.conf
