#!/bin/bash
( echo "cat <<EOF" ; cat /cray-dhcp-kea-ctrl-agent.conf ; echo EOF ) | sh > /etc/kea/cray-dhcp-kea-ctrl-agent.conf
#  clean up
sed -i 's/EOF//g' /etc/kea/cray-dhcp-kea-ctrl-agent.conf
#  helpful for future debugging
cat /etc/kea/cray-dhcp-kea-ctrl-agent.conf
# what we use to run isc kea
/usr/sbin/kea-ctrl-agent -c /etc/kea/cray-dhcp-kea-ctrl-agent.conf
