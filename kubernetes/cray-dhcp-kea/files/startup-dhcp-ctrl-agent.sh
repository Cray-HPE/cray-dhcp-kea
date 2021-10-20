#!/bin/bash

( echo "cat <<EOF" ; cat /srv/kea/cray-dhcp-kea-ctrl-agent.conf  ; echo EOF ) | sh > /usr/local/etc/kea/cray-dhcp-kea-ctrl-agent.conf
#  helpful for debugging
cat /usr/local/kea/cray-dhcp-kea-ctrl-agent.conf
# what we use to run Cray Dhcp Kea control agent(api)
/usr/local/sbin/kea-ctrl-agent -c /usr/local/kea/cray-dhcp-kea-ctrl-agent.conf