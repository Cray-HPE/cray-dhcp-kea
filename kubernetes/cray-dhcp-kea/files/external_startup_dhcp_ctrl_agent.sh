#!/bin/bash
: "${DHCP_CAHOST:="0.0.0.0"}"
: "${DHCP_CAPORT:=8000}"

( echo "cat <<EOF" ; cat /srv/kea/cray-dhcp-kea-ctrl-agent.conf  ; echo EOF ) | sh > /usr/local/kea/cray-dhcp-kea-ctrl-agent.conf
sed -i 's/EOF//g' /usr/local/kea/cray-dhcp-kea-ctrl-agent.conf
#  helpful for debugging
cat /usr/local/kea/cray-dhcp-kea-ctrl-agent.conf
# what we use to run Cray Dhcp Kea control agent(api)
/usr/local/sbin/kea-ctrl-agent -c /usr/local/kea/cray-dhcp-kea-ctrl-agent.conf