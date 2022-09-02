#!/bin/bash

: "${DHCP_CAHOST:="0.0.0.0"}"
: "${DHCP_CAPORT:=8000}"


#mkdir -p /usr/local/kea
#  since the username and password is dyanmic with the k8s postgres operator
#  we output the config file and substitute the environment variables
cp /srv/kea/startup-config-dhcp4.conf /usr/local/kea/cray-dhcp-kea-dhcp4.conf
cp /srv/kea/startup-config-dhcp4.conf /usr/local/kea/cray-dhcp-kea-dhcp4.conf.bak

( echo "cat <<EOF" ; cat /srv/kea/cray-dhcp-kea-ctrl-agent.conf  ; echo EOF ) | sh > /usr/local/kea/cray-dhcp-kea-ctrl-agent.conf
sed -i 's/EOF//g' /usr/local/kea/cray-dhcp-kea-ctrl-agent.conf

#  helpful for debugging
echo "/usr/local/kea/cray-dhcp-kea-dhcp4.conf"
cat /usr/local/kea/cray-dhcp-kea-dhcp4.conf
echo "/usr/local/kea/cray-dhcp-kea-ctrl-agent.conf"
cat /usr/local/kea/cray-dhcp-kea-ctrl-agent.conf
# what we use to run Cray DHCP Kea server
nohup /usr/local/sbin/kea-dhcp4 -p 6067 -c /usr/local/kea/cray-dhcp-kea-dhcp4.conf &
# kea exporter for prometheus
kea-exporter --address ${KEA_EXPORTER_ADDRESS:="0.0.0.0"} --port ${KEA_EXPORTER_PORT:=8080} ${KEA_SOCKET:="/cray-dhcp-kea-socket/cray-dhcp-kea.socket"} &
# what we use to run Cray Dhcp Kea control agent(api)
/usr/local/sbin/kea-ctrl-agent -c /usr/local/kea/cray-dhcp-kea-ctrl-agent.conf &
# we will need to tune this
while true; do /srv/kea/external_dhcp-helper.py; sleep ${DHCP_HELPER_INTERVAL_SECONDS:=120}; done








