#!/bin/bash

#mkdir -p /usr/local/kea
#  since the username and password is dyanmic with the k8s postgres operator
#  we output the config file and substitute the environment variables
cp /srv/kea/startup-config-dhcp4.conf /usr/local/kea/cray-dhcp-kea-dhcp4.conf
cp /srv/kea/startup-config-dhcp4.conf /usr/local/kea/cray-dhcp-kea-dhcp4.conf.bak
#  helpful for debugging
cat /usr/local/kea/cray-dhcp-kea-dhcp4.conf
# what we use to run Cray DHCP Kea server
nohup /usr/local/sbin/kea-dhcp4 -p 6067 -c /usr/local/kea/cray-dhcp-kea-dhcp4.conf &
# kea exporter for prometheus
kea-exporter --address ${KEA_EXPORTER_ADDRESS:="0.0.0.0"} --port ${KEA_EXPORTER_PORT:=8080} ${KEA_SOCKET:="/cray-dhcp-kea-socket/cray-dhcp-kea.socket"} &
# we will need to tune this
while true; do /srv/kea/external_dhcp-helper.py; sleep ${DHCP_HELPER_INTERVAL_SECONDS:=120}; done
