#!/bin/bash
# wait for istio
counter=0

#until [[ "curl --head localhost:15000" || counter -lt 5 ]]  ; do echo Waiting for Sidecar; sleep 3 ; counter++ ; done ; echo Sidecar available;

#mkdir -p /usr/local/kea
#  since the username and password is dyanmic with the k8s postgres operator
#  we output the config file and substitute the environment variables
cp /srv/kea/startup-config-dhcp4.conf /usr/local/kea/cray-dhcp-kea-dhcp4.conf
#  helpful for debugging
cat /usr/local/kea/cray-dhcp-kea-dhcp4.conf
# what we use to run Cray DHCP Kea server
nohup /usr/local/sbin/kea-dhcp4 -c /usr/local/kea/cray-dhcp-kea-dhcp4.conf &
# we will need to tune this
while true; do /srv/kea/dhcp-helper.py; sleep ${DHCP_HELPER_INTERVAL_SECONDS}; done
