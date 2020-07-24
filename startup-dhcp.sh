#!/bin/bash

mkdir -p /usr/local/kea
#  since the username and password is dyanmic with the k8s postgres operator
#  we output the config file and substitute the environment variables
cp /cray-dhcp-kea-dhcp4.conf /usr/local/kea/cray-dhcp-kea-dhcp4.conf
#  helpful for debugging
cat /usr/local/kea/cray-dhcp-kea-dhcp4.conf
# what we use to run Cray DHCP Kea server
nohup /usr/local/sbin/kea-dhcp4 -c /usr/local/kea/cray-dhcp-kea-dhcp4.conf &
# we will need to tune this
while true; do /dhcp-helper.py; sleep ${DHCP_HELPER_INTERVAL_SECONDS}; done
