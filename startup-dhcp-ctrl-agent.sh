#!/bin/bash
#wait for istio
#until curl --head localhost:15000 ; do echo Waiting for Sidecar; sleep 3 ; done ; echo Sidecar available;

mkdir -p /usr/local/kea
cp /cray-dhcp-kea-ctrl-agent.conf /usr/local/kea/cray-dhcp-kea-ctrl-agent.conf
#  helpful for debugging
cat /usr/local/kea/cray-dhcp-kea-ctrl-agent.conf
# what we use to run Cray Dhcp Kea control agent(api)
/usr/local/sbin/kea-ctrl-agent -c /usr/local/kea/cray-dhcp-kea-ctrl-agent.conf