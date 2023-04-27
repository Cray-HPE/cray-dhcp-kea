#!/bin/bash

# wait for kea server to start
i=1
while [[ $i -le 600 || ! -f /cray-dhcp-kea-socket/cray-dhcp-kea.socket ]]
do
    i=$(( $i + 1 ))
    sleep 10
done
( echo "cat <<EOF" ; cat /srv/kea/cray-dhcp-kea-ctrl-agent.conf  ; echo EOF ) | sh > /usr/local/kea/cray-dhcp-kea-ctrl-agent.conf
sed -i 's/EOF//g' /usr/local/kea/cray-dhcp-kea-ctrl-agent.conf
#  helpful for debugging
cat /usr/local/kea/cray-dhcp-kea-ctrl-agent.conf
# what we use to run Cray Dhcp Kea control agent(api)
/usr/local/sbin/kea-ctrl-agent -c /usr/local/kea/cray-dhcp-kea-ctrl-agent.conf