#!/bin/bash
#  check username and passward are empty
#  this can happen if the pod restarts
if [ -z "$DHCP_DBUSER" ]
then
      DHCP_DBUSER=$(cat /secrets/postgres/dhcpdsuser/username)
fi
if [ -z "$DHCP_DBPASS" ]
then
      DHCP_DBPASS=$(cat /secrets/postgres/dhcpdsuser/password)
fi
mkdir -p /usr/local/kea
#  since the username and password is dyanmic with the k8s postgres operator
#  we output the config file and substitute the environment variables
( echo "cat <<EOF" ; cat /cray-dhcp-kea-dhcp4.conf ; echo EOF ) | sh > /usr/local/kea/cray-dhcp-kea-dhcp4.conf
#  clean up
sed -i 's/EOF//g' /usr/local/kea/cray-dhcp-kea-dhcp4.conf
#  helpful for debugging
cat /usr/local/kea/cray-dhcp-kea-dhcp4.conf
# what we use to run Cray DHCP Kea server
/usr/local/sbin/kea-dhcp4 -c /usr/local/kea/cray-dhcp-kea-dhcp4.conf
