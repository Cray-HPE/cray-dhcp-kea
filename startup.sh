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

#  since the username and password is dyanmic with the k8s postgres operator
#  we output the config file and substitute the environment variables
( echo "cat <<EOF" ; cat /kea-dhcp4.conf ; echo EOF ) | sh > /etc/kea/kea-dhcp4.conf
#  clean up
sed -i 's/EOF//g' /etc/kea/kea-dhcp4.conf
#  helpful for future debugging
cat /etc/kea/kea-dhcp4.conf
# what we use to run isc kea
/usr/sbin/kea-dhcp4 -c /etc/kea/kea-dhcp4.conf
