#!/bin/bash
# Copyright 2023 Hewlett Packard Enterprise Development LP
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

. /usr/local/kea_virtualenv/bin/activate

# wait for istio
until curl --head localhost:15000  ; do echo Waiting for Sidecar; sleep 3 ; done ; echo Sidecar available;

BACKUP_CONFIG_PATH=/srv/kea/backup/
BACKUP_CONFIG_FILE=keaBackup.conf.gz
KEA_CONFIG_PATH=/usr/local/kea/
KEA_DB_VERSION=$(ls -l /usr/local/share/kea/scripts/pgsql | grep "upgrade_" | tail -n 1 | awk '{print $NF}' | sed 's/.sh//g' | cut -d '_' -f 4 | sed 's/^0*//')

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

# Wait until the database schema is at our desired version
count=0
DB_VERSION=0
echo "INFO: Waiting for postgres schema to be initialized."
until (( $(echo "$DB_VERSION == $KEA_DB_VERSION" | bc -l) )) ; do
    DB_VERSION=$(kea-admin db-version pgsql -u $DHCP_DBUSER -p $DHCP_DBPASS -n $DHCP_DBNAME -h $DHCP_DBHOST)
    CMD_STAT=$?
    if (( $CMD_STAT )) ; then
        DB_VERSION=0
    fi
    ((count++))
    if [ $count -gt 60 ] ; then
        echo "ERROR: Timeout waiting for postgres. Exiting..."
        exit 1
    fi
    sleep 10
done
echo "INFO: Postgres is ready."

# Wait for a valid KEA config
CONFIG_VALIDATION=1
while (( $CONFIG_VALIDATION )) ; do
    if [ -f "${BACKUP_CONFIG_PATH}${BACKUP_CONFIG_FILE}" ]; then
        echo "INFO: Configuration backup exists, checking for validity."
        cd /tmp
        cp ${BACKUP_CONFIG_PATH}${BACKUP_CONFIG_FILE} .
        gunzip "${BACKUP_CONFIG_FILE}"
        kea-dhcp4 -t "${BACKUP_CONFIG_FILE%.*}" > /dev/null
        CONFIG_VALIDATION=$?
        if [ ${CONFIG_VALIDATION} -eq 0 ]; then
            echo "INFO: Configuration backup validated, copying into place"
            cp ${BACKUP_CONFIG_FILE%.*} ${KEA_CONFIG_PATH}cray-dhcp-kea-dhcp4.conf
        else
            echo "WARN: Configuration backup cannot be validated. Retrying..."
            ((count++))
            if [ $count -gt 60 ] ; then
                echo "ERROR: Timeout waiting for valid KEA config."
                exit 1
            fi
            sleep 10
        fi
        # Cleanup
        rm /tmp/${BACKUP_CONFIG_FILE%.*}
    else
        # No configmap 
        echo "INFO: Generating new configuration."
        /srv/kea/dhcp-helper.py --init
        # We output the config file and substitute the environment variables
        cp ${KEA_CONFIG_PATH}cray-dhcp-kea-dhcp4.conf ${KEA_CONFIG_PATH}cray-dhcp-kea-dhcp4.conf.bak
        break
    fi
done

# what we use to run Cray DHCP Kea server
nohup /usr/local/sbin/kea-dhcp4 -p 6067 -c /usr/local/kea/cray-dhcp-kea-dhcp4.conf &

# kea exporter for prometheus
kea-exporter --address ${KEA_EXPORTER_ADDRESS} --port ${KEA_EXPORTER_PORT} ${KEA_SOCKET} &

while true; do
    inotifywait -e modify ${BACKUP_CONFIG_PATH}${BACKUP_CONFIG_FILE}
    curr_time=$(date)
    echo "INFO: Reload Config - $curr_time"
    cd /tmp
    cp ${BACKUP_CONFIG_PATH}${BACKUP_CONFIG_FILE} .
    gunzip "${BACKUP_CONFIG_FILE}"
    kea-dhcp4 -t "${BACKUP_CONFIG_FILE%.*}" > /dev/null
    CONFIG_VALIDATION=$?
    if [ ${CONFIG_VALIDATION} -eq 0 ]; then
        echo "INFO: Configuration backup validated, copying into place"
        cp ${BACKUP_CONFIG_FILE%.*} ${KEA_CONFIG_PATH}cray-dhcp-kea-dhcp4.conf
        curl -s -X POST http://localhost:8000/ -H "Content-Type: application/json" -d '{"command": "config-reload", "service": ["dhcp4"]}'
    else
        echo "WARN: Configuration backup cannot be validated. Retrying..."
    fi
    # Cleanup
    rm /tmp/${BACKUP_CONFIG_FILE%.*}
done
