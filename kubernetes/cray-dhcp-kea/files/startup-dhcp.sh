#!/bin/bash

# wait for istio
until curl --head localhost:15000  ; do echo Waiting for Sidecar; sleep 3 ; counter++ ; done ; echo Sidecar available;

BACKUP_CONFIG_PATH=/srv/kea/backup/
BACKUP_CONFIG_FILE=keaBackup.conf.gz
KEA_COFNIG_PATH=/usr/local/kea/

if [ -f "$BACKUP_CONFIG_PATH$BACKUP_CONNFIG" ]; then
    echo "Backup exists."
    echo "Validating"
    cd /tmp
    cp $BACKUP_CONFIG_PATH$BACKUP_CONNFIG .
    gunzip "${BACKUP_CONFIG_FILE%.*}"
    kea_dhcp4 -t "${BACKUP_CONFIG_FILE%.*}"
    CONFIG_VALIDATION=$?
    if [ $CONFIG_VALIDATION -eq 0 ]; then
        cp ${BACKUP_CONFIG_FILE%.*} ${KEA_COFNIG_PATH}cray-dhcp-kea-dhcp4.conf
    fi
fi

# If no backup was loaded.  Run initialization of configs via dhcp-helper.py
if [ ! -f "/usr/local/kea/cray-dhcp-kea-dhcp4.conf" ]; then
    # init run of dhcp-helper
    /srv/kea/dhcp-helper.py --init
    #  we output the config file and substitute the environment variables
    cp ${KEA_COFNIG_PATH}cray-dhcp-kea-dhcp4.conf ${KEA_COFNIG_PATH}cray-dhcp-kea-dhcp4.conf.bak
else
    echo "ERROR: no config file loaded or initialized."
fi

# what we use to run Cray DHCP Kea server
nohup /usr/local/sbin/kea-dhcp4 -p 6067 -P 67 -c /usr/local/kea/cray-dhcp-kea-dhcp4.conf &

# kea exporter for prometheus
kea-exporter --address ${KEA_EXPORTER_ADDRESS} --port ${KEA_EXPORTER_PORT} ${KEA_SOCKET} &

# we will need to tune this
while true; do /srv/kea/dhcp-helper.py; sleep ${DHCP_HELPER_INTERVAL_SECONDS}; done
