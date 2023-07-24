#!/bin/bash

# wait for istio
until curl --head localhost:15000  ; do echo Waiting for Sidecar; sleep 3 ; counter++ ; done ; echo Sidecar available;

BACKUP_CONFIG_PATH=/srv/kea/backup/
BACKUP_CONFIG_FILE=keaBackup.conf.gz
KEA_CONFIG_PATH=/usr/local/kea/

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
        echo "WARN: Configuration backup cannot be validated. Generating new configuration"
    fi
fi

# If no backup was loaded.  Run initialization of configs via dhcp-helper.py
if [ ! -f "/usr/local/kea/cray-dhcp-kea-dhcp4.conf" ]; then
    # init run of dhcp-helper
    echo "INFO: Generating new configuration."
    /srv/kea/dhcp-helper.py --init
    #  we output the config file and substitute the environment variables
    cp ${KEA_CONFIG_PATH}cray-dhcp-kea-dhcp4.conf ${KEA_CONFIG_PATH}cray-dhcp-kea-dhcp4.conf.bak
else
    echo "INFO: Using existing configuration."
fi

# what we use to run Cray DHCP Kea server
nohup /usr/local/sbin/kea-dhcp4 -p 6067 -c /usr/local/kea/cray-dhcp-kea-dhcp4.conf &

# kea exporter for prometheus
kea-exporter --address ${KEA_EXPORTER_ADDRESS} --port ${KEA_EXPORTER_PORT} ${KEA_SOCKET} &

# we will need to tune this
while true; do /srv/kea/dhcp-helper.py; sleep ${DHCP_HELPER_INTERVAL_SECONDS}; done
