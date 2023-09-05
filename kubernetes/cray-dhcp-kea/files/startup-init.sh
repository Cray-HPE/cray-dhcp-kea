#!/bin/bash

# wait for istio
# until curl --head localhost:15000  ; do echo Waiting for Sidecar; sleep 3 ; counter++ ; done ; echo Sidecar available;

BACKUP_CONFIG_PATH=/srv/kea/backup/
BACKUP_CONFIG_FILE=keaBackup.conf.gz
KEA_CONFIG_PATH=/usr/local/kea/
KEA_PGSQL_PATH=/usr/local/share/kea/scripts/pgsql/

# Get the expected database schema version. We can get this from the names of the postgres upgrade scripts in the KEA install since they're of the format "upgrade_<version1>_to_<version2>.sh". The highest version is our expected version.
KEA_DB_VERSION=$(ls -l /usr/local/share/kea/scripts/pgsql | grep "upgrade_" | tail -n 1 | awk '{print $NF}' | sed 's/.sh//g' | cut -d '_' -f 4 | sed 's/^0*//')

echo "KEA is expecting postgres schema version ${KEA_DB_VERSION}"

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

# check for db
PGPASSWORD=$DHCP_DBPASS
pg_uri="postgres://$DHCP_DBUSER@$DHCP_DBHOST:5432/"
count=0

# make sure pg is ready to accept connections
until pg_isready -h $DHCP_DBHOST -p 5432 -U $DHCP_DBUSER ; do
  echo "Waiting for postgres at: $pg_uri"
  ((count++))
  sleep 60;
  if [ $count -gt 10 ]
  then
    echo "timeout waiting for postgres and exiting"
    exit 1
  fi
done

DB_VERSION=$(kea-admin db-version pgsql -u $DHCP_DBUSER -p $DHCP_DBPASS -n $DHCP_DBNAME -h $DHCP_DBHOST)
CMD_STAT=$?
if (( $CMD_STAT )) ; then
    # Failed because the database isn't initialized. Create it.
    PGPASSWORD=$DHCP_DBPASS /bin/sh -c "/usr/bin/psql -h $DHCP_DBHOST -U $DHCP_DBUSER -d $DHCP_DBNAME -a -f ${KEA_PGSQL_PATH}dhcpdb_create.pgsql"
elif (( $(echo "$DB_VERSION < $KEA_DB_VERSION" | bc -l) )) ; then
    # Upgrade the database
    kea-admin db-upgrade pgsql -u $DHCP_DBUSER -p $DHCP_DBPASS -n $DHCP_DBNAME -h $DHCP_DBHOST
elif (( $(echo "$DB_VERSION > $KEA_DB_VERSION" | bc -l) )) ; then
    # kea-admin does not provide a way to downgrade the database.
    # In this case we will just have to delete everything and
    # allow dhcp_helper to rebuild everything.
    PGPASSWORD=$DHCP_DBPASS /bin/sh -c "/usr/bin/psql -h $DHCP_DBHOST -U $DHCP_DBUSER -d $DHCP_DBNAME -a -f ${KEA_PGSQL_PATH}dhcpdb_drop.sql"
    # Recreate the database
    PGPASSWORD=$DHCP_DBPASS /bin/sh -c "/usr/bin/psql -h $DHCP_DBHOST -U $DHCP_DBUSER -d $DHCP_DBNAME -a -f ${KEA_PGSQL_PATH}dhcpdb_create.sql"
fi
# PGPASSWORD=$DHCP_DBPASS /bin/sh -c "/usr/bin/psql -h $DHCP_DBHOST -U $DHCP_DBUSER -d $DHCP_DBNAME -a -f dhcpdb_create.sql"

# kea-admin db-init pgsql -u $DHCP_DBUSER -p $DHCP_DBPASS -n $DHCP_DBNAME -h $DHCP_DBHOST

# Will make sure the correct postgres creds exist in existing configs
# and will create a new config if one doesn't exist.
# /srv/kea/dhcp-helper.py --init
if [ -f "${BACKUP_CONFIG_PATH}${BACKUP_CONFIG_FILE}" ]; then
    echo "INFO: Configuration backup exists, checking for validity."
    cd /tmp
    cp ${BACKUP_CONFIG_PATH}${BACKUP_CONFIG_FILE} .
    gunzip "${BACKUP_CONFIG_FILE}"
    kea-dhcp4 -t "${BACKUP_CONFIG_FILE%.*}" > /dev/null
    CONFIG_VALIDATION=$?
    if [ ${CONFIG_VALIDATION} -eq 0 ]; then
        # Fix up the postgres credentials just incase they changed
        # mv ${BACKUP_CONFIG_FILE%.*} ${BACKUP_CONFIG_FILE%.*}.bak
        # jq '.Dhcp4."lease-database"={"type": "postgresql", "name": $DHCP_DBNAME, "host": $DHCP_DBHOST, "user": $DHCP_DBUSER, "password": $DHCP_DBPASS}' --arg DHCP_DBNAME $DHCP_DBNAME --arg DHCP_DBHOST $DHCP_DBHOST --arg DHCP_DBUSER $DHCP_DBUSER --arg DHCP_DBPASS $DHCP_DBPASS "${BACKUP_CONFIG_FILE%.*}.bak" > ${BACKUP_CONFIG_FILE%.*}
        # gzip ${BACKUP_CONFIG_FILE%.*}
        # kubectl -n services patch configmaps cray-dhcp-kea-backup --type merge -p '{"binaryData":{"keaBackup.conf.gz":"$((cat ${BACKUP_CONFIG_FILE}))"}}'
        echo "INFO: Configuration backup validated, copying into place"
        /srv/kea/dhcp-helper.py --backup /tmp/${BACKUP_CONFIG_FILE%.*}
        # cp ${BACKUP_CONFIG_FILE%.*} ${KEA_CONFIG_PATH}cray-dhcp-kea-dhcp4.conf
    else
        echo "WARN: Configuration backup cannot be validated. Generating new configuration"
        /srv/kea/dhcp-helper.py --init
        #  we output the config file and substitute the environment variables
        /srv/kea/dhcp-helper.py --backup ${KEA_CONFIG_PATH}cray-dhcp-kea-dhcp4.conf
        # cp ${KEA_CONFIG_PATH}cray-dhcp-kea-dhcp4.conf ${KEA_CONFIG_PATH}cray-dhcp-kea-dhcp4.conf.bak
    fi
fi
