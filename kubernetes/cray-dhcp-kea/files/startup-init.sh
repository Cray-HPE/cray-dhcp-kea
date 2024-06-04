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
until curl --head localhost:15000  ; do echo Waiting for Sidecar; sleep 3 ; counter++ ; done ; echo Sidecar available;

BACKUP_CONFIG_PATH=/srv/kea/backup/
BACKUP_CONFIG_FILE=keaBackup.conf.gz
KEA_CONFIG_PATH=/usr/local/kea/
KEA_PGSQL_PATH=/usr/local/share/kea/scripts/pgsql/

# Get the expected database schema version. We can get this from the names of the postgres upgrade scripts in the KEA install since they're of the format "upgrade_<version1>_to_<version2>.sh". The highest version is our expected version.
KEA_DB_VERSION=$(ls -l /usr/local/share/kea/scripts/pgsql | grep "upgrade_" | tail -n 1 | awk '{print $NF}' | sed 's/.sh//g' | cut -d '_' -f 4 | sed 's/^0*//')

echo "INFO: KEA is expecting postgres schema version ${KEA_DB_VERSION}"

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

# Make sure pg is ready to accept connections
echo "INFO: Waiting for postgres at: $pg_uri"
until psql postgres://$DHCP_DBUSER:$DHCP_DBPASS@$DHCP_DBHOST:$DHCP_DBPORT/$DHCP_DBNAME -c 'select version();'; do
    ((count++))
    if [ $count -gt 300 ] ; then
        echo "ERROR: Timeout waiting for postgres and exiting"
        exit 1
    fi
    sleep 2
done
echo "INFO: Postgres is ready."

count=0
CMD_STAT=1
# Retry setting up the database until we succeed or timeout
while (( $CMD_STAT )) ; do
    DB_VERSION=$(kea-admin db-version pgsql -u $DHCP_DBUSER -p $DHCP_DBPASS -n $DHCP_DBNAME -h $DHCP_DBHOST)
    CMD_STAT=$?
    if (( $CMD_STAT )) ; then
        # Failed because the database isn't initialized. Create it.
        PGPASSWORD=$DHCP_DBPASS /bin/sh -c "/usr/bin/psql -h $DHCP_DBHOST -U $DHCP_DBUSER -d $DHCP_DBNAME -a -f ${KEA_PGSQL_PATH}dhcpdb_create.pgsql"
        CMD_STAT=$?
    elif (( $(echo "$DB_VERSION < $KEA_DB_VERSION" | bc -l) )) ; then
        # Upgrade the database
        kea-admin db-upgrade pgsql -u $DHCP_DBUSER -p $DHCP_DBPASS -n $DHCP_DBNAME -h $DHCP_DBHOST
        CMD_STAT=$?
    elif (( $(echo "$DB_VERSION > $KEA_DB_VERSION" | bc -l) )) ; then
        # kea-admin does not provide a way to downgrade the database.
        # In this case we will just have to delete everything and
        # allow dhcp_helper to rebuild everything.
        PGPASSWORD=$DHCP_DBPASS /bin/sh -c "/usr/bin/psql -h $DHCP_DBHOST -U $DHCP_DBUSER -d $DHCP_DBNAME -a -f ${KEA_PGSQL_PATH}dhcpdb_drop.sql"
        # Recreate the database
        PGPASSWORD=$DHCP_DBPASS /bin/sh -c "/usr/bin/psql -h $DHCP_DBHOST -U $DHCP_DBUSER -d $DHCP_DBNAME -a -f ${KEA_PGSQL_PATH}dhcpdb_create.sql"
        CMD_STAT=$?
    fi
    if (( $CMD_STAT )) ; then
        ((count++))
        if [ $count -gt 10 ] ; then
            echo "ERROR: Failed to initialize Postgres to KEA schema version ${KEA_DB_VERSION}"
            exit 1
        else
            echo "WARN: Failed to initialize Postgres to KEA schema version ${KEA_DB_VERSION}. Retrying..."
            sleep 5
        fi
    fi
done

# Will make sure the correct postgres creds exist in existing configs
# and will create a new config if one doesn't exist.
if [ -f "${BACKUP_CONFIG_PATH}${BACKUP_CONFIG_FILE}" ]; then
    echo "INFO: Configuration backup exists, checking for validity."
    cd /tmp
    cp ${BACKUP_CONFIG_PATH}${BACKUP_CONFIG_FILE} .
    gunzip "${BACKUP_CONFIG_FILE}"
    kea-dhcp4 -t "${BACKUP_CONFIG_FILE%.*}" > /dev/null
    CONFIG_VALIDATION=$?
    if [ ${CONFIG_VALIDATION} -eq 0 ]; then
        # Fix up the postgres credentials just incase they changed
        echo "INFO: Configuration backup validated, copying into place"
        /srv/kea/dhcp-helper.py --backup /tmp/${BACKUP_CONFIG_FILE%.*}
    else
        echo "WARN: Configuration backup cannot be validated. Generating new configuration"
        /srv/kea/dhcp-helper.py --init
        # We output the config file and substitute the environment variables
        /srv/kea/dhcp-helper.py --backup ${KEA_CONFIG_PATH}cray-dhcp-kea-dhcp4.conf
    fi
else
    echo "WARN: No existing backup. Generating new configuration"
    /srv/kea/dhcp-helper.py --init
    # We output the config file and substitute the environment variables
    /srv/kea/dhcp-helper.py --backup ${KEA_CONFIG_PATH}cray-dhcp-kea-dhcp4.conf
fi
