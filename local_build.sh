#/bin/bash

docker build -t cray/cray-dhcp-kea -f Dockerfile.dhcp-kea .
docker build -t cray/cray-dhcp-kea-ctrl-agent -f Dockerfile.dhcp-kea-ctrl-agent .
docker build -t cray/cray-dhcp-kea-init -f Dockerfile.dhcp-kea-init .
