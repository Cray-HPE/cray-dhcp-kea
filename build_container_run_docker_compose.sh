#/bin/bash

docker build -t cray-dhcp-kea -f Dockerfile.dhcp-kea .
docker-compose up -d
