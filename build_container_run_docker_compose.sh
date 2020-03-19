#/bin/bash

docker build -t cray-dhcp-kea -f Dockerfile.dhcp .
docker-compose up -d