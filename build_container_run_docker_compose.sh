#/bin/bash

docker build -t cray-dhcp -f Dockerfile.dhcp .
docker-compose up -d