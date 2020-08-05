#!/usr/bin/env bash

# check number of pids for kea
pid_health=$(ps -ef |grep kea|grep -v grep|wc -l)
# check status via api
# result = 0 means kea server and api is working
# result != 0 means something is wrong
kea_health=$(curl -X POST -H "Content-Type: application/json" -d '{ "command": "status-get" }' cray-dhcp-kea-api:8000|jq '.[].result')

if [[ $pid_health -gt 0 ]] && [[ $kea_health -eq 0 ]]
then
  exit 0
else
  echo "**********************"\n
  echo "Failed health check"\n
  echo "kea pid count is: $pid_health"\n
  echo "kea status on failed health check"\n
  curl -s -X POST -H "Content-Type: application/json" -d '{ "command": "status-get", "service": [ "dhcp4" ] }' cray-dhcp-kea-api:8000|jq
  echo "kea config on failed health check"\n
  curl -s -X POST -H "Content-Type: application/json" -d '{ "command": "config-get", "service": [ "dhcp4" ] }' cray-dhcp-kea-api:8000|jq
  echo "Kea active leases when faield health check"/n
  curl -s -X POST -H "Content-Type: application/json" -d '{ "command": "lease4-get-all",  "service": [ "dhcp4" ] }' cray-dhcp-kea-api:8000 | jq
  echo "**********************"\n
  exit 1
fi