#!/usr/bin/env bash

# check number of pids for kea
pid_health=$(ps -ef |egrep "kea-dhcp|kea-ctrl-agent"|grep -v grep|wc -l)
# check status via api
# result = 0 means kea server and api is working
# result != 0 means something is wrong
kea_health=$(curl -s -X POST -H "Content-Type: application/json" -d '{ "command": "config-get",  "service": [ "dhcp4" ] }' localhost:8000 | jq '.[].result' 2>/dev/null || echo 1)

if [[ $pid_health -gt 0 ]] && [[ $kea_health -eq 0 ]]
then
  exit 0
else
  echo "Failed health check - PID count is: ${pid_health}, API health: ${kea_health}"
  exit 1
fi
