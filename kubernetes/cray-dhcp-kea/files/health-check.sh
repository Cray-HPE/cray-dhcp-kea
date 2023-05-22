#!/usr/bin/env bash

# check number of pids for kea
pid_health=$(ps -ef |grep kea-dhcp|grep -v grep|wc -l)
# check status via api
# result = 0 means kea server and api is working
# result != 0 means something is wrong
kea_health=$(curl -X POST -H "Content-Type: application/json" -d '{ "command": "config-get",  "service": [ "dhcp4" ] }' localhost:8000|jq '.[].result')

if [[ $pid_health -gt 0 ]] && [ $kea_health -eq 0 ]
then
  exit 0
else
  echo "**********************"
  echo "Failed health check"
  echo "kea pid count is: $pid_health"
  echo "kea status on failed health check"
  curl -s -X POST -H "Content-Type: application/json" -d '{ "command": "status-get", "service": [ "dhcp4" ] }' localhost:8000|jq
  echo "kea config on failed health check"
  curl -s -X POST -H "Content-Type: application/json" -d '{ "command": "config-get", "service": [ "dhcp4" ] }' localhost:8000|jq
  echo "Kea active leases when faield health check"
  curl -s -X POST -H "Content-Type: application/json" -d '{ "command": "lease4-get-all",  "service": [ "dhcp4" ] }' localhost:8000 | jq
  echo "**********************"
  exit 1
