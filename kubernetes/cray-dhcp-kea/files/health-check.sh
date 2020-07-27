#!/usr/bin/env bash
# check number of pids for kea
health=$(ps -ef |grep kea|grep-v grep|wc -l)

# need greater than
if [[ $health -gt 0 ]]
then
  exit 0
else
  exit 1
  echo "Failed health check"
fi