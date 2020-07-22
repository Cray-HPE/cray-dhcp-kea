#!/usr/bin/env bash
# check number of pids for kea
health=$(ps -ef |grep kea|wc -l)

# need greater than
if [[ $health -gt 1 ]]
then
  exit 0
else
  exit 1
fi