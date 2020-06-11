#!/usr/bin/env python

import requests
import json
import ipaddress
import os

resp = requests.get(url='http://cray-sls/v1/search/hardware?type=comptype_cabinet')
subnet4 = []
for i in resp.json():
    for item in resp.json()[0]['ExtraProperties']['Networks']['cn']:
        subnet4_subnet = {}
        subnet4_subnet['pools'] = {}
        subnet4_subnet['pools']['pool'] = {}
        subnet4_subnet['option-data'] = {}
        cn_network_cidr = resp.json()[0]['ExtraProperties']['Networks']['cn'][item]['CIDR']
        cn_gateway = resp.json()[0]['ExtraProperties']['Networks']['cn'][item]['Gateway']
        cn_network = ipaddress.ip_network(cn_network_cidr)
        cn_network_total_hosts = cn_network.num_addresses
        cn_network_pool_start = cn_network[26]
        cn_network_pool_end = cn_network[cn_network_total_hosts - 51]
        # create dictionary json for subnet
        subnet4_subnet['subnet'] = cn_network_cidr
        subnet4_subnet['pools']['pool'] = str(cn_network_pool_start) + '-' + str(cn_network_pool_end)
        subnet4_subnet['option-data']['name'] = 'router'
        subnet4_subnet['option-data']['data'] = cn_gateway
        subnet4.append(subnet4_subnet)
os.environ[SUBNET4] = json.dumps(subnet4)


