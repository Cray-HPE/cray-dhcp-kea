#!/usr/bin/env python

import requests
import json

# dict of the current IPv4 leases managed by Kea, each item in the format:
# '08:08:08:08:08:08': {
#     "cltt": 12345678,
#     "duid": "42:42:42:42:42:42:42:42",
#     "fqdn-fwd": false,
#     "fqdn-rev": true,
#     "hostname": "myhost.example.com.",
#     "hw-address": "08:08:08:08:08:08",
#     "iaid": 1,
#     "ip-address": "10.0.0.20",
#     "preferred-lft": 500,
#     "state": 0,
#     "subnet-id": 44,
#     "type": "IA_NA",
#     "valid-lft": 3600
# }
kea_ipv4_leases = {}

# dict of network interfaces that SMD is aware of, each item in the format:
# 'a4:bf:01:3e:c8:fa': {
#     "ID": "a4bf013ec8fa",
#     "Description": "System NIC 2",
#     "MACAddress": "a4:bf:01:3e:c8:fa",
#     "IPAddress": "",
#     "LastUpdate": "2020-06-01T22:42:07.204895Z",
#     "ComponentID": "x3000c0s19b1n0",
#     "Type": "Node"
# }
smd_ethernet_interfaces = {}

# 1) ##############################################################################

#   a) Get network subnet and cabinet subnet info from SLS
resp = requests.get(url='http://cray-sls/v1/search/hardware?type=comptype_cabinet')

#   b) TODO: use resp.json() to process the SLS results and pass to kea appropriately
#            Kea should be updated with the subnet info served from SLS, but not sure
#            how this translates

#   c) TODO: enable kea dhcp pools?
#            not sure what this means or how to do it

# 2) ##############################################################################

#   a) Query Kea for DHCP leases, we'll just query the api
data = {'command': 'lease4-get-all', 'service': ['dhcp4']}
kea_headers = {'Content-Type': 'application/json'}
kea_api_endpoint = 'http://cray-dhcp-kea-api:8000'
try:
    resp = requests.post(url=kea_api_endpoint, json=data, headers=kea_headers)
    resp.raise_for_status()
except Exception as err:
    raise SystemExit(err)
for lease in resp.json()[0]['arguments']['leases']:
    if lease['hw-address'] != '':
        kea_ipv4_leases[lease['hw-address']] = lease

#   b) Query SMD to get all network interfaces it knows about
try:
    resp = requests.get(url='http://cray-smd/hsm/v1/Inventory/EthernetInterfaces')
    resp.raise_for_status()
except Exception as err:
    raise SystemExit(err)
for item in resp.json():
    if item['MACAddress'] != '':
        smd_ethernet_interfaces[item['MACAddress']] = item

#   c) Resolve the results from both SMD and Kea to synchronize both

for smd_mac_address in smd_ethernet_interfaces:
    # if SMD has MAC and IP and not in Kea DHCP reservation, add DHCP reservation in Kea
    if smd_ethernet_interfaces[smd_mac_address]['IPAddress'] != '' and smd_mac_address not in kea_ipv4_leases:
        print('Found MAC and IP address pair from SMD and updating Kea with the record: {} {}'.format(smd_mac_address, smd_ethernet_interfaces[smd_mac_address]['IPAddress']))
        data = {'command': 'lease4-update', 'arguments': {'ip-address': smd_ethernet_interfaces[smd_mac_address]['IPAddress'], 'hw-address': smd_mac_address, 'force-create': 'true'}}
        try:
            resp = requests.post(url=kea_api_endpoint, json=data, headers=kea_headers)
            resp.raise_for_status()
        except Exception as err:
            raise SystemExit(err)
    # if IP Address is not present for a given mac address record in SMD, but Kea has a record with the MAC address and a non-empty IP, we can submit updates to SMD
    if smd_ethernet_interfaces[smd_mac_address]['IPAddress'] == '' and smd_mac_address in kea_ipv4_leases and kea_ipv4_leases[smd_mac_address]['ip-address'] != '':
        print("") # TODO: remove this print line, just here to ensure there's some code in the if block
        # TODO: Update SMD with IP
        # TODO: Initiate discovery of IP on SMD
for kea_mac_address in kea_ipv4_leases:
    # go through the Kea records now and make sure we submit any MACs/IPs that weren't in SMD at all back for discovery to SMD
    if kea_mac_address not in smd_ethernet_interfaces:
        # TODO: Submit IP for discovery in SMD
