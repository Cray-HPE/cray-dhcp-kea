#!/usr/bin/env python

import requests
import json
import ipaddress

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

# dict for sls hardware entry
# 'x3000c0s19b1n0' : {
#     "Parent":"x3000c0s19b1",
#     "Xname":"x3000c0s19b1n0",
#     "Type":"comptype_node",
#     "Class":"River",
#     "TypeString":"Node",
#     "ExtraProperties":{
#          "Aliases":["nid000001"],
#          "NID":1,
#           "Role":"Compute"
#     }
# }
sls_hardware_entry = {}

# dict for lease database information
# "lease-database": {
#    "host": "cray-dhcp-kea-postgres",
#    "name": "dhcp",
#    "password": "xxxxxxxxxxx",
#    "type": "postgresql",
#    "user": "dhcpdsuser"
# }
lease_database_info = {}
#
#
data = {'command': 'config-get', 'service': ['dhcp4']}
kea_headers = {'Content-Type': 'application/json'}
kea_api_endpoint = 'http://cray-dhcp-kea-api:8000'
try:
    resp = requests.post(url=kea_api_endpoint, json=data, headers=kea_headers)
    resp.raise_for_status()
except Exception as err:
    raise SystemExit(err)
lease_database_info = resp.json()[0]['arguments']['Dhcp4']['lease-database']
print (lease_database_info)
# 1) ##############################################################################

#   a) Get network subnet and cabinet subnet info from SLS
resp = requests.get(url='http://cray-sls/v1/search/hardware?type=comptype_cabinet')
cn_nmn_cidr = resp.json()[0]['ExtraProperties']['Networks']['cn']['NMN']['CIDR']

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
    # if SMD has MAC and IP and not in Kea DHCP reservation, add DHCP reservation in Kea
    if smd_ethernet_interfaces[smd_mac_address]['IPAddress'] != '' and smd_mac_address not in kea_ipv4_leases:
        # check for alias
        sls_hardware_url = 'http://cray-sls/v1/hardware/' + str(smd_ethernet_interfaces[smd_mac_address]['ComponentID']) + 'n0'
        print(sls_hardware_url)
        try:
            resp = requests.get(url=sls_hardware_url)
            resp.raise_for_status()
        except Exception as err:
            raise SystemExit(err)
        print(resp.json()['ExtraProperties']['Aliases'])
        # checking to see if its nmn ip, we will need to switch the name to nid instad of xname
        if resp.json()['ExtraProperties']['Aliases'] != '' and ipaddress.ip_address(smd_ethernet_interfaces[smd_mac_address]['IPAddress']) in ipaddress.ip_network(cn_nmn_cidr):
            smd_ethernet_interfaces[smd_mac_address]['ComponentID'] = resp.json()[0]['ExtraProperties']['Aliases']
        # convert mac format
        data['arguments']['hw-address'] = ':'.join(smd_mac_address[i:i+2] for i in range(0,12,2))
        data = {'command': 'lease4-update','service': 'dhcp4', 'arguments': {'ip-address': smd_ethernet_interfaces[smd_mac_address]['IPAddress'], 'hw-address': smd_mac_address, 'hostname':smd_ethernet_interfaces[smd_mac_address]['ComponentID'],'force-create': 'true'}}
        print(data)
        print('Found MAC and IP address pair from SMD and updating Kea with the record: {} {} {}'.format(smd_mac_address, smd_ethernet_interfaces[smd_mac_address]['IPAddress'], smd_ethernet_interfaces[smd_mac_address]['ComponentID'],))
        try:
            resp = requests.post(url=kea_api_endpoint, json=data, headers=kea_headers)
            resp.raise_for_status()
        except Exception as err:
            raise SystemExit(err)
        print(resp)
    # if IP Address is not present for a given mac address record in SMD, but Kea has a record with the MAC address and a non-empty IP, we can submit updates to SMD
    if smd_ethernet_interfaces[smd_mac_address]['IPAddress'] == '' and smd_mac_address in kea_ipv4_leases and kea_ipv4_leases[smd_mac_address]['ip-address'] != '':
        update_smd_url = 'http://cray-smd/hsm/v1/Inventory/EthernetInterfaces'
        data = {'MACAddress': smd_mac_address,'IPAddress': kea_ipv4_leases[smd_mac_address]['ip-address']}
        try:
            resp = requests.post(url=update_smd_url, json=data)
            resp.raise_for_status()
        except Exception as err:
            raise SystemExit(err)
