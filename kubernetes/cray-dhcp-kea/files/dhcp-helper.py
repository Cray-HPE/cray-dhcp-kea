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

# array for subnet4 for cabinet subnets
# [
#   {
#     "pools": {
#       "pool": "10.254.0.26-10.254.3.205"
#     },
#     "option-data": {
#       "name": "router",
#       "data": "10.254.0.1"
#     },
#     "subnet": "10.254.0.0/22"
#   }
# ]

# dhcp reservation array structure
# there will be two types of reservations.
# [
#     {
#         "hostname": "Joey-Jo-Jo-Junior-Shabadoo",
#         "hw-address": "1a:1b:1c:1d:1e:1f",
#         "ip-address": "192.0.2.201"
#     },
#     {
#        "hw-address": "01:11:22:33:44:55:66",
#        "hostname": "rodimus-prime"
#     }
# ]
dhcp_reservations = []

# import config template
with open('cray_dhcp_kea_dhcp4.conf') as file:
    cray_dhcp_kea_dhcp4 = json.loads(file.read())
# query sls for cabinet subnets
resp = requests.get(url='http://cray-sls/v1/search/hardware?type=comptype_cabinet')
# parse the response from cray-sls
subnet4 = []
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
    cn_network_pool_end = cn_network[cn_network_total_hosts -51]
    #create dictionary json for subnet
    subnet4_subnet['subnet'] = cn_network_cidr
    subnet4_subnet['pools']['pool'] = str(cn_network_pool_start) + '-' + str(cn_network_pool_end)
    subnet4_subnet['option-data']['name'] = 'router'
    subnet4_subnet['option-data']['data'] = cn_gateway
    subnet4.append(subnet4_subnet)
cray_dhcp_kea_dhcp4['arguments']['Dhcp4']['subnet4'].extend(subnet4)

# query cray-dhcp-kea for lease db info
data = {'command': 'config-get', 'service': ['dhcp4']}
kea_headers = {'Content-Type': 'application/json'}
kea_api_endpoint = 'http://cray-dhcp-kea-api:8000'
try:
    resp = requests.post(url=kea_api_endpoint, json=data, headers=kea_headers)
    resp.raise_for_status()
except Exception as err:
    raise SystemExit(err)
lease_database_info = resp.json()[0]['arguments']['Dhcp4']['lease-database']
cray_dhcp_kea_dhcp4['arguments']['Dhcp4']['lease-database'] = lease_database_info

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
#    print(smd_ethernet_interfaces[smd_mac_address])
    reservation = {}
    # if SMD has MAC and IP and not in Kea DHCP reservation, add DHCP reservation in Kea
    if smd_ethernet_interfaces[smd_mac_address]['IPAddress'] != '' and smd_mac_address not in kea_ipv4_leases:
        data = {}
        if smd_ethernet_interfaces[smd_mac_address]['ComponentID']:
            print("setting reservation for hostname/mac/ip %s",smd_ethernet_interfaces[smd_mac_address]['ComponentID'] )
            # check for alias
            if 'n0' in smd_ethernet_interfaces[smd_mac_address]['ComponentID']:
                sls_hardware_url = 'http://cray-sls/v1/hardware/' + str(smd_ethernet_interfaces[smd_mac_address]['ComponentID'])
            else:
                sls_hardware_url = 'http://cray-sls/v1/hardware/' + str(smd_ethernet_interfaces[smd_mac_address]['ComponentID']) + 'n0'
            print(sls_hardware_url)
            try:
                resp = requests.get(url=sls_hardware_url)
                resp.raise_for_status()
            except Exception as err:
                raise SystemExit(err)
        # checking to see if its nmn ip, we will need to switch the name to nid instead of xname
        if resp.json()['ExtraProperties']['Aliases'] != '' and ipaddress.ip_address(smd_ethernet_interfaces[smd_mac_address]['IPAddress']) in ipaddress.ip_network(cn_nmn_cidr):
            smd_ethernet_interfaces[smd_mac_address]['ComponentID'] = resp.json()[0]['ExtraProperties']['Aliases']
        # convert mac format
        data['hw-address'] = ':'.join(smd_mac_address[i:i+2] for i in range(0,12,2))
        data['ip-address'] = smd_ethernet_interfaces[smd_mac_address]['IPAddress']
        data = {"hostname": smd_ethernet_interfaces[smd_mac_address]['ComponentID'],'hw-address': smd_mac_address, 'ip-address': smd_ethernet_interfaces[smd_mac_address]['IPAddress']}
        print(data)
        # submit dhcp reservation with hostname, mac and ip
        print('Found MAC and IP address pair from SMD and updating Kea with the record: {} {} {}'.format(smd_mac_address, smd_ethernet_interfaces[smd_mac_address]['IPAddress'], smd_ethernet_interfaces[smd_mac_address]['ComponentID'],))
        if data['hw-address'] != '' and data['ip-address'] != '' and data['hostname'] != '':
            dhcp_reservations.append(data)
    if smd_ethernet_interfaces[smd_mac_address]['Type'] == 'Node' and '1' in smd_ethernet_interfaces[smd_mac_address]['Description'] and smd_ethernet_interfaces[smd_mac_address]['IPAddress'] is None:
        data = {}
        # submit dhcp reservation with only hostname and mac
        # check for alias
        print( "setting reservation for hostname/mac %s", smd_ethernet_interfaces[smd_mac_address]['ComponentID'])
        if smd_ethernet_interfaces[smd_mac_address]['ComponentID']:
            print("setting reservation for hostname/mac/ip")
            # check for alias
            if 'n0' in smd_ethernet_interfaces[smd_mac_address]['ComponentID']:
                sls_hardware_url = 'http://cray-sls/v1/hardware/' + str(smd_ethernet_interfaces[smd_mac_address]['ComponentID'])
            else:
                sls_hardware_url = 'http://cray-sls/v1/hardware/' + str(smd_ethernet_interfaces[smd_mac_address]['ComponentID']) + 'n0'
            resp = requests.get(url=sls_hardware_url)
        # checking to see if its nmn ip, we will need to switch the name to nid instead of xname
        if resp.json()['ExtraProperties']['Aliases'] != '' and '200' in resp:
            smd_ethernet_interfaces[smd_mac_address]['ComponentID'] = resp.json()['ExtraProperties']['Aliases']
        else:
            data['hostname'] = smd_ethernet_interfaces[smd_mac_address]['ComponentID']
        # convert mac format
        data['hw-address'] = smd_mac_address
#        data['hw-address'] = ':'.join(smd_mac_address[i:i+2] for i in range(0,12,2))
#        data['hostname'] = smd_ethernet_interfaces[smd_mac_address]['ComponentID']
        if data['hw-address'] != '' and data['hostname'] != '':
            dhcp_reservations.append(data)

    # if IP Address is not present for a given mac address record in SMD, but Kea has a record with the MAC address and a non-empty IP, we can submit updates to SMD
    if smd_ethernet_interfaces[smd_mac_address]['IPAddress'] == '' and smd_mac_address in kea_ipv4_leases and kea_ipv4_leases[smd_mac_address]['ip-address'] != '':
        update_smd_url = 'http://cray-smd/hsm/v1/Inventory/EthernetInterfaces'
        data = {'MACAddress': smd_mac_address, 'IPAddress': kea_ipv4_leases[smd_mac_address]['ip-address']}
        try:
            resp = requests.post(url=update_smd_url, json=data)
            resp.raise_for_status()
        except Exception as err:
            raise SystemExit(err)
cray_dhcp_kea_dhcp4['arguments']['Dhcp4']['reservations'].extend(dhcp_reservations)
print(json.dumps(cray_dhcp_kea_dhcp4))
cray_dhcp_kea_dhcp4_json = json.dumps(cray_dhcp_kea_dhcp4)

# send udpate to kea
kea_headers = {'Content-Type': 'application/json'}
kea_api_endpoint = 'http://cray-dhcp-kea-api:8000'
try:
    resp = requests.post(url=kea_api_endpoint, json=cray_dhcp_kea_dhcp4_json, headers=kea_headers)
    resp.raise_for_status()
except Exception as err:
    raise SystemExit(err)
# reload config
data = {'command': 'config-reload'}
kea_headers = {'Content-Type': 'application/json'}
kea_api_endpoint = 'http://cray-dhcp-kea-api:8000'
try:
    resp = requests.post(url=kea_api_endpoint, json=data, headers=kea_headers)
    resp.raise_for_status()
except Exception as err:
    raise SystemExit(err)