#!/usr/bin/env python3

import requests
import json
import ipaddress
import time
import os
import sys
import socket

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
#          "Role":"Compute"
#     }
# }

# dict for lease database information
# "lease-database": {
#    "host": "cray-dhcp-kea-postgres",
#    "name": "dhcp",
#    "password": "xxxxxxxxxxx",
#    "type": "postgresql",
#    "user": "dhcpdsuser"
# }

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

kea_api_endpoint = 'http://cray-dhcp-kea-api:8000'
kea_headers = {'Content-Type': 'application/json'}

def debug(title, out):
    if os.environ['DHCP_HELPER_DEBUG'] == 'true':
        print('********************* DEBUG **************************')
        print(title)
        print(out)
        print('******************************************************')

def on_error(err, exit=True):
    print('ERROR: {}'.format(err))
    if exit:
        sys.exit()

# import base config
cray_dhcp_kea_dhcp4 = {}
with open('/cray-dhcp-kea-dhcp4.conf.template') as file:
    cray_dhcp_kea_dhcp4 = json.loads(file.read())

# query sls for cabinet subnets
try:
    resp = requests.get(url='http://cray-sls/v1/search/hardware?type=comptype_cabinet')
    resp.raise_for_status()
except Exception as err:
    on_error(err)
sls_cabinets = resp.json()

# 1) ##############################################################################
#   a) Get network subnet and cabinet subnet info from SLS
# parse the response from cray-sls for subnet/cabinet network information
subnet4 = []
nmn_cidr = []
dns_masq_hostname = os.environ['DNS_MASQ_HOSTNAME']
dns_masq_servers = {}

# get dns masq server ip for nmn and hmn
# this needs to go away in 1.4!!!
system_name = ('nmn','hmn')
for name in system_name:
    ip = socket.gethostbyname(dns_masq_hostname + '-' + name)
    if ip == '':
        print('error getting dns masq ip for ',dns_masq_hostname + name)
    dns_masq_servers[name.upper()] = ip + ','
debug('this is the dns_masq_servesr:',dns_masq_servers)

debug('sls cabinet query response:', sls_cabinets)
for i in range(len(sls_cabinets)):
    if 'ExtraProperties' in sls_cabinets[i] and 'Networks' in sls_cabinets[i]['ExtraProperties']:
        for network_name in sls_cabinets[i]['ExtraProperties']['Networks']:
            dubplicate_cidr = False
            debug('network:', network_name)
            if sls_cabinets[i]['ExtraProperties']:
                network = sls_cabinets[i]['ExtraProperties']['Networks'][network_name]
                debug('network data:', network)
                for system_name in network:
                    debug('system:', system_name)
                    system = network[system_name]
                    debug('system data:', system)
                    # checking for duplciate network cidrs and exiting for loop
                    for subnet in subnet4:
                        debug("cidr ",system['CIDR'])
                        debug(" subnet is ",subnet['subnet'])
                        if system['CIDR'] == subnet['subnet']:
                            debug('duplicate subnet exiting', system['CIDR'])
                            dubplicate_cidr = True
                            break
                    # exiting for loop if duplicate network cidr
                    if dubplicate_cidr:
                        debug('duplicate cidr true and exiting',system['CIDR'])
                        break
                    if system_name == 'NMN':
                        nmn_cidr.append(system['CIDR'])
                    subnet4_subnet = {}
                    subnet4_subnet['pools'] = []
                    subnet4_subnet['pools'].append({'pool': {}})
                    subnet4_subnet['option-data'] = []
                    ip_network = ipaddress.ip_network(system['CIDR'],strict=False)
                    network_total_hosts = ip_network.num_addresses
                    network_pool_start = ip_network[26]
                    network_pool_end = ip_network[network_total_hosts - 51]
                    debug('ip network:', ip_network)
                    debug('total hosts on network:', network_total_hosts)
                    debug('range', '{} to {}'.format(network_pool_start, network_pool_end))
                    # create dictionary json for subnet
                    subnet4_subnet['subnet'] = system['CIDR']
                    subnet4_subnet['pools'][0]['pool'] = '{}-{}'.format(network_pool_start, network_pool_end)
                    subnet4_subnet['option-data'].append({'name': 'routers', 'data': system['Gateway']})
                    subnet4_subnet['boot-file-name'] = 'ipxe.efi'
                    if system_name == 'NMN':
                        subnet4_subnet['option-data'].append({'name': 'domain-name-servers', 'data': dns_masq_servers[system_name] + '10.92.100.225'})
                        subnet4_subnet['next-server'] = '10.92.100.60'
                    if system_name == 'HMN':
                        subnet4_subnet['option-data'].append({'name': 'domain-name-servers', 'data': dns_masq_servers[system_name] + '10.94.100.225'})
                        subnet4_subnet['next-server'] = '10.94.100.60'
                    subnet4.append(subnet4_subnet)
debug('subnet4:', subnet4)
cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'].extend(subnet4)

# query cray-dhcp-kea for lease db info
kea_request_data = {'command': 'config-get', 'service': ['dhcp4']}
try:
    resp = requests.post(url=kea_api_endpoint, json=kea_request_data, headers=kea_headers)
    resp.raise_for_status()
except Exception as err:
    on_error(err)

kea_get_config = resp.json()
debug('kea config-get response:', kea_get_config)
if len(kea_get_config) > 0:
    if 'arguments' in kea_get_config[0] and 'Dhcp4' in kea_get_config[0]['arguments'] and 'lease-database' in kea_get_config[0]['arguments']['Dhcp4']:
        lease_database_info = kea_get_config[0]['arguments']['Dhcp4']['lease-database']
        cray_dhcp_kea_dhcp4['Dhcp4']['lease-database'] = lease_database_info

#   a) Query Kea for DHCP leases, we'll just query the api
kea_request_data = {'command': 'lease4-get-all', 'service': ['dhcp4']}
try:
    resp = requests.post(url=kea_api_endpoint, json=kea_request_data, headers=kea_headers)
    resp.raise_for_status()
except Exception as err:
    on_error(err)
leases_response = resp.json()
debug('kea leases response:', leases_response)
if len(leases_response) > 0:
    if 'arguments' in leases_response[0] and 'leases' in leases_response[0]['arguments']:
        for lease in leases_response[0]['arguments']['leases']:
            if 'hw-address' in lease and lease['hw-address'] != '':
                kea_ipv4_leases[lease['hw-address']] = lease
debug('kea ipv4 leases:', kea_ipv4_leases)

# check to see if smd is aware of ips and macs in kea.  Potentially update SMD with new ethernet interfaces
for mac_address, mac_details in kea_ipv4_leases.items():
    kea_ip = mac_details['ip-address']
    smd_mac_format = mac_address.replace(':', '')
    search_smd_mac_resp = ''
    search_smd_ip_resp = ''

    # TODO: pull all needed data down once instead of query smd for each ip
    search_smd_mac_url = 'http://cray-smd/hsm/v1/Inventory/EthernetInterfaces?MACAddress={}'.format(smd_mac_format)
    try:
        search_smd_mac_resp = requests.get(url=search_smd_mac_url)
        if search_smd_mac_resp.status_code == 404:
            print('WARNING: Not found {}'.format(smd_mac_format))
        else:
            search_smd_mac_resp.raise_for_status()
    except Exception as err:
        on_error(err)
    # dupe ip check
    search_smd_ip_url = 'http://cray-smd/hsm/v1/Inventory/EthernetInterfaces?IPAddress={}'.format(kea_ip)
    try:
        search_smd_ip_resp = requests.get(url=search_smd_ip_url)
        if search_smd_ip_resp.status_code == 404:
            print('WARNING: Not found {}'.format(search_smd_ip_url))
        else:
            search_smd_ip_resp.raise_for_status()
    except Exception as err:
        on_error(err)

    # logging when detecting duplicate ips in SMD
    if len(search_smd_ip_resp.json()) > 0:
        print("we tried adding an a dupe ip for an new interface",)
        print(search_smd_ip_resp.json())

    if search_smd_mac_resp.json() == [] and search_smd_ip_resp.json() == []:
        update_smd_url = 'http://cray-smd/hsm/v1/Inventory/EthernetInterfaces'
        post_data = {'MACAddress': smd_mac_format, 'IPAddress': kea_ip}
        try:
            resp = requests.post(url=update_smd_url, json=post_data)
            resp.raise_for_status()
        except Exception as err:
            print('we got an error posting to SMD, trying to patch instead...')
            try:
                update_smd_url = 'http://cray-smd/hsm/v1/Inventory/EthernetInterfaces/{}'.format(smd_mac_format)
                resp = requests.patch(url=update_smd_url, json=post_data)
                resp.raise_for_status()
            except Exception as err:
                on_error(err)
#   b) Query SMD to get all network interfaces it knows about
try:
    resp = requests.get(url='http://cray-smd/hsm/v1/Inventory/EthernetInterfaces')
    resp.raise_for_status()
except Exception as err:
    on_error(err)
smd_ethernet_interfaces_response = resp.json()
debug('smd ethernet interfaces response:', smd_ethernet_interfaces_response)
for interface in smd_ethernet_interfaces_response:
    if 'MACAddress' in interface and interface['MACAddress'] != '':
        smd_ethernet_interfaces[interface['MACAddress']] = interface

#   c) Resolve the results from both SMD and Kea to synchronize both
for smd_mac_address in smd_ethernet_interfaces:
    reservation = {}
    kea_mac_format = ''
    data = {}
    if not 'ComponentID' in smd_ethernet_interfaces[smd_mac_address]:
        on_error('no ComponentID found in smd ethernet interface', exit=False)
        continue
    data['hostname'] = smd_ethernet_interfaces[smd_mac_address]['ComponentID']
    sls_hardware_url = 'http://cray-sls/v1/hardware/{}'.format(smd_ethernet_interfaces[smd_mac_address]['ComponentID'])
    debug('sls hardware url:', sls_hardware_url)
    try:
        resp = requests.get(url=sls_hardware_url)
        if resp.status_code == 404:
            print('WARNING: Not found {}'.format(sls_hardware_url))
        else:
            resp.raise_for_status()
    except Exception as err:
        on_error(err)
    sls_hardware_response = resp.json()
    # checking mac format
    if not ':' in smd_mac_address:
        kea_mac_format = ':'.join(smd_mac_address[i:i + 2] for i in range(0, 12, 2))
    else:
        kea_mac_format = smd_mac_address
    data['hw-address'] = kea_mac_format

    # setting ip address information
    if 'IPAddress' in smd_ethernet_interfaces[smd_mac_address] and smd_ethernet_interfaces[smd_mac_address]['IPAddress']:
        data['ip-address'] = smd_ethernet_interfaces[smd_mac_address]['IPAddress']

    # node checks for switching hostname to an alias
    if 'Type' in smd_ethernet_interfaces[smd_mac_address] and smd_ethernet_interfaces[smd_mac_address]['Type'] == 'Node':
        alias = {}
        if 'ExtraProperties' in sls_hardware_response:
            alias = sls_hardware_response['ExtraProperties'].get('Aliases', [])
            if len(alias) > 0:
                # checking to see if its nmn nic, we will need to switch the name to nid instead of xname
                if 'IPAddress' in smd_ethernet_interfaces[smd_mac_address] and smd_ethernet_interfaces[smd_mac_address]['IPAddress']:
                    for cidr in nmn_cidr:
                        if ipaddress.IPv4Address(smd_ethernet_interfaces[smd_mac_address]['IPAddress']) in ipaddress.IPv4Network(cidr, strict=False):
                            data['hostname'] = alias[0]
                            debug('setting alias as hostname for ip/mac/hostname reservation ', alias[0])
                # checking to see if we need to do a nid hostname and mac reservation to make first nid boot work properly
                if 'Description' in smd_ethernet_interfaces[smd_mac_address] and '1' in smd_ethernet_interfaces[smd_mac_address]['Description']:
                    if smd_ethernet_interfaces[smd_mac_address]['IPAddress'] == '':
                        if sls_hardware_response['ExtraProperties']['Role'] == 'Compute':
                            data['hostname'] = alias[0]
                            debug('setting alias as hostname', alias[0])
                        if data['hw-address'] != '' and data['hostname'] != '':
                            dhcp_reservations.append(data)
                            debug('setting alias dhcp reservation for mac/hostname', data)

    # submit dhcp reservation with hostname, mac and ip
    if 'ip-address' in data and data['hw-address'] != '' and data['ip-address'] != '' and data['hostname'] != '':
        dhcp_reservations.append(data)
        debug('setting dhcp reservation for ip/mac/hostname reservation', data)

    # checking smd for latest information on ethernet interface in SMD of known ethernet interfaces
    smd_mac_format = smd_mac_address.replace(':', '')
    smd_interface_ip = ''
    check_smd_url = 'http://cray-smd/hsm/v1/Inventory/EthernetInterfaces/{}'.format(smd_mac_format)
    try:
        resp = requests.get(url=check_smd_url)
        if resp.status_code == 404:
            print('WARNING: Not found {}'.format(check_smd_url))
        else:
            resp.raise_for_status()
    except Exception as err:
        on_error(err)
    if 'IPAddress' in resp.json():
        smd_interface_ip = resp.json()['IPAddress']
        debug('refresh to confirm ip being set', smd_interface_ip)


    # if we need to update SMD with IP address for ethernet interface
    if smd_mac_address in kea_ipv4_leases and 'ip-address' in kea_ipv4_leases[smd_mac_address] and smd_interface_ip == '':
        if (not 'IPAddress' in smd_ethernet_interfaces[smd_mac_address] or smd_ethernet_interfaces[smd_mac_address]['IPAddress'] == '') and kea_ipv4_leases[smd_mac_address]['ip-address'] != '':
            # dupe ip check
            search_smd_ip_resp = ''
            search_smd_ip_url = 'http://cray-smd/hsm/v1/Inventory/EthernetInterfaces?IPAddress={}'.format(kea_ipv4_leases[smd_mac_address]['ip-address'])
            try:
                search_smd_ip_resp = requests.get(url=search_smd_ip_url)
                if search_smd_ip_resp.status_code == 404:
                    print('WARNING: Not found {}'.format(search_smd_ip_url))
                else:
                    search_smd_ip_resp.raise_for_status()
            except Exception as err:
                on_error(err)
            if len(search_smd_ip_resp.json()) == 0:
                update_smd_url = 'http://cray-smd/hsm/v1/Inventory/EthernetInterfaces'
                post_data = {'MACAddress': smd_mac_address, 'IPAddress': kea_ipv4_leases[smd_mac_address]['ip-address']}
                try:
                    resp = requests.post(url=update_smd_url, json=post_data)
                    resp.raise_for_status()
                except Exception as err:
                    print('we got an error posting to SMD, trying to patch instead...')
                    try:
                        update_smd_url = 'http://cray-smd/hsm/v1/Inventory/EthernetInterfaces/{}'.format(smd_mac_format)
                        resp = requests.patch(url=update_smd_url, json=post_data)
                        resp.raise_for_status()
                    except Exception as err:
                        on_error(err)
            if len(search_smd_ip_resp.json()) > 0:
                print("we tried adding an a dupe ip in know interface")
                print(search_smd_ip_resp.json())
cray_dhcp_kea_dhcp4['Dhcp4']['reservations'].extend(dhcp_reservations)
cray_dhcp_kea_dhcp4_json = json.dumps(cray_dhcp_kea_dhcp4)
# logging kea config out
print(cray_dhcp_kea_dhcp4_json)

# lease wipe to clear out any potential funky state
if len(leases_response) > 0:
    if 'arguments' in leases_response[0] and 'leases' in leases_response[0]['arguments']:
        for lease in leases_response[0]['arguments']['leases']:
            hw_address = lease['hw-address']
            ip_address = lease['ip-address']
            subnet_id = lease['subnet-id']
            for reservation in cray_dhcp_kea_dhcp4['Dhcp4']['reservations']:
                if 'hw-address' in lease and lease['hw-address'] == reservation['hw-address']:
                    if 'ip-address' in lease and lease['ip-address'] != reservation['ip-address'] and 'subnet-id' in lease:
                        print ('we found a mis-match, deleting active lease', lease['hw-address'], lease['ip-address'], lease['subnet-id'])
                        data = {'command': 'lease4-del', 'service': ['dhcp4'], 'arguments': {'hw-address': lease['hw-address'], 'ip-address': lease['ip-address']}}
                        resp = requests.post(url=kea_api_endpoint, json=kea_request_data, headers=kea_headers)

# write config to disk
with open('/usr/local/kea/cray-dhcp-kea-dhcp4.conf', 'w') as outfile:
    json.dump(cray_dhcp_kea_dhcp4, outfile)

# reload config in kea from conf file written
keq_request_data = {'command': 'config-reload', 'service': ['dhcp4']}
try:
    resp = requests.post(url=kea_api_endpoint, json=keq_request_data, headers=kea_headers)
    resp.raise_for_status()
except Exception as err:
    on_error(err)
print(resp.json())

#adding sleep delay
print('waiting 10 seconds for any leases to be given out...')
time.sleep(10)

# check active leases
kea_request_data = {'command': 'lease4-get-all', 'service': ['dhcp4']}
try:
    resp = requests.post(url=kea_api_endpoint, json=kea_request_data, headers=kea_headers)
    resp.raise_for_status()
except Exception as err:
    on_error(err)
print(resp.json())