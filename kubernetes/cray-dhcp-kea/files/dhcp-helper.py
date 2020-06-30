#!/usr/bin/env python3

import requests
import json
import ipaddress
import time


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
# TODO fix job template load
#with open('cray_dhcp_kea_dhcp4.conf.template') as file:
#    cray_dhcp_kea_dhcp4 = json.loads(file.read())
#
# temp work around for job template load
cray_dhcp_kea_dhcp4 = json.loads('{"Dhcp4":{"control-socket":{"socket-name":"\/cray-dhcp-kea-socket\/cray-dhcp-kea.socket","socket-type":"unix"},"hooks-libraries":[{"library":"\/usr\/local\/lib\/kea\/hooks\/libdhcp_lease_cmds.so"},{"library":"\/usr\/local\/lib\/kea\/hooks\/libdhcp_stat_cmds.so"}],"interfaces-config":{"dhcp-socket-type":"raw","interfaces":["eth0"]},"lease-database":{},"host-reservation-identifiers":["circuit-id","hw-address","duid","client-id","flex-id"],"reservation-mode":"global","reservations":[],"subnet4":[],"valid-lifetime":120,"renew-timer":120,"rebind-timer":120}}')
# query sls for cabinet subnets
resp = requests.get(url='http://cray-sls/v1/search/hardware?type=comptype_cabinet')

# 1) ##############################################################################
#   a) Get network subnet and cabinet subnet info from SLS
# parse the response from cray-sls for subnet/cabinet network information
subnet4 = []
nmn_cidr = []
for i in range(len(resp.json())):
    for networks in resp.json()[i]['ExtraProperties']['Networks']:
        if networks != 'ncn':
            for system in resp.json()[i]['ExtraProperties']['Networks'][networks]:
#                print('networks ',networks)
#                print ("********debug***********", system)
                if system == 'NMN':
                    nmn_cidr.append(resp.json()[i]['ExtraProperties']['Networks'][networks][system]['CIDR'])
                subnet4_subnet = {}
                subnet4_subnet['pools'] = []
                subnet4_subnet['pools'].append({'pool': {}})
                subnet4_subnet['option-data'] = []
                network_cidr = resp.json()[i]['ExtraProperties']['Networks'][networks][system]['CIDR']
#                print('network cidr: ',network_cidr)
                gateway = resp.json()[i]['ExtraProperties']['Networks'][networks][system]['Gateway']
#                print('gateway: ',gateway)
                vlan = resp.json()[i]['ExtraProperties']['Networks'][networks][system]['VLan']
#                print ('vlan: ', vlan)
                network = ipaddress.ip_network(network_cidr)
                network_total_hosts = network.num_addresses
                network_pool_start = network[26]
                network_pool_end = network[network_total_hosts - 51]
#                print ('network', network)
#                print ('total hosts on network ',network_total_hosts)
#                print ('start',network_pool_start,' to ',network_pool_end)
                #create dictionary json for subnet
                subnet4_subnet['subnet'] = network_cidr
                subnet4_subnet['pools'][0]['pool'] = str(network_pool_start) + '-' + str(network_pool_end)
                subnet4_subnet['option-data'].append({'name': 'routers', 'data': gateway})
                subnet4_subnet['boot-file-name'] = 'ipxe.efi'
                if system == 'NMN':
                    subnet4_subnet['option-data'].append({'name': 'domain-name-servers', 'data': '10.92.100.225,10.254.0.4'})
                    subnet4_subnet['next-server'] = '10.92.100.60'
                if system == 'HMN':
                    subnet4_subnet['option-data'].append({'name': 'domain-name-servers', 'data': '10.94.100.225,10.254.0.4'})
                    subnet4_subnet['next-server'] = '10.94.100.60'
                subnet4.append(subnet4_subnet)
cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'].extend(subnet4)
#print(subnet4)

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
cray_dhcp_kea_dhcp4['Dhcp4']['lease-database'] = lease_database_info



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
# check to see if smd is aware of ips in kea
for mac_address, mac_details in kea_ipv4_leases.items():
#    print('checking mac_address', mac_address)
#    print('checking ip', mac_details['ip-address'])
    kea_ip = mac_details['ip-address']
    # TODO: pull all needed data down once instead of query smd for each ip
    update_smd_url = 'http://cray-smd/hsm/v1/Inventory/EthernetInterfaces?IPAddress=' + kea_ip
#    print(update_smd_url)
    try:
        resp = requests.get(url=update_smd_url)
        resp.raise_for_status()
    except Exception as err:
        raise SystemExit(err)
#    print(resp.json())
    if resp.json() == []:
        smd_mac_format = mac_address.replace(':', '')
        update_smd_url = 'http://cray-smd/hsm/v1/Inventory/EthernetInterfaces'
        post_data = {'MACAddress': smd_mac_format, 'IPAddress': kea_ip}
        resp = requests.post(url=update_smd_url, json=post_data)
#        print('adding mac',mac_address,'adding ip address',kea_ip)
#        print('update url', update_smd_url, ' with post data', post_data)
        if 200 not in resp:
#            print('we got an error posting, trying to patch instead')
            update_smd_url = 'http://cray-smd/hsm/v1/Inventory/EthernetInterfaces/' + smd_mac_format
            resp = requests.patch(url=update_smd_url, json=post_data)
#            print('response from patch', resp, ' ', resp.json())
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
    reservation = {}
    kea_mac_format = ''
    # if SMD has MAC and IP and not in Kea DHCP reservation, add DHCP reservation in Kea
    if smd_ethernet_interfaces[smd_mac_address]['IPAddress']:
        data = {}
        data['hostname'] = smd_ethernet_interfaces[smd_mac_address]['ComponentID']
        if smd_ethernet_interfaces[smd_mac_address]['Type'] == 'Node':
#            print("setting reservation for hostname/mac/ip %s",smd_ethernet_interfaces[smd_mac_address]['ComponentID'] )
            sls_hardware_url = 'http://cray-sls/v1/hardware/' + str(smd_ethernet_interfaces[smd_mac_address]['ComponentID'])
#            print(sls_hardware_url)
            resp = requests.get(url=sls_hardware_url)
        # checking to see if its nmn nic, we will need to switch the name to nid instead of xname
#            print('nmn network cidr', nmn_cidr)
            alias = {}
#            print(resp.json)
            if 'ExtraProperties' in resp.json():
#                print('extra properties exist')
                alias = resp.json()['ExtraProperties'].get('Aliases', {})
                if alias:
                    for cidr in nmn_cidr:
                        if ipaddress.IPv4Address(smd_ethernet_interfaces[smd_mac_address]['IPAddress']) in ipaddress.IPv4Network(cidr):
                            data['hostname'] = alias[0]
                            print('setting alias',json.dumps(data['hostname']))
        # check mac format
        colon_count = 0
        kea_mac_format = smd_mac_address
        for i in smd_mac_address:
            if i == ':':
                colon_count = colon_count + 1
        if colon_count == 0:
            kea_mac_format = ':'.join(smd_mac_address[i:i + 2] for i in range(0, 12, 2))
#        data['hostname'] = hostname
        data['hw-address'] = kea_mac_format
        data['ip-address'] = smd_ethernet_interfaces[smd_mac_address]['IPAddress']
#        print(data)
        # submit dhcp reservation with hostname, mac and ip
#        print('Found MAC and IP address pair from SMD and updating Kea with the record: {} {} {}'.format(smd_mac_address, smd_ethernet_interfaces[smd_mac_address]['IPAddress'], smd_ethernet_interfaces[smd_mac_address]['ComponentID'],))
        if data['hw-address'] != '' and data['ip-address'] != '' and data['hostname'] != '':
            dhcp_reservations.append(data)
    # checking to see if we need to do a nid hostname and mac reservation to make first nid boot work properly
    if smd_ethernet_interfaces[smd_mac_address]['Type'] == 'Node' and '1' in smd_ethernet_interfaces[smd_mac_address]['Description'] and smd_ethernet_interfaces[smd_mac_address]['IPAddress'] == '':
        data = {}
        print ('checking for hostname/mac reservation')
        data['hostname'] = smd_ethernet_interfaces[smd_mac_address]['ComponentID']
        if smd_ethernet_interfaces[smd_mac_address]['Type'] == 'Node':
#            print("setting reservation for hostname/mac/ip %s",smd_ethernet_interfaces[smd_mac_address]['ComponentID'] )
            sls_hardware_url = 'http://cray-sls/v1/hardware/' + str(smd_ethernet_interfaces[smd_mac_address]['ComponentID'])
#            print(sls_hardware_url)
            resp = requests.get(url=sls_hardware_url)
        # checking to see if its nmn ip, we will need to switch the name to nid instead of xname
            print('sls_hardware_url respond ',resp.json())
            alias = {}
            if '200' in str(resp.json()):
                alias = resp.json()['ExtraProperties'].get('Aliases', {})
            if alias and resp.json()['ExtraProperties']['Role'] == 'Compute':
                data['hostname'] = json.dumps(alias)
                print('setting alias for hostname/mac reservation', json.dumps(data['hostname']))
        colon_count = 0
        kea_mac_format = smd_mac_address
        for i in smd_mac_address:
            if i == ':':
                colon_count = colon_count + 1
        if colon_count == 0:
            kea_mac_format = ':'.join(smd_mac_address[i:i + 2] for i in range(0, 12, 2))
        else:
            kea_mac_format = smd_mac_address
        data['hw-address'] = kea_mac_format
        if data['hw-address'] != '' and data['hostname'] != '':
            dhcp_reservations.append(data)
    # if IP Address is not present for a given mac address record in SMD, but Kea has a record with the MAC address and a non-empty IP, we can submit updates to SMD
    if smd_ethernet_interfaces[smd_mac_address]['IPAddress'] == '' and smd_mac_address in kea_ipv4_leases and kea_ipv4_leases[smd_mac_address]['ip-address'] != '':
        update_smd_url = 'http://cray-smd/hsm/v1/Inventory/EthernetInterfaces'
        post_data = {'MACAddress': smd_mac_address, 'IPAddress': kea_ipv4_leases[smd_mac_address]['ip-address']}
        resp = requests.post(url=update_smd_url, json=post_data)
        if 200 not in resp:
#            print('we got an error posting, trying to patch instead')
            update_smd_url = 'http://cray-smd/hsm/v1/Inventory/EthernetInterfaces/' + smd_mac_format
            resp = requests.patch(url=update_smd_url, json=post_data)
#            print('response from patch', resp, ' ', resp.json())
cray_dhcp_kea_dhcp4['Dhcp4']['reservations'].extend(dhcp_reservations)
#print(json.dumps(cray_dhcp_kea_dhcp4))
cray_dhcp_kea_dhcp4_json = json.dumps(cray_dhcp_kea_dhcp4)

# lease wipe to clear out any potential funky state
data = {'command': 'lease4-get-all', 'service': ['dhcp4']}
kea_headers = {'Content-Type': 'application/json'}
kea_api_endpoint = 'http://cray-dhcp-kea-api:8000'
resp = requests.post(url=kea_api_endpoint, json=data, headers=kea_headers)

for lease in resp.json()[0]['arguments']['leases']:
#    print(lease)
    hw_address = lease['hw-address']
    ip_address = lease['ip-address']
    subnet_id = lease['subnet-id']
    for reservation in cray_dhcp_kea_dhcp4['Dhcp4']['reservations']:
#        print('checking ',hw_address,' with ',reservation['hw-address'])
        if hw_address == reservation['hw-address'] and ip_address != reservation['ip-address']:
            print ('we found a mis-match, deleting active lease',hw_address, ip_address, subnet_id)
            data = {'command': 'lease4-del', 'service': ['dhcp4'], 'arguments': {'hw-address': hw_address ,"ip-address": ip_address}}
            kea_headers = {'Content-Type': 'application/json'}
            kea_api_endpoint = 'http://cray-dhcp-kea-api:8000'
            resp = requests.post(url=kea_api_endpoint, json=data, headers=kea_headers)
#            print(resp.json())

# write config to disk
with open('/usr/local/kea/cray-dhcp-kea-dhcp4.conf', 'w') as outfile:
    json.dump(cray_dhcp_kea_dhcp4, outfile)

# reload config in kea from conf file written
data = {'command': 'config-reload', 'service': ['dhcp4']}
kea_headers = {'Content-Type': 'application/json'}
kea_api_endpoint = 'http://cray-dhcp-kea-api:8000'
try:
    resp = requests.post(url=kea_api_endpoint, json=data, headers=kea_headers)
    resp.raise_for_status()
except Exception as err:
    raise SystemExit(err)
print(resp.json())

#adding sleep delay
print ('waiting 10 seconds for any leases to be given out')
time.sleep(10)

# check active leases
data = {'command': 'lease4-get-all', 'service': ['dhcp4']}
kea_headers = {'Content-Type': 'application/json'}
kea_api_endpoint = 'http://cray-dhcp-kea-api:8000'
try:
    resp = requests.post(url=kea_api_endpoint, json=data, headers=kea_headers)
    resp.raise_for_status()
except Exception as err:
    raise SystemExit(err)
print(resp.json())