#!/usr/bin/env python3

# Copyright 2014-2020 Hewlett Packard Enterprise Development LP

import requests
import json
import ipaddress
import time
import os
import sys
import socket
import random
import dns.resolver
import dns.exception

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
global_dhcp_reservations = []

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

class DNSresponse:
    # data object for DNS answer response_full - full DNS response raw answer - DNS answer to the query
    def __init__(self, response_full=[], answer=[]):
        self.response_full = response_full
        self.answer = answer

class Nslookup:
    # Object for DNS resolver, init with optional specific DNS servers
    def __init__(self, dns_servers=[]):
        self.dns_resolver = dns.resolver.Resolver()

        if dns_servers:
            self.dns_resolver.nameservers = dns_servers

    def base_lookup(self, domain, record_type):
        # Get the DNS record, if any, for the given domain.
        # set DNS server for lookup
        try:
            # get the dns resolutions for this domain
            answer = self.dns_resolver.query(domain, record_type)
            return answer
        except dns.resolver.NXDOMAIN:
            # the domain does not exist so dns resolutions remain empty
            pass
        except dns.resolver.NoAnswer as e:
            debug("Warning: the DNS servers did not answer:", e)
        except dns.resolver.NoNameservers as e:
            debug("Warning: the nameservers did not answer:", e)
        except dns.exception.DNSException as e:
            debug("Error: DNS exception occurred:", e)

    def dns_lookup(self, domain):
        dns_answer = self.base_lookup(domain, 'A')
        if dns_answer:
            dns_response = [answer.to_text() for answer in dns_answer.response.answer]
            ips = [ip.address for ip in dns_answer]
            return DNSresponse(dns_response, ips)
        return DNSresponse()

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

# query sls for network subnets
try:
    resp = requests.get(url='http://cray-sls/v1/networks')
    resp.raise_for_status()
except Exception as err:
    on_error(err)
sls_networks = resp.json()

# 1) ##############################################################################
#   a) Get network subnet and cabinet subnet info from SLS
# parse the response from cray-sls for subnet/cabinet network information
subnet4 = []
nmn_cidr = []
dns_masq_servers = {}
unbound_servers = {}
tftp_server_nmn = os.environ['TFTP_SERVER_NMN']
tftp_server_hmn = os.environ['TFTP_SERVER_HMN']
unbound_servers['NMN'] = os.environ['UNBOUND_SERVER_HMN']
unbound_servers['HMN'] = os.environ['UNBOUND_SERVER_HMN']
dns_masq_hostname = os.environ['DNS_MASQ_HOSTNAME']
dnsmasq_running = False

# work with systems that have dnsmasqs and systems that do not
system_name = ('nmn','hmn')
for name in system_name:
    try:
        ip = socket.gethostbyname(dns_masq_hostname + '-' + name)
    except socket.error:
        ip =''
    debug('getting dhcp',unbound_servers)
    if ip != '':
        # checking connectivity of dnsmasq server
        check_resolver  = Nslookup(dns_servers=[ip])
        try:
            debug('querying name ',dns_masq_hostname + '-' + name + '.local')
            ips_record = check_resolver.dns_lookup(dns_masq_hostname + '-' + name + '.local')
            debug('lookup answer ',ips_record.answer[0])
            dns_masq_servers[name.upper()] = ips_record.answer[0] + ','
            dnsmasq_running = True
        except:
            dns_masq_servers[name.upper()] = ''
            debug('dnsmasq check failed', ip)
    else:
#        print ('^ NOT a critical error message on a Shasta 1.4')
        dns_masq_servers[name.upper()] = ''
    debug('this is the dns_masq_servesr:',dns_masq_hostname + '-' + name)


if not dnsmasq_running:
    for i in range(len(sls_networks)):
        if sls_networks[i]['Name'] == 'NMN' or sls_networks[i]['Name'] == 'HMN':
            if 'Subnets' in sls_networks[i]['ExtraProperties'] and sls_networks[i]['ExtraProperties']['Subnets']:
                for system in sls_networks[i]['ExtraProperties']['Subnets']:
                    if 'DHCPStart' in system and system['DHCPStart'] and 'DHCPEnd' in system and system['DHCPEnd']:
                        subnet4_subnet = {}
                        subnet4_subnet['pools'] = []
                        subnet4_subnet['pools'].append({'pool': {}})
                        subnet4_subnet['option-data'] = []
                        network_pool_start = system['DHCPStart']
                        network_pool_end = system['DHCPEnd']
                        debug('range', '{} to {}'.format(network_pool_start, network_pool_end))
                        subnet4_subnet['pools'][0]['pool'] = '{}-{}'.format(network_pool_start, network_pool_end)
                        ip_network = ipaddress.ip_network(system['CIDR'], strict=False)
                        network_total_hosts = ip_network.num_addresses
                        debug('ip network:', ip_network)
                        debug('total hosts on network:', network_total_hosts)
                        subnet4_subnet['subnet'] = system['CIDR']
                        subnet4_subnet['option-data'].append({'name': 'routers', 'data': system['Gateway']})
                        subnet4_subnet['boot-file-name'] = 'ipxe.efi'
                        subnet4_subnet['id'] = system['VlanID']
                        subnet4_subnet['reservation-mode'] = 'all'
                        subnet4_subnet['reservations'] = []
                        if sls_networks[i]['Name'] == 'NMN':
                            subnet4_subnet['option-data'].append({'name': 'domain-name-servers','data': unbound_servers['NMN']})
                            subnet4_subnet['next-server'] = tftp_server_nmn
                        if sls_networks[i]['Name'] == 'HMN':
                            subnet4_subnet['option-data'].append({'name': 'domain-name-servers','data': unbound_servers['HMN']})
                            subnet4_subnet['next-server'] = tftp_server_hmn
                        subnet4.append(subnet4_subnet)
    cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'].extend(subnet4)

    # loading static reservations
    static_reservations = []
    for i in range(len(sls_networks)):
        debug('length of SLS networks is',range(len(sls_networks)))
        if 'Subnets' in sls_networks[i]['ExtraProperties'] and sls_networks[i]['ExtraProperties']['Subnets']:
            debug('sls network subnet is', sls_networks[i]['ExtraProperties']['Subnets'])
            if 'IPReservations' in sls_networks[i]['ExtraProperties']['Subnets'][0] and sls_networks[i]['ExtraProperties']['Subnets'][0]['IPReservations']:
                ip_reservations = sls_networks[i]['ExtraProperties']['Subnets'][0]['IPReservations']
                for j in range(len(ip_reservations)):
                    debug ('static reservation data is:', ip_reservations[j])
                    # creating a random mac to create a place hold reservation
                    random_mac = ("00:00:00:%02x:%02x:%02x" % (
                    random.randint(0, 255),
                    random.randint(0, 255),
                    random.randint(0, 255),
                    ))
                    data = {'hostname': ip_reservations[j]['Name'], 'hw-address': random_mac, 'ip-address': ip_reservations[j]['IPAddress']}
                    static_reservations.append(data)
            debug ('static reservation data is',static_reservations)
    # loading static reservations into kea
    for i in range(len(static_reservations)):
        global_dhcp_reservations.append(static_reservations[i])
        for j in range(len(cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'])):
            debug('the subnet is ', cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][j])
            # loading per subnet
            if ipaddress.ip_address(static_reservations[i]['ip-address']) in ipaddress.ip_network(cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][j]['subnet'], strict=False):
                cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][j]['reservations'].append(static_reservations[i])
                break

# if system is running dnsmasq.  Shasta 1.3.x system
if dnsmasq_running:
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
                        network_pool_start = ip_network[51]
                        network_pool_end = ip_network[network_total_hosts - 51]
                        debug('ip network:', ip_network)
                        debug('total hosts on network:', network_total_hosts)
                        debug('range', '{} to {}'.format(network_pool_start, network_pool_end))
                        # create dictionary json for subnet
                        subnet4_subnet['subnet'] = system['CIDR']
                        subnet4_subnet['pools'][0]['pool'] = '{}-{}'.format(network_pool_start, network_pool_end)
                        subnet4_subnet['option-data'].append({'name': 'routers', 'data': system['Gateway']})
                        subnet4_subnet['boot-file-name'] = 'ipxe.efi'
                        subnet4_subnet['id'] = system['VLan']
                        subnet4_subnet['reservation-mode'] = 'all'
                        subnet4_subnet['reservations']= []
                        if system_name == 'NMN':
                            subnet4_subnet['option-data'].append({'name': 'domain-name-servers', 'data': dns_masq_servers[system_name] + unbound_servers[system_name]})
                            subnet4_subnet['next-server'] = tftp_server_nmn
                        if system_name == 'HMN':
                            subnet4_subnet['option-data'].append({'name': 'domain-name-servers', 'data': dns_masq_servers[system_name] + unbound_servers[system_name]})
                            subnet4_subnet['next-server'] = tftp_server_hmn
                        subnet4.append(subnet4_subnet)
    debug('subnet4:', subnet4)
    cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'].extend(subnet4)

# setup in memory db
cray_dhcp_kea_dhcp4['Dhcp4']['lease-database'] = { "type": "memfile", "name": "/cray-dhcp-kea-socket/dhcp4.leases","lfc-interval": 122 }
cray_dhcp_kea_dhcp4['Dhcp4']['valid-lifetime'] = 300

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

# getting information from SMD for all ethernetInterfaces
smd_all_ethernet_url = 'http://cray-smd/hsm/v1/Inventory/EthernetInterfaces'
debug('smd all ethernet url:', smd_all_ethernet_url)
try:
    smd_all_ethernet_resp = requests.get(url=smd_all_ethernet_url)
    smd_all_ethernet_resp.raise_for_status()
except Exception as err:
    on_error(err)
smd_all_ethernet = smd_all_ethernet_resp.json()
debug('1st pass of smd_all_ethernet_resp', smd_all_ethernet_resp)

found_new_interfaces = False
# check to see if smd is aware of ips and macs in kea.  Potentially update SMD with new ethernet interfaces
for mac_address, mac_details in kea_ipv4_leases.items():
    kea_hostname = mac_details['hostname']
    kea_ip = mac_details['ip-address']
    smd_mac_format = mac_address.replace(':', '')
    search_smd_mac_resp = ''
    search_smd_ip_resp = ''
    search_smd_ip = []
    search_smd_mac = []

    for i in range(len(smd_all_ethernet)):
        if smd_mac_format == smd_all_ethernet[i]['ID']:
            search_smd_ip.append(smd_all_ethernet_resp.json()[i])
        if kea_ip == smd_all_ethernet[i]['IPAddress']:
            search_smd_mac.append(smd_all_ethernet_resp.json()[i])
    # logging when detecting duplicate ips in SMD
    if len(search_smd_ip) > 0:
        debug('we tried adding an a dupe ip for an new interface {} {}'.format(search_smd_mac,search_smd_ip),kea_hostname)

    if search_smd_mac == [] and search_smd_ip == []:
        # double check duplicate ip check
        search_smd_ip_url = 'http://cray-smd/hsm/v1/Inventory/EthernetInterfaces?IPAddress={}'.format(kea_ip)
        try:
            search_smd_ip_resp = requests.get(url=search_smd_ip_url)
            if search_smd_ip_resp.status_code == 404:
                print('WARNING: Not found {}'.format(search_smd_ip_url))
            else:
                search_smd_ip_resp.raise_for_status()
        except Exception as err:
            on_error(err)
        # we update SMD only if ip doesn't exist
        if search_smd_ip_resp.json() == []:
            found_new_interfaces = True
            update_smd_url = 'http://cray-smd/hsm/v1/Inventory/EthernetInterfaces'
            post_data = {'MACAddress': smd_mac_format, 'IPAddress': kea_ip}
            print ('updating SMD with {}'.format(post_data))
            try:
                resp = requests.post(url=update_smd_url, json=post_data)
                resp.raise_for_status()
            except Exception as err:
                on_error(err)
#   b) Query SMD to get all network interfaces it knows about
# refresh SMD ethernet interface data after if dhcp-helper posted an update to SMD
if found_new_interfaces:
    try:
        resp = requests.get(url='http://cray-smd/hsm/v1/Inventory/EthernetInterfaces')
        resp.raise_for_status()
    except Exception as err:
        on_error(err)
    smd_all_ethernet = resp.json()

debug('found_new_interfaces is',found_new_interfaces)
debug('2nd pass smd ethernet interfaces response:', smd_all_ethernet)
for interface in smd_all_ethernet:
    if 'MACAddress' in interface and interface['MACAddress'] != '':
        smd_all_ethernet[interface['MACAddress']] = interface

#   c) Resolve the results from both SMD and Kea to synchronize both
# get all hardware info from SLS
sls_all_hardware_url = 'http://cray-sls/v1/hardware'
debug('sls all hardware url:', sls_all_hardware_url)
try:
    resp = requests.get(url=sls_all_hardware_url)
    resp.raise_for_status()
except Exception as err:
    on_error(err)
sls_all_hardware = resp.json()
for smd_mac_address in smd_ethernet_interfaces:
    reservation = {}
    kea_mac_format = ''
    data = {}
    smd_interface_ip = ''

    if not 'ComponentID' in smd_ethernet_interfaces[smd_mac_address]:
        on_error('no ComponentID found in smd ethernet interface', exit=False)
        continue
    data['hostname'] = smd_ethernet_interfaces[smd_mac_address]['ComponentID']
    if not ':' in smd_mac_address:
        kea_mac_format = ':'.join(smd_mac_address[i:i + 2] for i in range(0, 12, 2))
    else:
        kea_mac_format = smd_mac_address
    data['hw-address'] = kea_mac_format
    # setting ip address information
    if 'IPAddress' in smd_ethernet_interfaces[smd_mac_address] and smd_ethernet_interfaces[smd_mac_address]['IPAddress']:
        data['ip-address'] = smd_interface_ip = smd_ethernet_interfaces[smd_mac_address]['IPAddress']
    # checking SLS hardware info
    for i in range(len(sls_all_hardware)):
        if smd_ethernet_interfaces[smd_mac_address]['ComponentID'] == sls_all_hardware[i]['Xname']:
            # node checks for switching hostname to an alias
            if 'Type' in smd_ethernet_interfaces[smd_mac_address] and smd_ethernet_interfaces[smd_mac_address]['Type'] == 'Node':
                alias = {}
                if 'ExtraProperties' in sls_all_hardware[i]:
                    alias = sls_all_hardware[i]['ExtraProperties'].get('Aliases', [])
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
                                if sls_all_hardware[i]['ExtraProperties']['Role'] == 'Compute':
                                    data['hostname'] = alias[0]
                                    debug('setting alias as hostname', alias[0])
                                if data['hw-address'] != '' and data['hostname'] != '':
                                    global_dhcp_reservations.append(data)
                                    debug('setting alias dhcp reservation for mac/hostname', data)

    # submit dhcp reservation with hostname, mac and ip
    if 'ip-address' in data and data['hw-address'] != '' and data['ip-address'] != '' and data['hostname'] != '':
        # retaining the original dhcp reservation structure
        global_dhcp_reservations.append(data)
        # setting dhcp reservation under the subnet the reservation should be part of based on ip
        for i in range(len(cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'])):
            debug('the subnet is ', cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i])
            if ipaddress.ip_address(data['ip-address']) in ipaddress.ip_network(cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['subnet'],strict=False):
                cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['reservations'].append(data)
                break
        debug('setting dhcp reservation for ip/mac/hostname reservation', data)
        # we are checking reserved IP/MAC/Hostname as an active lease in kea
        kea_lease4_get_data = {'command': 'lease4-get', 'service': ['dhcp4'],"arguments": { "ip-address": data['ip-address'] }}
        try:
            resp = requests.post(url=kea_api_endpoint, json=kea_lease4_get_data, headers=kea_headers)
            resp.raise_for_status()
        except Exception as err:
            on_error(err)
        # checking for dhcp reservation with an active lease doesn't come back with result=0
        if (resp.json()[0]['result'] != 0):
            kea_lease4_add_data = {'command': 'lease4-add', 'service': ['dhcp4'],"arguments": { "hostname": data['hostname'], "hw-address": data['hw-address'],"ip-address": data['ip-address'] }}
            try:
                resp = requests.post(url=kea_api_endpoint, json=kea_lease4_add_data, headers=kea_headers)
                resp.raise_for_status()
            except Exception as err:
                on_error(err)


    # 2nd update scenario for updating SMD with IP address for ethernet interface
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
                smd_mac_format = smd_mac_address.replace(':', '')
                update_smd_url = 'http://cray-smd/hsm/v1/Inventory/EthernetInterfaces'
                patch_data = {'MACAddress': smd_mac_address, 'IPAddress': kea_ipv4_leases[smd_mac_address]['ip-address']}
                print('updating SMD with {}'.format(patch_data))
                try:
                    update_smd_url = 'http://cray-smd/hsm/v1/Inventory/EthernetInterfaces/{}'.format(smd_mac_format)
                    resp = requests.patch(url=update_smd_url, json=patch_data)
                    resp.raise_for_status()
                except Exception as err:
                    on_error(err)
            if len(search_smd_ip_resp.json()) > 0:
                print("we tried adding an a dupe ip in known interface")
                print(search_smd_ip_resp.json())

cray_dhcp_kea_dhcp4['Dhcp4']['reservations'].extend(global_dhcp_reservations)
cray_dhcp_kea_dhcp4_json = json.dumps(cray_dhcp_kea_dhcp4)
# logging kea config out
debug("kea config",cray_dhcp_kea_dhcp4_json)

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
debug("logging config-reload",resp.json())

if os.environ['DHCP_HELPER_DEBUG'] == 'true':
    # adding sleep delay during debug mode
    print('waiting 10 seconds for any leases to be given out...')
    time.sleep(10)

# check active leases
kea_request_data = {'command': 'lease4-get-all', 'service': ['dhcp4']}
try:
    resp = requests.post(url=kea_api_endpoint, json=kea_request_data, headers=kea_headers)
    resp.raise_for_status()
except Exception as err:
    on_error(err)
debug("logging active leases",resp.json())