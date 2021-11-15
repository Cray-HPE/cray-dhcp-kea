#!/usr/bin/env python3

# Copyright 2014-2021 Hewlett Packard Enterprise Development LP

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import json
import ipaddress
import os
import sys
import socket
import shutil
from urllib.parse import urljoin
import logging
import datetime




class APIRequest(object):
    """

    Example use:
        api_request = APIRequest('http://api.com')
        response = api_request('GET', '/get/stuff')

        print (f"response.status_code")
        print (f"{response.status_code}")
        print()
        print (f"response.reason")
        print (f"{response.reason}")
        print()
        print (f"response.text")
        print (f"{response.text}")
        print()
        print (f"response.json")
        print (f"{response.json()}")
    """

    def __init__(self, base_url, headers=None):
        if not base_url.endswith('/'):
            base_url += '/'
        self._base_url = base_url

        if headers is not None:
            self._headers = headers
        else:
            self._headers = {}

    def __call__(self, method, route, **kwargs):

        if route.startswith('/'):
            route = route[1:]

        url = urljoin(self._base_url, route, allow_fragments=False)

        headers = kwargs.pop('headers', {})
        headers.update(self._headers)

        retry_strategy = Retry(
            total=10,
            backoff_factor=0.1,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["PATCH", "DELETE", "POST","HEAD", "GET", "OPTIONS"]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        http = requests.Session()
        http.mount("https://", adapter)
        http.mount("http://", adapter)

        response = http.request(method=method, url=url, headers=headers, **kwargs)

        if 'data' in kwargs:
            log.debug(f"{method} {url} with headers:"
                     f"{json.dumps(headers, indent=4)}"
                     f"and data:"
                     f"{json.dumps(kwargs['data'], indent=4)}")
        elif 'json' in kwargs:
            log.debug(f"{method} {url} with headers:"
                     f"{json.dumps(headers, indent=4)}"
                     f"and JSON:"
                     f"{json.dumps(kwargs['json'], indent=4)}")
        else:
            log.debug(f"{method} {url} with headers:"
                     f"{json.dumps(headers, indent=4)}")
        log.debug(f"Response to {method} {url} => {response.status_code} {response.reason}"
                 f"{response.text}")

        return response


def check_kea_api():
    kea_request_data = '{ "command": "status-get",  "service": [ "dhcp4" ] }'
    resp = kea_api('POST','/', headers=kea_headers, json=kea_request_data)

def import_base_config():
    with open('/srv/kea/cray-dhcp-kea-dhcp4.conf.template') as file:
        cray_dhcp_kea_dhcp4 = json.loads(file.read())
    cray_dhcp_kea_dhcp4['Dhcp4']['lease-database'] = {"type": "memfile", "name": "/cray-dhcp-kea-socket/dhcp4.leases",
                                                      "lfc-interval": 122}
    cray_dhcp_kea_dhcp4['Dhcp4']['valid-lifetime'] = 3600
    return cray_dhcp_kea_dhcp4

def get_time_servers(network):

    time_servers = ''

    # picking ncn-w00[1-3] to set as time servers
    for i in range(1, 4):
        lookup_in_unbound = True
        try:
            time_servers += socket.gethostbyname('ncn-w00' + str(i) + '.' + network)
            if i != 3:
                time_servers += ','
        except:
            log.warning(f'Did not get ip for ncn-w00{str(i)} from Unbound. '
                        f'Going to try looking for info in SLS')
            lookup_in_unbound = False
            # this will only be used if querying unbound failed
            if not lookup_in_unbound:
                alias = 'ncn-w00' + str(i)
                resp = sls_api('GET', '/v1/networks/' + network.upper())
                network_data = resp.json()
                if 'Subnets' in network_data['ExtraProperties'] and len(network_data['ExtraProperties']['Subnets']) > 0:
                    subnets = network_data['ExtraProperties']['Subnets']
                else:
                    break
                for j in range(len(subnets)):
                    # check to see if there are any IPRservations
                    if 'IPReservations' in subnets[j] and len(subnets[j]['IPReservations']) > 0:
                        ip_reservations = subnets[j]['IPReservations']
                    else:
                        break
                    for k in range(len(ip_reservations)):
                        if ip_reservations[k]['Name'] == alias:
                            time_servers += ip_reservations[k]['IPAddress']
                            if i != 3:
                                time_servers += ','

    # there are rare instances where we do not get all 3 time servers
    time_servers = time_servers.replace(',,', ',')
    log.debug(f'time servers  {time_servers}')

    return time_servers


def get_nmn_cidr(sls_networks):

    nmn_cidr = []

    for i in range(len(sls_networks)):
        if any(n in sls_networks[i]['Name'] for n in ('NMN','HMN','MTL','CAN', 'CHN', 'CMN')):
            if 'Subnets' in sls_networks[i]['ExtraProperties'] and sls_networks[i]['ExtraProperties']['Subnets']:
                for system in sls_networks[i]['ExtraProperties']['Subnets']:
                    if 'DHCPStart' in system and system['DHCPStart'] and 'DHCPEnd' in system and system['DHCPEnd']:
                        if 'NMN' in sls_networks[i]['Name']:
                            nmn_cidr.append(system['CIDR'])
    return nmn_cidr

def load_network_configs(cray_dhcp_kea_dhcp4, sls_networks, time_servers_nmn, time_servers_hmn):

    subnet4 = []

    for i in range(len(sls_networks)):
        if any(n in sls_networks[i]['Name'] for n in ('NMN','HMN','MTL','CAN', 'CHN', 'CMN')):
            if 'Subnets' in sls_networks[i]['ExtraProperties'] and sls_networks[i]['ExtraProperties']['Subnets']:
                for system in sls_networks[i]['ExtraProperties']['Subnets']:
                    if 'DHCPStart' in system and system['DHCPStart'] and 'DHCPEnd' in system and system['DHCPEnd']:
                        subnet4_subnet = {}
                        subnet4_subnet['pools'] = []
                        subnet4_subnet['pools'].append({'pool': {}})
                        subnet4_subnet['option-data'] = []
                        network_pool_start = system['DHCPStart']
                        network_pool_end = system['DHCPEnd']
                        log.debug(f'range {network_pool_start} to {network_pool_end}')
                        subnet4_subnet['pools'][0]['pool'] = '{}-{}'.format(network_pool_start, network_pool_end)
                        ip_network = ipaddress.ip_network(system['CIDR'], strict=False)
                        network_total_hosts = ip_network.num_addresses
                        log.debug(f'ip network: {ip_network}')
                        log.debug(f'total hosts on network:{network_total_hosts}')
                        subnet4_subnet['subnet'] = system['CIDR']
                        subnet4_subnet['option-data'].append({'name': 'routers', 'data': system['Gateway']})
                        subnet4_subnet['boot-file-name'] = 'ipxe.efi'
                        subnet4_subnet['id'] = system['VlanID']
                        subnet4_subnet['reservation-mode'] = 'all'
                        subnet4_subnet['reservations'] = []
                        if any(n in sls_networks[i]['Name'] for n in ('NMN','MTL','CAN')):
                            subnet4_subnet['option-data'].append({'name': 'dhcp-server-identifier', 'data': nmn_loadbalancer_ip })
                            subnet4_subnet['option-data'].append({'name': 'domain-name-servers', 'data': unbound_servers['NMN']})
                            subnet4_subnet['next-server'] = tftp_server_nmn
                            subnet4_subnet['option-data'].append({'name': 'time-servers', 'data': str(time_servers_nmn).strip('[]') })
                            subnet4_subnet['option-data'].append({'name': 'ntp-servers', 'data': str(time_servers_nmn).strip('[]') })
                        if 'HMN' in sls_networks[i]['Name']:
                            subnet4_subnet['option-data'].append({'name': 'dhcp-server-identifier', 'data': hmn_loadbalancer_ip})
                            subnet4_subnet['option-data'].append({'name': 'domain-name-servers','data': unbound_servers['HMN']})
                            subnet4_subnet['next-server'] = tftp_server_hmn
                            subnet4_subnet['option-data'].append({'name': 'time-servers', 'data': str(time_servers_hmn).strip('[]') })
                            subnet4_subnet['option-data'].append({'name': 'ntp-servers', 'data': str(time_servers_hmn).strip('[]') })
                        subnet4.append(subnet4_subnet)
    cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'].extend(subnet4)

    return cray_dhcp_kea_dhcp4


def get_kea_dhcp4_leases():
    kea_request_data = {'command': 'lease4-get-all', 'service': ['dhcp4']}
    resp = kea_api('POST', '/', headers=kea_headers, json=kea_request_data)

    return resp.json()


def create_index_kea_dhcp4_lease(kea_dhcp4_leases):
    kea_dhcp4_by_mac = {}
    for entry in kea_dhcp4_leases:
        kea_dhcp4_by_mac[entry['hw-address']] = entry


def get_sls_networks():
    # get information from SLS networks
    resp = sls_api('GET', '/v1/networks')

    return resp.json()


def get_sls_hardware():
    # getting information from SLS hardware info
    resp = sls_api('GET','/v1/hardware')

    return resp.json()


def create_index_sls_all_hardware(sls_hardware):
    sls_data_by_xname = {}
    for entry in sls_hardware:
        sls_data_by_xname[entry['Xname']] = entry

    return sls_data_by_xname


def get_smd_ethernet_interfaces():
    # getting information from SMD for all ethernetInterfaces
    resp = smd_api('GET', '/hsm/v2/Inventory/EthernetInterfaces')

    return resp.json()

def create_index_smd_ethernet_interfaces(smd_ethernet_interfaces):

    index_smd_ethernet_interfaces = {}

    for interface in smd_ethernet_interfaces:
        if 'MACAddress' in interface and interface['MACAddress'] != '':
            mac = interface['MACAddress']
            if mac != '' and ':' not in mac:
                mac = ':'.join(mac[i:i + 2] for i in range(0, 12, 2))
            index_smd_ethernet_interfaces[mac] = interface
    return index_smd_ethernet_interfaces

def all_ips_in_smd(smd_ethernet_interfaces):

    smd_ip_set = set()

    for record in smd_ethernet_interfaces:
        if record['IPAddresses'] != []:
            for ip in record['IPAddresses']:
                if ip['IPAddress'] not in smd_ip_set:
                    smd_ip_set.add(ip['IPAddress'])

    return smd_ip_set


def alias_to_xname_dict(sls_hardware):
    alias_to_xname = {}
    for sls_record in sls_hardware:
        xname = sls_record['Xname']
        if 'ExtraProperties' in sls_record:
            if 'Aliases' in sls_record['ExtraProperties'] and sls_record['ExtraProperties']['Aliases'][0] != '':
                log.info(f"SLS alias:{sls_record['ExtraProperties']['Aliases'][0]}")
                alias_to_xname[xname] = sls_record['ExtraProperties']['Aliases'][0]

    return alias_to_xname


def load_static_ncn_ips(sls_hardware):

    bss_host_records = {}

    # get ncn and ncn-bmc ip info
    resp = bss_api('GET', '/boot/v1/bootparameters?name=Global')
    bss_data = resp.json()
    if 'cloud-init' in bss_data[0]:
        if 'meta-data' in bss_data[0]['cloud-init']:
            if 'host-records' in bss_data[0]['cloud-init']['meta-data']:
                 bss_host_records = bss_data[0]['cloud-init']['meta-data']['host_records']    log.debug(f'bss_host_records')
        log.debug(f'{json.dumps(bss_host_records)}')
    ncn_data = {}
    alias_to_mac = {}
    alias_set = set()

    # sort bss data
    for record in bss_host_records:
        static_mac = ''
        log.debug(f'for record in bss_host_records.')
        log.debug(f'Record is: {record}')
        if any(n in record['aliases'][0] for n in ('-mgmt','.nmn', '.mtl', '.can', 'hmn')):
            split_aliases = ''
            log.debug(f'Record is: {record}')
            log.debug(f"record.split: {record['aliases'][0].split('.', 1)}")
            if '.' in record['aliases'][0]:
                split_aliases = record['aliases'][0].split('.', 1)
            if 'mgmt' in record['aliases'][0]:
                split_char = '-'
                count = 2
                temp_string = record['aliases'][0].split(split_char)
                split_aliases = split_char.join(temp_string[:count]), split_char.join(temp_string[count:])
            alias = split_aliases[0]
            alias_network = split_aliases[1]
            static_ip = record['ip']
            log.debug(f"Collecting IPs.  alias: {alias}, alias_network: {alias_network}, static_ip: {static_ip}")
            if alias_network == 'mgmt':
                if alias + 'bmc' not in alias_set:
                    ncn_data[alias + '_bmc'] = {}
                    alias_to_mac[alias + '_bmc'] = {}
                    alias_set.add(alias + 'bmc')
                ncn_data[alias + '_bmc'][alias_network] = static_ip
            else:
                if alias not in alias_set:
                    ncn_data[alias] = {}
                    alias_to_mac[alias] = {}
                    alias_set.add(alias)
                ncn_data[alias][alias_network] = static_ip
    log.info(f'ncn_data')
    log.info(f'{json.dumps(ncn_data)}')

    # get mac address info
    for alias in alias_to_mac:
        query_bss = True
        bond0_first_interface = ''
        static_mac = ''
        xname = ''
        xname_bmc = ''
        update_smd = True
        if 'bmc' not in alias:
            # get xname from alias
            for sls_record in sls_hardware:
                if 'ExtraProperties' in sls_record:
                    if 'Aliases' in sls_record['ExtraProperties'] and sls_record['ExtraProperties']['Aliases'][0] == alias:
                        xname = sls_record['Xname']
                        log.debug(f'Alias to xname found {alias} and {xname}')
                        # check description to see if kea has already loaded the data for NCN
                        resp = smd_api('GET','/hsm/v2/Inventory/EthernetInterfaces?ComponentID=' + xname)
                        smd_query = resp.json()
                        for i in range(len(smd_query)):
                            if 'kea' in smd_query[i]['Description']:
                                query_bss = False
                                update_smd = False

                        if query_bss:
                            resp = bss_api('GET', '/boot/v1/bootparameters?name=' + xname)
                            bss_params = resp.json()[0]['params'].split()
                            log.debug(f'bss_params:')
                            log.debug(f'{bss_params}')
                            for param in bss_params:
                                log.debug(f'param loop for first bond interface csm-1.0')
                                # csm-1.0
                                if 'bond=bond0' in param:
                                    log.debug(f'param: {param}')
                                    bond0_interfaces = param.split(':')
                                    log.debug(f'bond0_interfaces: {bond0_interfaces}')
                                    bond0_interfaces_split = bond0_interfaces[1].split(',')
                                    bond0_first_interface = bond0_interfaces_split[0]
                                    log.debug(f'bond0_first_interface:{bond0_first_interface}')
                            for param in bss_params:
                                log.debug(f'param loop for first bond interface MAC')
                                if 'ifname=' + bond0_first_interface in param:
                                        log.debug(f'{param}')
                                        temp_string = param.split(':', 1)
                                        static_mac = temp_string[1]
                                        log.debug(f'{bond0_first_interface_mac}')
                                        log.info(f'the data for NMN alias:{alias}, xname:{xname}, MAC:{static_mac}')
                                        break
                                # csm-1.2 and if we didn't find the first mac of bond0
                                # we assume the interface name is mgmt0
                                if bond0_first_interface == '' and static_mac == '':
                                    for param in bss_params:
                                        log.debug(f'param loop for first bond interface csm-1.2+')
                                        if 'ifname=mgmt0' in param:
                                            log.debug(f'param: {param}')
                                            interface_mgmt0 = param.split(':', 1)
                                            log.debug(f'bond0_interfaces: {interface_mgmt0}')
                                            bond0_first_interface_mac = interface_mgmt0[1]
                                            log.debug(f'bond0_first_interface_mac:{bond0_first_interface_mac}')
                                            static_mac = bond0_first_interface_mac
                                            log.info(f'found MAC:{static_mac} for alias:{alias}, xname:{xname}')
                                            alias_to_mac[alias] = static_mac
                                            break
            log.info(f'the data for NMN query_bss:{query_bss}alias:{alias}, xname:{xname}, MAC:{static_mac}')
        # skipping bmc for ncm-m001 due to not being on the shasta csm management network
        if 'bmc' in alias and 'ncn-m001' not in alias:
            # get xname from alias
            for sls_record in sls_hardware:
                if 'ExtraProperties' in sls_record:
                    if 'Aliases' in sls_record['ExtraProperties'] and sls_record['ExtraProperties']['Aliases'][0] == alias.strip('_bmc'):
                        xname_bmc = sls_record['Parent']
                        resp = smd_api('GET', 'hsm/v1/Inventory/EthernetInterfaces?ComponentID=' + xname_bmc)
                        smd_query = resp.json()
                        max_int = 0
                        for i in range(len(smd_query)):
                            if 'kea' in smd_query[i]['Description']:
                                update_smd = False
                        if update_smd:
                            for entry in smd_query:
                                if 'usb' not in entry['Description'].lower():
                                    hex_to_int = int(entry['ID'][-2:], 16)
                                    if hex_to_int > max_int:
                                        max_int = hex_to_int
                            for entry in smd_query:
                                hex_to_int = int(entry['ID'][-2:], 16)
                                if max_int == hex_to_int:
                                    static_mac = entry['MACAddress']
                                    log.info(f'found MAC:{static_mac} for alias:{alias}, xname:{xname_bmc}')
                                    alias_to_mac[alias] = static_mac
            log.info(f'the data for BMC alias:{alias}, xname:{xname_bmc}, MAC:{static_mac}')

    log.info(f'data from BSS sorted into two dictionaries:')
    log.info(f'{json.dumps(ncn_data)}')
    log.info(f'{json.dumps(alias_to_mac)}')

    # update smd
    for alias in ncn_data:
        update_smd = True
        patch_ip = []
        patch_mac = ''
        patch_description = ''
        if 'ncn-m001_bmc' not in alias:
            # making sure nmn is the first entry for nodes but not bmcs
            if 'bmc' not in alias:
                patch_ip.append({'IPAddress': ncn_data[alias]['nmn']})
            for network in ncn_data[alias]:
                # skip nmn ip address
                if network != 'nmn':
                    patch_ip.append({'IPAddress': ncn_data[alias][network]})
            patch_mac = alias_to_mac[alias]
            if patch_mac == {}:
                update_smd = False
            if update_smd:
                resp = smd_api('GET', 'hsm/v2/Inventory/EthernetInterfaces/' + patch_mac.replace(':', '').lower())
                log.info(f"static_mac stripped of colons {patch_mac.replace(':', '').lower()}")
                log.info(f'{len(resp.json())}')
                if 'kea' not in resp.json()['Description']:
                    if patch_mac != '' and resp.status_code == 200:
                            patch_description = resp.json()['Description'] + ' - kea'
                            log.info(f'Patch Data:')
                            log.info(f"MAC:{patch_mac}, IP:{patch_ip}")
                            log.info(
                                f"Patch URL: cray-smd/hsm/v2/Inventory/EthernetInterfaces/{patch_mac.replace(':', '')}")
                            patch_data = {'MACAddress':patch_mac,'Description': patch_description, 'IPAddresses': patch_ip}
                            resp = smd_api('PATCH', 'hsm/v2/Inventory/EthernetInterfaces/' + patch_mac.replace(':', ''),json=patch_data)
                            log.info(f"smd_api('PATCH', 'hsm/v2/Inventory/EthernetInterfaces/' + {patch_mac.replace(':', '')},json={json.dumps(patch_data)})")
                            log.info(f'{resp.json}')
                    else:
                            log.warning(f'Tried to update IP for alias:{alias}, patch_ip: {patch_ip} MAC:{patch_mac}')
                            log.warning(f"Entry already had IP: {resp.json()['IPAddress']}")
                    log.info(f'Patch data: alias:{alias}, patch_ip: {patch_ip} MAC:{patch_mac}, description: {patch_description}')

def compare_smd_kea_information(kea_dhcp4_leases, main_smd_ip_set):

    for record in kea_dhcp4_leases[0]['arguments']['leases']:
        log.debug(f'record in kea_dhcp4_leases[0]: '
                  f'{record}')
        entry_exist = False
        if record['ip-address'] not in main_smd_ip_set:
            smd_id = record['hw-address'].replace(':','')
            resp = smd_api('GET', '/hsm/v2/Inventory/EthernetInterfaces/' + smd_id)
            smd_entry = resp.json()
            if resp.status_code == 200:
                entry_exist = True
            if not entry_exist and smd_id != '':
                post_ip = [{'IPAddress': record['ip-address']}]
                post_mac = smd_id
                post_data = {'MACAddress': post_mac, 'IPAddresses': post_ip}
                resp = smd_api('POST','/hsm/v2/Inventory/EthernetInterfaces',json=post_data)
                log.info(f'Added {post_data}')

                if resp.status_code != 200:
                    log.error(f'Post to SMD EthernetInterfaces did not succeed')
                    log.error(f'status_code: {resp.status_code}')
                    log.error(f'{resp.json}')

            if entry_exist and smd_id != '':
                valid_patch_entry = True
                if 'IPAddresses' in smd_entry:
                    patch_ip = smd_entry['IPAddresses']
                else:
                    patch_ip = []
                patch_ip.append({'IPAddress': record['ip-address']})
                # check for any blank ips kv pairs
                for i in range(len(patch_ip)-1):
                    if 'IPAddress' in patch_ip[i] and patch_ip[i]['IPAddress'] == '':
                        del patch_ip[i]
                patch_mac = smd_id
                patch_data = {'IPAddresses': patch_ip}
                if smd_entry['Type'] == 'NodeBMC' and len(patch_ip) > 1:
                    valid_patch_entry = False
                    # working around known issue with BMCs set to static still DHCP
                    if len(patch_ip) > 1:
                        # delete active lease in kea
                        for i in range(len(patch_ip)-1):
                            if i != 0:
                                ip_delete = patch_ip[i]['IPAddress']
                                kea_lease4_delete = {'command': 'lease4-del', 'service': ['dhcp4'],
                                                     'arguments': {'ip-address': ip_delete}}
                                resp = kea_api('POST', '/', json=kea_lease4_delete, headers=kea_headers)
                                del patch_ip[i]
                        log.info(f'Attempting automated repair by removing extra ips')
                        valid_patch_entry = True
                if not valid_patch_entry and len(patch_ip) != 1:
                    log.error(f'Patch scenario is not correct.  Manual review recommended:'
                              f'{patch_mac} with {patch_data}')
                    valid_patch_entry = False
                if valid_patch_entry:
                    resp = smd_api('PATCH', '/hsm/v2/Inventory/EthernetInterfaces/' + patch_mac, json=patch_data)
                    log.info(f'Updated {patch_mac} with {patch_data}')

                    if resp.status_code != 200:
                        log.error(f'Patch to SMD EthernetInterfaces did not succeed')
                        log.error(f'status_code: {resp.status_code}')
                        log.error(f'{resp.json}')


def create_per_subnet_reservation(cray_dhcp_kea_dhcp4,smd_ethernet_interfaces, nmn_cidr, all_alias_to_xname, sls_hardware):

    # create dynamic set of sets
    list_of_subnet_sets = {}

    for i in range(len(cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'])):
        ip_var = 'ip_' + str(i)
        hostname_var = 'hostname_' + str(i)
        mac_var = 'mac_' + str(i)
        list_of_subnet_sets[ip_var] = set()
        list_of_subnet_sets[hostname_var] = set()
        list_of_subnet_sets[mac_var] = set()

    for record in smd_ethernet_interfaces:
        #subnet_index = ''
        dupe_ip = False
        dupe_hostname = False
        dupe_mac = False

        kea_ips = record.get('IPAddresses', [])
        kea_hostname = record.get('ComponentID', '')
        kea_mac = record.get('MACAddress', '')
        log.info(f'kea_ip:{kea_ips},kea_hostname:{kea_hostname},kea_mac:{kea_mac}')
        # check kea_mac format
        if kea_mac != '' and ':' not in kea_mac:
            kea_mac = ':'.join(kea_mac[i:i + 2] for i in range(0, 12, 2))

        if kea_ips == [] and kea_hostname != '' and kea_mac != '':
            if record['Type'] == 'Node' and all_alias_to_xname[kea_hostname] != '':
                if kea_hostname in all_alias_to_xname:
                    kea_hostname = all_alias_to_xname[kea_hostname]
                cray_dhcp_kea_dhcp4['Dhcp4']['reservations'].append({'hostname': kea_hostname,'hw-address': kea_mac})

        if kea_ips != [] and kea_hostname != '' and kea_mac != '':
            for ip in kea_ips:
                kea_ip = ip['IPAddress']
                if kea_ip == '':
                    break
                for i in range(len(cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'])):
                    if ipaddress.IPv4Address(kea_ip) in ipaddress.IPv4Network(cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['subnet'], strict=False):
                        if kea_ip in list_of_subnet_sets['ip_' + str(i)]:
                            dupe_ip = True
                            log.error(f"Dupe IP detected with: subnet {cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['subnet']} with "
                                      f"kea_hostname: {kea_hostname}, kea_mac: {kea_mac}, kea_hostname: {kea_hostname}")

                        if kea_hostname in list_of_subnet_sets['hostname_' + str(i)]:
                            log.warning(f'Possible node move or replacement.  Attempting automated repair')
                            dupe_hostname = True
                            log.info(f"URL: http://cray-smd/hsm/v1/Inventory/EthernetInterfaces?ComponentID={kea_hostname}")
                            resp = smd_api('GET', 'hsm/v1/Inventory/EthernetInterfaces?ComponentID=' + kea_hostname)
                            repair_data = resp.json()
                            for j in range(len(repair_data)-1):
                                if repair_data[j]['IPAddress'] == '':
                                    print('repair_data: Deleting entry with no ip')
                                    del repair_data[j]
                            print(repair_data)
                            # if length of repair data is not 2, we are unable to automatically fix the SMD data
                            if len(repair_data) != 2:
                                log.error(f'Automated repair failed')
                                log.error(
                                    f"Error duplicate hostname found in {cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['subnet']}")
                                log.error(f"ip: {kea_ip}, mac:{kea_mac}, hostname:{kea_hostname}")
                                break
                            else:
                                # getting the dates formated
                                date0 = datetime.datetime.fromisoformat(repair_data[0]['LastUpdate'][0:19])
                                date1 = datetime.datetime.fromisoformat(repair_data[1]['LastUpdate'][0:19])


                                if date0 < date1:
                                    log.debug(
                                        'URL: http://cray-smd/hsm/v1/Inventory/EthernetInterfaces?ComponentID=' +
                                        repair_data[0][
                                            'ID'])
                                    patch_data = {'IPAddress': ''}
                                    resp = smd_api('PATCH',
                                                   'hsm/v1/Inventory/EthernetInterfaces/' + repair_data[0]['ID'],
                                                   json=patch_data)
                                    log.debug(
                                        'URL: http://cray-smd/hsm/v1/Inventory/EthernetInterfaces?ComponentID=' +
                                        repair_data[1][
                                            'ID'])
                                    repair_ip = repair_data[0]['IPAddress']
                                    repair_mac = repair_data[0]['MACAddress']
                                    if ':' not in repair_mac:
                                        repair_mac = ':'.join(repair_mac[i:i + 2] for i in range(0, 12, 2))
                                    repair_component_id = kea_hostname
                                    patch_data = {'IPAddress': repair_ip}
                                    resp = smd_api('PATCH',
                                                   'hsm/v1/Inventory/EthernetInterfaces/' + repair_data[1]['ID'],
                                                   json=patch_data)

                                # move the old ip to the newer interface
                                # delete the ip in the older entry
                                if date1 < date0:
                                    log.debug(
                                        'URL: http://cray-smd/hsm/v1/Inventory/EthernetInterfaces?ComponentID=' +
                                        repair_data[1]['ID'])
                                    patch_data = {'IPAddress': ''}
                                    resp = smd_api('PATCH',
                                                   'hsm/v1/Inventory/EthernetInterfaces/' + repair_data[1]['ID'],
                                                   json=patch_data)
                                    log.debug(
                                        'URL: http://cray-smd/hsm/v1/Inventory/EthernetInterfaces?ComponentID=' +
                                        repair_data[0]['ID'])
                                    repair_ip = repair_data[1]['IPAddress']
                                    repair_mac = repair_data[1]['MACAddress']
                                    if ':' not in repair_mac:
                                        repair_mac = ':'.join(repair_mac[i:i + 2] for i in range(0, 12, 2))
                                    repair_component_id = kea_hostname
                                    patch_data = {'IPAddress': repair_ip}
                                    resp = smd_api('PATCH',
                                                   'hsm/v1/Inventory/EthernetInterfaces/' + repair_data[0]['ID'],
                                                   json=patch_data)

                                # delete active lease in kea
                                kea_lease4_delete = {'command': 'lease4-del', 'service': ['dhcp4'],
                                                     'arguments': {'ip-address': repair_ip}}
                                resp = kea_api('POST', '/', json=kea_lease4_delete, headers=kea_headers)

                                # update generated kea info
                                for j in range(len(cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['reservations'])):
                                    dhcp_reservation = cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['reservations'][j]
                                    if dhcp_reservation['hostname'] == repair_component_id:
                                        log.info(f'repair data is:')
                                        log.info(
                                            f'repair_component_id:{repair_component_id}, repair_mac: {repair_mac}, repair_ip:{repair_ip}')
                                        cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['reservations'][j]['hw-address'] = repair_mac
                                        cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['reservations'][j]['ip-address'] = repair_ip
                                        break
                                log.info(f'Automated repair successful')
                                dupe_hostname = False


                        if kea_ip in list_of_subnet_sets['ip_' + str(i)]:
                            log.error(
                                f"Dupe IP detected with: subnet {cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['subnet']} with "
                                f"kea_hostname: {kea_hostname}, kea_mac: {kea_mac}, kea_ip: {kea_ip}. "
                                f"Not adding to kea configs")
                            dupe_ip = True
                            break
                        if kea_mac in list_of_subnet_sets['mac_' + str(i)]:
                            log.error(
                                f"Dupe MAC detected with: subnet {cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['subnet']} with "
                                f"kea_hostname: {kea_hostname}, kea_mac: {kea_mac}, kea_hostname: {kea_hostname} "
                                f"Not adding to kea configs")
                            dupe_mac = True
                            break

                        if cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['subnet'] in nmn_cidr:
                            for cidr in nmn_cidr:
                                if ipaddress.IPv4Address(kea_ip) in ipaddress.IPv4Network(cidr, strict=False):
                                    if kea_hostname in all_alias_to_xname:
                                        kea_hostname = all_alias_to_xname[kea_hostname]



                        if not dupe_ip and not dupe_hostname and not dupe_mac:

                            if kea_ip != '' and kea_hostname != '' and kea_mac !='':
                                list_of_subnet_sets['ip_' + str(i)].add(kea_ip)
                                list_of_subnet_sets['hostname_' + str(i)].add(kea_hostname)
                                list_of_subnet_sets['mac_' + str(i)].add(kea_mac)
                                cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['reservations'].append({'hostname': kea_hostname,'hw-address': kea_mac, 'ip-address':kea_ip})

    return cray_dhcp_kea_dhcp4

def create_placeholder_leases(cray_dhcp_kea_dhcp4, kea_dhcp4_leases):

    place_holder_leases = []
    kea_active_ip_set = set()

    for lease in kea_dhcp4_leases[0]['arguments']['leases']:
        if lease['ip-address'] not in kea_active_ip_set:
            kea_active_ip_set.add(lease['ip-address'])


    for i in range(len(cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'])):
        for j in range(len(cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['reservations'])):
            place_holder_ip = cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['reservations'][j]['ip-address']
            place_holder_hostname = cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['reservations'][j]['hostname']
            place_holder_mac = cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['reservations'][j]['hw-address']
            if place_holder_ip not in kea_active_ip_set:
                place_holder_leases.append({'hostname': place_holder_hostname,'hw-address': place_holder_mac, 'ip-address':place_holder_ip})

    if len(place_holder_leases) > 0:
        for i in range(len(place_holder_leases)):
            kea_lease4_add_data = {'command': 'lease4-add', 'service': ['dhcp4'], 'arguments': {}}
            kea_lease4_add_data['arguments'] = place_holder_leases[i]
            log.debug(f'http post to kea api '
                      f'{kea_lease4_add_data}')
            resp = kea_api('POST', '/', json=kea_lease4_add_data, headers=kea_headers)

            if resp.status_code != 200 or resp.json()[0]['result'] != 0:
                log.warning(f'Placeholder lease creation failed'
                          f'{resp.json()[0]}')


def write_config(cray_dhcp_kea_dhcp4):
    # write config to disk
    with open('/usr/local/kea/cray-dhcp-kea-dhcp4.conf', 'w') as outfile:
        json.dump(cray_dhcp_kea_dhcp4, outfile)


def reload_config():
    # reload config in kea from conf file written
    kea_request_data = {'command': 'config-reload', 'service': ['dhcp4']}
    resp = kea_api('POST', '/', json=kea_request_data, headers=kea_headers)
    log.debug(f'logging config-reload '
              f'{resp.json()}')

    if resp.json()[0]['result'] != 0:
        log.error(f'Config reload failed '
                  f'Trying to load last known good config. '
                  f'{resp.json()}')
        shutil.copyfile(kea_path + '/cray-dhcp-kea-dhcp4.conf.bak', kea_path + '/cray-dhcp-kea-dhcp4.conf')
        # 2nd reload config in kea from last known good config
        keq_request_data = {'command': 'config-reload', 'service': ['dhcp4']}
        resp = kea_api('POST', '/', json=kea_request_data, headers=kea_headers)
        log.debug(f'logging config-reload '
                  f'{resp.json()}')
    else:
        # create backup copy of last known good kea config
        shutil.copyfile(kea_path + '/cray-dhcp-kea-dhcp4.conf', kea_path + '/cray-dhcp-kea-dhcp4.conf.bak')


# globbals
log = logging.getLogger(__name__)
log.setLevel(logging.WARNING)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
log.addHandler(handler)

# variables from env
tftp_server_nmn = os.environ['TFTP_SERVER_NMN']
tftp_server_hmn = os.environ['TFTP_SERVER_HMN']
unbound_servers = {}
unbound_servers['NMN'] = os.environ['UNBOUND_SERVER_NMN']
unbound_servers['HMN'] = os.environ['UNBOUND_SERVER_HMN']
hmn_loadbalancer_ip = os.environ['HMN_LOADBALANCER_IP']
nmn_loadbalancer_ip = os.environ['NMN_LOADBALANCER_IP']

# setup kea configs
kea_path = '/usr/local/kea'
kea_headers = {'Content-Type': 'application/json'}

# setup api urls
kea_api = APIRequest('http://cray-dhcp-kea-api:8000')
smd_api = APIRequest('http://cray-smd')
sls_api = APIRequest('http://cray-sls')
bss_api = APIRequest('http://cray-bss')


def main():

    # kea config
    cray_dhcp_kea_dhcp4 = {}
    nmn_cidr = []
    main_smd_ip_set = set()
    time_servers_nmn = ''
    time_servers_hmn = ''
    kea_dhcp4_leases = {}
    smd_ethernet_interfaces = {}
    all_alias_to_xname = {}

    # make sure kea api is up
    check_kea_api()

    # query SLS for network data
    sls_networks = get_sls_networks()

    # query SLS for hardware data
    sls_hardware = get_sls_hardware()

    # query SMD for EthernetInterfaces data
    smd_ethernet_interfaces = get_smd_ethernet_interfaces()

    # query Kea for dhcp4 leases
    kea_dhcp4_leases = get_kea_dhcp4_leases()

    # get templated base kea configs
    cray_dhcp_kea_dhcp4 = import_base_config()

    # get nmn cidr
    nmn_cidr = get_nmn_cidr(sls_networks)

    # get time servers
    time_servers_nmn = get_time_servers('nmn')
    time_servers_hmn = get_time_servers('hmn')

    # load SLS network data in Kea config
    cray_dhcp_kea_dhcp4 = load_network_configs(cray_dhcp_kea_dhcp4, sls_networks, time_servers_nmn, time_servers_hmn)

    # get all ips in SMD
    main_smd_ip_set = all_ips_in_smd(smd_ethernet_interfaces)

    # create alias to xname dictionary
    all_alias_to_xname = alias_to_xname_dict(sls_hardware)

    # check for any entries or ips kea has and update smd
    compare_smd_kea_information(kea_dhcp4_leases, main_smd_ip_set)

    # load bss cloud-init ncn data into SMD EthernetInterfaces
    load_static_ncn_ips(sls_hardware)

    # create per dhcp reservations per subnet
    cray_dhcp_kea_dhcp4 = create_per_subnet_reservation(cray_dhcp_kea_dhcp4,smd_ethernet_interfaces, nmn_cidr, all_alias_to_xname, sls_hardware)

    # write kea config to file
    write_config(cray_dhcp_kea_dhcp4)

    # reload kea config via api call
    reload_config()

    # create placeholder leases
    create_placeholder_leases(cray_dhcp_kea_dhcp4, kea_dhcp4_leases)

if __name__ == "__main__":
    main()