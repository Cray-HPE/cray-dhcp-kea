#!/usr/bin/env python3

# Copyright 2014-2022 Hewlett Packard Enterprise Development LP
"""
This is automation to coordinate data between kea, smd and sls
"""

import sys
import socket
import shutil
from urllib.parse import urljoin
import logging
import datetime
import ipaddress
import json
import os
import time
import requests
import yaml
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from manuf import manuf
import argparse
import subprocess
import codecs
import gzip
import base64


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
            total=3,
            backoff_factor=0.1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["PATCH", "DELETE", "POST", "HEAD", "GET", "OPTIONS"]
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
    """
    Checking kea api on startup and waiting till kea api is online
    """
    kea_api_online = False
    counter = 0
    kea_request_lease_data = {"command": "lease4-get-all", "service": ["dhcp4"]}
    kea_reload_config = {"command": "config-reload", "service": ["dhcp4"]}

    while not kea_api_online and counter <= 3:
        resp = kea_api('POST', '/', headers=kea_headers, json=kea_request_lease_data)
        kea_api_resp = resp.json()[0]['result']
        if kea_api_resp == 0 or kea_api_resp == 3:
            kea_api_online = True
        else:
            resp = kea_api('POST', '/', headers=kea_headers, json=kea_reload_config)
            log.debug('Kea config reload during API check response is:'
                      f'{resp.json()}')
            counter += 1
            time.sleep(5)

    if not kea_api_online and counter >= 3:
        log.error('Kea API is not working as expected.')
        sys.exit(1)

    log.info('Kea API is working as expected.')


def get_ipxe_boot_filename(ipxe_settings_file):
    '''
    Get ipxe boot file name from cray-ipxe-settings configmap data
    :return:
    '''

    ipxe_filename = {}
    ipxe_settings = {}
    settings_file_exist = True

    try:
        with open(ipxe_settings_file, "r") as file:
            ipxe_settings = yaml.safe_load(file)
    except IOError:
        settings_file_exist = False
        log.error(f'Not able to load {ipxe_settings_file}')

    ipxe_filename['ipxe'] = ipxe_settings.get('cray_ipxe_binary_name', '')
    ipxe_filename['ipxe_debug'] = ipxe_settings.get('cray_ipxe_debug_binary_name', '')
    ipxe_filename['ipxe_aarch64'] = ipxe_settings.get('cray_ipxe_aarch64_binary_name', '')
    ipxe_filename['ipxe_aarch64_debug'] = ipxe_settings.get('cray_ipxe_aarch64_debug_binary_name', '')

    # fall back to default ipxe filename if no ipxe filename provided
    if not settings_file_exist or ipxe_filename == '':
        ipxe_filename['ipxe'] = os.environ['IPXE_DEFAULT_FILENAME']
        ipxe_filename['ipxe_debug'] = os.environ['IPXE_DEBUG_DEFAULT_FILENAME']

    return ipxe_filename


def import_base_config(ipxe_settings_file):
    """
    importing kea config template and setting lease-database and default lease time
    :return:
    """
    ipxe_filename = get_ipxe_boot_filename(ipxe_settings_file)

    with open('/srv/kea/cray-dhcp-kea-dhcp4.conf.template', encoding="utf-8") as file:
        cray_dhcp_kea_dhcp4 = json.loads(file.read())

    cray_dhcp_kea_dhcp4['Dhcp4']['lease-database'] = \
        {"type": "memfile", "name": "/cray-dhcp-kea-socket/dhcp4.leases",
         "lfc-interval": 122}

    cray_dhcp_kea_dhcp4['Dhcp4']['valid-lifetime'] = 3600

    client_classes = { "client-classes": [
        {
         'name': 'ipxe_x86_64_efi',
         'test': 'option[93].hex == 0x0007',
         'boot-file-name': ipxe_filename['ipxe'],
        },
        {
         'name': 'ipxe_arm64_efi',
         'test': 'option[93].hex == 0x000b',
         'boot-file-name': ipxe_filename['ipxe_aarch64'],
        },
      ]
    }
    cray_dhcp_kea_dhcp4['Dhcp4']['client-classes'] = client_classes['client-classes']

    return cray_dhcp_kea_dhcp4


def get_time_servers(network):
    """
    Get time and ntp server ips.
    The logic is to use the workers 1-3 since that is the smallest worker size possible.
    :param network:
    :return:
    """

    time_servers = ''

    # picking ncn-w00[1-3] to set as time servers
    # ncn-w00[1-3] is used since that is the smallest number of workers we support for a system
    for i in range(1, 4):
        lookup_in_unbound = True
        try:
            time_servers += socket.gethostbyname('ncn-w00' + str(i) + '-' + network)
            if i != 3:
                time_servers += ','
        except:
            log.warning(f'Did not get ip for ncn-w00{str(i)} from Unbound. '
                        f'Going to try looking for info in SLS')
            lookup_in_unbound = False
            # this will only be used if querying unbound failed
            # get information from SLS /v1/networks/
            if not lookup_in_unbound:
                alias = 'ncn-w00' + str(i)
                resp = sls_api('GET', '/v1/networks/' + network.upper())
                network_data = resp.json()
                if 'Subnets' in network_data['ExtraProperties'] and \
                        len(network_data['ExtraProperties']['Subnets']) > 0:
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
    """
    Collect all the NMN network cidrs
    :param sls_networks:
    :return:
    """

    nmn_cidr = []

    # dynamically collecting NMN CIDRS since we have special handling for computes and UANs
    for i in range(len(sls_networks)):
        if any(n in sls_networks[i]['Name'] for n in ('NMN', 'HMN', 'MTL', 'CAN', 'CHN', 'CMN')):
            if 'Subnets' in sls_networks[i]['ExtraProperties'] and \
                    sls_networks[i]['ExtraProperties']['Subnets']:
                for system in sls_networks[i]['ExtraProperties']['Subnets']:
                    if 'DHCPStart' in system and system['DHCPStart'] and \
                            'DHCPEnd' in system and system['DHCPEnd']:
                        if 'NMN' in sls_networks[i]['Name']:
                            nmn_cidr.append(system['CIDR'])
    return nmn_cidr


def get_black_list_cidr(sls_networks, black_list_network_names):
    """
    Get a list of network cidrs we do not want to create dyanmic dhcp reservations for.
    :param sls_networks:
    :param black_list_network_names:
    :return:
    """
    black_list_cidr = []

    # primarly the list of interfaces for NCNs and potentially other interfaces we want to set static IPs to
    for i in range(len(sls_networks)):
        if any(n in sls_networks[i]['Name']
               for n in ('MTL', 'CAN', 'CHN', 'CMN')):
            if 'Subnets' in sls_networks[i]['ExtraProperties'] and \
                    sls_networks[i]['ExtraProperties']['Subnets']:
                for system in sls_networks[i]['ExtraProperties']['Subnets']:
                    if 'DHCPStart' in system and system['DHCPStart'] and \
                            'DHCPEnd' in system and system['DHCPEnd']:
                        for black_list_network_name in black_list_network_names:
                            if black_list_network_name in sls_networks[i]['Name']:
                                black_list_cidr.append(system['CIDR'])
    return black_list_cidr


def load_network_configs(cray_dhcp_kea_dhcp4, sls_networks, time_servers_nmn, time_servers_hmn, ipxe_boot_filename):
    """
    Load network data from SLS
    :param cray_dhcp_kea_dhcp4:
    :param sls_networks:
    :param time_servers_nmn:
    :param time_servers_hmn:
    :return:
    """

    subnet4 = []

    for i in range(len(sls_networks)):
        if any(n in sls_networks[i]['Name']
               for n in ('NMN', 'HMN', 'MTL', 'CAN', 'CHN', 'CMN')):
            if 'Subnets' in sls_networks[i]['ExtraProperties'] \
                    and sls_networks[i]['ExtraProperties']['Subnets']:
                for system in sls_networks[i]['ExtraProperties']['Subnets']:
                    if 'DHCPStart' in system and system['DHCPStart'] \
                            and 'DHCPEnd' in system and system['DHCPEnd']:
                        subnet4_subnet = {}
                        subnet4_subnet['pools'] = []
                        subnet4_subnet['pools'].append({'pool': {}})
                        subnet4_subnet['option-data'] = []
                        network_pool_start = system['DHCPStart']
                        network_pool_end = system['DHCPEnd']
                        log.debug(f'range {network_pool_start} to {network_pool_end}')
                        subnet4_subnet['pools'][0]['pool'] = '{}-{}'.format(
                            network_pool_start, network_pool_end)
                        ip_network = ipaddress.ip_network(system['CIDR'], strict=False)
                        network_total_hosts = ip_network.num_addresses
                        log.debug(f'ip network: {ip_network}')
                        log.debug(f'total hosts on network:{network_total_hosts}')
                        subnet4_subnet['subnet'] = system['CIDR']
                        subnet4_subnet['option-data'].append({'name': 'routers',
                                                              'data': system['Gateway']})
                        subnet4_subnet['id'] = system['VlanID']
                        subnet4_subnet['reservation-mode'] = 'all'
                        subnet4_subnet['reservations'] = []
                        if any(n in sls_networks[i]['Name'] for n in ('NMN', 'MTL', 'CAN')):
                            subnet4_subnet['option-data'].append(
                                {'name': 'dhcp-server-identifier', 'data': nmn_loadbalancer_ip})
                            subnet4_subnet['option-data'].append(
                                {'name': 'domain-name-servers', 'data': unbound_servers['NMN']})
                            subnet4_subnet['next-server'] = tftp_server_nmn
                            subnet4_subnet['option-data'].append(
                                {'name': 'time-servers', 'data': str(
                                    time_servers_nmn).strip('[]')})
                            subnet4_subnet['option-data'].append(
                                {'name': 'ntp-servers', 'data': str(time_servers_nmn).strip('[]')})
                        if 'HMN' in sls_networks[i]['Name']:
                            subnet4_subnet['option-data'].append(
                                {'name': 'dhcp-server-identifier', 'data': hmn_loadbalancer_ip})
                            subnet4_subnet['option-data'].append(
                                {'name': 'domain-name-servers', 'data': unbound_servers['HMN']})
                            subnet4_subnet['next-server'] = tftp_server_hmn
                            subnet4_subnet['option-data'].append(
                                {'name': 'time-servers', 'data': str(
                                    time_servers_hmn).strip('[]')})
                            subnet4_subnet['option-data'].append(
                                {'name': 'ntp-servers', 'data': str(time_servers_hmn).strip('[]')})
                        subnet4.append(subnet4_subnet)
    cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'].extend(subnet4)

    return cray_dhcp_kea_dhcp4


def get_kea_dhcp4_leases():
    """
    Query the kea-api to get all active dhcp leases
    :return:
    """
    kea_request_data = {'command': 'lease4-get-all', 'service': ['dhcp4']}
    resp = kea_api('POST', '/', headers=kea_headers, json=kea_request_data)

    return resp.json()


def create_index_kea_dhcp4_lease(kea_dhcp4_leases):
    """
    Create a quick lookup dictionary for active leases in kea by making MAC address an index.
    :param kea_dhcp4_leases:
    :return:
    """
    kea_dhcp4_by_mac = {}
    for entry in kea_dhcp4_leases:
        kea_dhcp4_by_mac[entry['hw-address']] = entry


def get_sls_networks():
    """
    Get network information from SLS
    :return:
    """
    resp = sls_api('GET', '/v1/networks')

    return resp.json()


def get_sls_hardware():
    """
    Get hardawre information from SLS
    :return:
    """
    resp = sls_api('GET', '/v1/hardware')

    return resp.json()


def create_index_sls_all_hardware(sls_hardware):
    """
    Create SLS hardware dictionary with Xname as the index
    :param sls_hardware:
    :return:
    """
    sls_data_by_xname = {}
    for entry in sls_hardware:
        sls_data_by_xname[entry['Xname']] = entry

    return sls_data_by_xname


def get_smd_ethernet_interfaces(black_list_cidr, nmn_cidr):
    """
    Get SMD EthernetInterface table data.
    :param black_list_cidr:
    :return:
    """
    resp = smd_api('GET', '/hsm/v2/Inventory/EthernetInterfaces')
    smd_ethernet_interfaces = resp.json()

    interface_removal_list = []

    for interface in smd_ethernet_interfaces:
        # We are specifically looking for at SMD entries first IP address if populated.
        # Static and dynamic IPAddress in SMD entries must have an NMN or HMN IP as the first IP address.
        # Skip checking any interfaces that have kea in description due to being a static interface
        # Checking only on len to be specific to 1 to exclude bonded interfaces
        if 'kea' not in interface['Description'] and interface['ComponentID'] != '':
            if interface['IPAddresses'] and len(interface['IPAddresses']) == 1:
                if 'IPAddress' in interface['IPAddresses'][0]:
                    smd_ip = interface['IPAddresses'][0]['IPAddress']
                else:
                    smd_ip = ''
                if smd_ip != '':
                    # check if an interface has A DHCP IP when it should be static or no IP
                    # add to list for clean loop
                    for cidr in black_list_cidr:
                        if ipaddress.IPv4Address(smd_ip) in ipaddress.IPv4Network(cidr, strict=False):
                            interface_removal_list.append(interface)
                            patch_id = interface['ID']
                            patch_mac = interface['MACAddress']
                            patch_data = {'ID': patch_id, 'MACAddress': patch_mac, 'IPAddresses': []}
                            resp = smd_api(
                                'PATCH', '/hsm/v2/Inventory/EthernetInterfaces/'
                                         + patch_id, json=patch_data)
                            log.warning(f'Found an IP in SMD EthernetInterfaces that should not be there.'
                                        f'MAC:{patch_mac}, IP: {smd_ip}')
                            if resp.status_code != 200 and resp.status_code != 201:
                                log.error(f'Update to SMD failed for MAC:{patch_mac}, IP: {smd_ip}'
                                          f' resp.status_code: {resp.status_code}'
                                          f' resp.json {resp.json()}')

    # clean up in memory copy of smd Ethernet Interfaces
    for interface in interface_removal_list:
        for i in range(len(smd_ethernet_interfaces)):
            if interface == smd_ethernet_interfaces[i]:
                del smd_ethernet_interfaces[i]
                log.warning(f'Removing '
                            f'{interface} '
                            f'from in memory copy of SMD Ethernet Interfaces')
                break

    return smd_ethernet_interfaces


def create_index_smd_ethernet_interfaces(smd_ethernet_interfaces):
    """
    Create dictionary of SMD EthernetInterface data with MACAddress as an index
    :param smd_ethernet_interfaces:
    :return:
    """

    index_smd_ethernet_interfaces = {}

    for interface in smd_ethernet_interfaces:
        if 'MACAddress' in interface and interface['MACAddress'] != '':
            mac = interface['MACAddress']
            if mac != '' and ':' not in mac:
                mac = ':'.join(mac[i:i + 2] for i in range(0, 12, 2))
            index_smd_ethernet_interfaces[mac] = interface
    return index_smd_ethernet_interfaces


def all_ips_in_smd(smd_ethernet_interfaces):
    """
    Collect all the IPs in SMD EthernetInterfaces and copy the IPs into a set()
    :param smd_ethernet_interfaces:
    :return:
    """

    smd_ip_set = set()

    for record in smd_ethernet_interfaces:
        if record['IPAddresses'] != []:
            for ip in record['IPAddresses']:
                if ip['IPAddress'] not in smd_ip_set:
                    smd_ip_set.add(ip['IPAddress'])

    return smd_ip_set


def xname_to_alias_dict(sls_hardware):
    """
    Create a dictionry to map SLS Xname to first Alias
    :param sls_hardware:
    :return:
    """
    xname_to_alias = {}
    for sls_record in sls_hardware:
        xname = sls_record['Xname']
        if 'ExtraProperties' in sls_record:
            if 'Aliases' in sls_record['ExtraProperties'] \
                    and sls_record['ExtraProperties']['Aliases'][0] != '':
                log.info(f"SLS alias:{sls_record['ExtraProperties']['Aliases'][0]}")
                xname_to_alias[xname] = sls_record['ExtraProperties']['Aliases'][0]

    return xname_to_alias


def alias_to_xname_dict(xname_to_alias):
    """
    Create a dictionary to map Alias to Xname
    :param xname_to_alias:
    :return:
    """
    alias_to_xname = {}
    for xname in xname_to_alias:
        alias = xname_to_alias[xname]
        alias_to_xname[alias] = xname

    return alias_to_xname


def create_interface_black_list(smd_ethernet_interfaces, all_alias_to_xname):
    """
    Create a list of interfaces we do not want to assign dynamic dhcp reservations to
    :param smd_ethernet_interfaces:
    :param all_alias_to_xname:
    :return:
    """

    interface_blacklist = []
    xname_list = []

    for alias in all_alias_to_xname:
        if 'ncn' in alias:
            xname_list.append(all_alias_to_xname[alias])

    for interface in smd_ethernet_interfaces:
        # adding to conditions to blacklist an interface from having kea update the ip address in SMD
        # first scenario is all xnames that are linked to an ncn
        # second scenario are times when we flag kea to not update an ip address in SMD EthernetInterface table like an ncn add/remove/move
        if interface['ComponentID'] in xname_list or 'kea' in interface['Description']:
            # using SMD ID since that is always MAC without colons
            mac = interface['ID'].lower()
            mac_colons = ':'.join(mac[i:i + 2] for i in range(0, 12, 2))
            mac_no_colons = mac
            interface_blacklist.append(mac_colons)
            interface_blacklist.append(mac_no_colons)

    return interface_blacklist


def load_static_ncn_ips(sls_hardware):
    """
    Load static IP data from BSS and update SMD EthernetInterfaces table
    :param sls_hardware:
    :return:
    """

    bss_host_records = {}

    # get ncn and ncn-bmc ip info from BSS
    resp = bss_api('GET', '/boot/v1/bootparameters?name=Global')
    bss_data = resp.json()
    try:
        if 'cloud-init' in bss_data[0]:
            if 'meta-data' in bss_data[0]['cloud-init']:
                if 'host_records' in bss_data[0]['cloud-init']['meta-data']:
                    bss_host_records = bss_data[0]['cloud-init']['meta-data']['host_records']
                    log.info('bss_host_records')
                    log.info(f'{json.dumps(bss_host_records)}')
    except:
        log.warning("Unable to extract cloud-init metadata from BSS response")

    ncn_data = {}
    alias_to_mac = {}
    alias_set = set()

    # sort bss cloud-init host_records
    if bss_host_records != {}:
        for record in bss_host_records:
            static_mac = ''
            log.debug('for record in bss_host_records.')
            log.debug(f'Record is: {record}')
            if any(n in record['aliases'][0] for n in
                   ('-mgmt', '.nmn', '.mtl', 'hmn', '.cmn', '.chn')):
                split_aliases = ''
                log.debug(f'Record is: {record}')
                log.debug(f"record.split: {record['aliases'][0].split('.', 1)}")
                if '.' in record['aliases'][0]:
                    split_aliases = record['aliases'][0].split('.', 1)
                if 'mgmt' in record['aliases'][0]:
                    split_char = '-'
                    count = 2
                    temp_string = record['aliases'][0].split(split_char)
                    split_aliases = split_char.join(temp_string[:count]), \
                                    split_char.join(temp_string[count:])
                alias = split_aliases[0]
                alias_network = split_aliases[1]
                static_ip = record['ip']
                log.debug(f"Collecting IPs.  alias: {alias}, "
                          f"alias_network: {alias_network}, static_ip: {static_ip}")
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
        log.info('ncn_data')
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
                        if 'Aliases' in sls_record['ExtraProperties'] \
                                and sls_record['ExtraProperties']['Aliases'][0] == alias:
                            xname = sls_record['Xname']
                            log.debug(f'Alias to xname found {alias} and {xname}')
                            # check description to see if kea has already loaded the data for NCN
                            resp = smd_api('GET'
                                           , '/hsm/v2/Inventory/EthernetInterfaces?ComponentID='
                                           + xname)
                            smd_query = resp.json()
                            for i in range(len(smd_query)):
                                if 'kea' in smd_query[i]['Description']:
                                    query_bss = False
                                    update_smd = False
                            if query_bss:
                                resp = bss_api('GET', '/boot/v1/bootparameters?name=' + xname)
                                if resp.status_code != 404 and 'params' in resp.json()[0]:
                                    bss_params = resp.json()[0]['params'].split()
                                else:
                                    log.warning(f'No BSS params for {xname}')
                                    bss_params = ''
                                    break
                                log.debug('bss_params:')
                                log.debug(f'{bss_params}')
                                for param in bss_params:
                                    log.debug('param loop for first bond interface csm-1.2+')
                                    if 'ifname=mgmt0' in param:
                                        log.debug(f'param: {param}')
                                        interface_mgmt0 = param.split(':', 1)
                                        log.debug(f'bond0_interfaces: {interface_mgmt0}')
                                        bond0_first_interface_mac = interface_mgmt0[1]
                                        log.debug(f'bond0_first_interface_mac:'
                                                  f'{bond0_first_interface_mac}')
                                        static_mac = bond0_first_interface_mac
                                        log.info(f'found MAC:{static_mac} '
                                                 f'for alias:{alias}, xname:{xname}')
                                        alias_to_mac[alias] = static_mac
                                        break
                log.info(f'the data for NMN query_bss:'
                         f'{query_bss}alias:{alias}, xname:{xname}, MAC:{static_mac}')
            # skipping bmc for ncm-m001 due to not being on the shasta csm management network
            if 'bmc' in alias and 'ncn-m001' not in alias:
                # get xname from alias
                for sls_record in sls_hardware:
                    if 'ExtraProperties' in sls_record:
                        if 'Aliases' in sls_record['ExtraProperties'] \
                                and sls_record['ExtraProperties']['Aliases'][0] == alias.strip('_bmc'):
                            xname_bmc = sls_record['Parent']
                            resp = smd_api('GET', 'hsm/v2/Inventory/EthernetInterfaces?ComponentID='
                                           + xname_bmc)
                            smd_query = resp.json()
                            max_int = 0
                            min_int = 0
                            mac_vendor = ''
                            for i in range(len(smd_query)):
                                if 'kea' in smd_query[i]['Description'].lower() or 'usb' in smd_query[i]['Description'].lower():
                                    update_smd = False
                            if update_smd:
                                mac_lookup = manuf.MacParser()
                                for entry in smd_query:
                                    if 'usb' not in entry['Description'].lower():
                                        hex_to_int = int(entry['ID'][-2:], 16)
                                        if hex_to_int > max_int:
                                            max_int = hex_to_int
                                        if hex_to_int < min_int:
                                            min_int = hex_to_int
                                for entry in smd_query:
                                    hex_to_int = int(entry['ID'][-2:], 16)
                                    mac_vendor = str(mac_lookup.get_manuf(entry['MACAddress'])).lower()
                                    # intel bmc mac use the higher mac for dedicated bmc port
                                    if mac_vendor != '':
                                        if 'intel' in mac_vendor and mac_vendor != '':
                                            if max_int == hex_to_int:
                                                static_mac = entry['MACAddress']
                                                log.info(f'found MAC:{static_mac} for alias:{alias}')
                                                alias_to_mac[alias] = static_mac
                                        # HPE and Gigabyte use the lower mac for dedicated bmc port
                                        else:
                                            if min_int == hex_to_int:
                                                static_mac = entry['MACAddress']
                                                log.info(f'found MAC:{static_mac} for alias:{alias}')
                                                alias_to_mac[alias] = static_mac
                        log.info(f'the data for BMC alias:{alias}, xname:{xname_bmc}, MAC:{static_mac}')

        log.info('data from BSS sorted into two dictionaries:')
        log.info(f'{json.dumps(ncn_data)}')
        log.info(f'{json.dumps(alias_to_mac)}')

        # update smd EthernetInterface table with NCN and NCN BMC data
        for alias in ncn_data:
            update_smd = True
            update_ip = []
            update_mac = ''
            patch_description = ''
            if 'ncn-m001_bmc' not in alias:
                # making sure nmn is the first entry for nodes but not bmcs
                if 'bmc' not in alias:
                    update_ip.append({'IPAddress': ncn_data[alias]['nmn']})
                for network in ncn_data[alias]:
                    # skip nmn ip address
                    if network != 'nmn':
                        update_ip.append({'IPAddress': ncn_data[alias][network]})
                update_mac = alias_to_mac[alias]
                if update_mac == {}:
                    update_smd = False
                if update_smd:
                    resp = smd_api('GET', 'hsm/v2/Inventory/EthernetInterfaces/'
                                   + update_mac.replace(':', '').lower())
                    log.info(f"static_mac stripped of colons {update_mac.replace(':', '').lower()}")
                    if 'Description' in resp.json() and resp.status_code == 200:
                        if 'kea' not in resp.json()['Description']:
                            if update_mac != '':
                                patch_mac = update_mac.replace(':', '')
                                patch_ip = update_ip
                                patch_description = resp.json()['Description'] + '- kea'
                                log.info('Patch Data:')
                                log.info(f"MAC:{patch_mac}, IP:{patch_ip}")
                                log.info(f"Patch URL: "
                                         f"cray-smd/hsm/v2/Inventory/EthernetInterfaces/{patch_mac}")
                                patch_data = \
                                    {'MACAddress': patch_mac, 'Description':
                                        patch_description, 'IPAddresses': patch_ip}
                                resp = smd_api('PATCH', 'hsm/v2/Inventory/EthernetInterfaces/'
                                               + patch_mac, json=patch_data)
                                log.info(f"smd_api('PATCH', 'hsm/v2/Inventory/EthernetInterfaces/' + {patch_mac},"
                                         f"json={json.dumps(patch_data)})")
                                log.info(f'{resp.json}')
                    if update_mac != '' and resp.status_code == 404:
                        post_mac = update_mac
                        post_ip = update_ip
                        post_description = '- kea'
                        log.info('Post Data:')
                        log.info(f"MAC:{post_mac}, IP:{post_ip}")
                        log.info("Post URL: cray-smd/hsm/v2/Inventory/EthernetInterfaces")
                        post_data = {'MACAddress': post_mac, 'Description': post_description,
                                     'IPAddresses': post_ip}
                        resp = smd_api('POST', 'hsm/v2/Inventory/EthernetInterfaces', json=post_data)
                        log.info(f"smd_api('PATCH', 'hsm/v2/Inventory/EthernetInterfaces/',"
                                 f"json={json.dumps(post_data)})")
                        log.info(f'{resp.json}')
                    # log any errors after trying to update SMD
                    # if status code is not 200 after the patch or post, update did not work
                    if update_mac != '' and resp.status_code != 200 and resp.status_code != 201:
                        log.error(f"Error trying to update SMD with {update_mac}")
    else:
        log.warning(f'Cray-bss empty')

def compare_smd_kea_information(kea_dhcp4_leases, smd_ethernet_interfaces, main_smd_ip_set, interface_black_list,
                                black_list_cidr):
    """
    Compare SMD EthernetInterface data with Kea active lease data.
    Update SMD EthernetInterface table with IPs for dynamic dhcp reservation
    :param kea_dhcp4_leases:
    :param smd_ethernet_interfaces:
    :param main_smd_ip_set:
    :param interface_black_list:
    :return:
    """

    for record in kea_dhcp4_leases[0]['arguments']['leases']:
        log.debug(f'record in kea_dhcp4_leases[0]: '
                  f'{record}')
        entry_exist = False
        query_smd = True
        smd_entry = ''
        valid_ip = True
        patch_ip = []
        patch_mac = ''
        post_mac = ''
        post_ip = []
        patch_data = {}
        smd_id = ''

        # checking for active leases in kea and comparing to SMD EthernetInterfaces
        # Also validating they are not in the interface blacklist and IP in cidr black list
        # valid-lft = 600 are place holder leases to speed up DNS hostname creation
        # and Slingshot switch bug with their DHCP client(see SSHOTPLAT-1151 for details)
        if record['valid-lft'] != 600:
            if record['ip-address'] not in main_smd_ip_set and \
                    record['hw-address'].lower() not in interface_black_list:
                for cidr in black_list_cidr:
                    if ipaddress.IPv4Address(record['ip-address']) in ipaddress.IPv4Network(cidr, strict=False):
                        valid_ip = False
                if valid_ip:
                    smd_id = record['hw-address'].replace(':', '').lower()
                    # check to see if we need to do a POST or PATCH
                    for smd_ethernet_interface in smd_ethernet_interfaces:
                        if smd_id == smd_ethernet_interface['ID']:
                            entry_exist = True
                            query_smd = False
                            smd_entry = smd_ethernet_interface
                    if query_smd and smd_id != '':
                        resp = smd_api('GET', '/hsm/v2/Inventory/EthernetInterfaces/' + smd_id)
                        smd_entry = resp.json()
                        if resp.status_code == 200:
                            entry_exist = True
                    # valid POST update to SMD EthernetInterface for interface
                    if not entry_exist and smd_id != '':
                        post_ip = [{'IPAddress': record['ip-address']}]
                        post_mac = smd_id
                        post_data = {'MACAddress': post_mac, 'IPAddresses': post_ip}
                        resp = smd_api('POST', '/hsm/v2/Inventory/EthernetInterfaces', json=post_data)
                        log.info(f'Added {post_data}')

                        if resp.status_code != 200 and resp.status_code != 201:
                            # if resp.satus_code not in (200,201):
                            log.error('Post to SMD EthernetInterfaces did not succeed')
                            log.error(f'status_code: {resp.status_code}')
                            log.error(f'{resp.json}')
                    # validate PATCH update SMD EthernetInterface for interface
                    if entry_exist and smd_id != '':
                        valid_patch_entry = True
                        patch_ip = []
                        patch_ip.append({'IPAddress': record['ip-address']})
                        patch_mac = smd_id
                        patch_data = {'IPAddresses': patch_ip}
                        if smd_entry['Type'] == 'NodeBMC' and len(patch_ip) > 1:
                            valid_patch_entry = False
                            # working around known issue with BMCs set to static still DHCP
                            if len(patch_ip) > 1:
                                # delete active lease in kea
                                for i in range(len(patch_ip) - 1):
                                    if i != 0:
                                        ip_delete = patch_ip[i]['IPAddress']
                                        kea_lease4_delete = {'command': 'lease4-del', 'service': ['dhcp4'],
                                                             'arguments': {'ip-address': ip_delete}}
                                        resp = kea_api('POST', '/', json=kea_lease4_delete, headers=kea_headers)
                                        del patch_ip[i]
                                log.info(f'Attempting automated repair by removing empty IPAddress entries')
                                valid_patch_entry = True
                        if not valid_patch_entry or len(patch_ip) > 1:
                            log.error(f'Patch scenario is not correct.  Manual review recommended:'
                                      f'{patch_mac} with {patch_data}')
                            valid_patch_entry = False
                        if valid_patch_entry:
                            resp = smd_api('PATCH', '/hsm/v2/Inventory/EthernetInterfaces/' + patch_mac,
                                           json=patch_data)
                            log.info(f'Updated {patch_mac} with {patch_data}')

                            if resp.status_code != 200:
                                log.error(f'Patch to SMD EthernetInterfaces did not succeed')
                                log.error(f'status_code: {resp.status_code}')
                                log.error(f'{resp.json}')
                        if valid_patch_entry and len(smd_entry['IPAddresses']) > 0:
                            log.warning(f'Already an IP for SMD entry')
                            log.warning(f'{smd_entry}')
                            log.warning(f'Failed patch data {patch_mac} with {patch_data}')
            # Clean up data if blacklist data found in SMD EthernetInterfaces
            if record['ip-address'] not in main_smd_ip_set and record['hw-address'].lower() in interface_black_list:
                log.warning(f"Interface {record['hw-address']} {record['ip-address']} "
                            f"via dynamic dhcp reservation and was on interface blacklist "
                            f"Will remove lease from kea")
                kea_lease4_delete = {'command': 'lease4-del', 'service': ['dhcp4'],
                                     'arguments': {'ip-address': record['ip-address']}}
                resp = kea_api('POST', '/', json=kea_lease4_delete, headers=kea_headers)


def create_per_subnet_reservation(cray_dhcp_kea_dhcp4, smd_ethernet_interfaces, nmn_cidr, all_xname_to_alias,
                                  all_alias_to_xname, sls_hardware, ipxe_boot_filename):
    """
    Create per subnet reservation configurations for Kea config.
    :param cray_dhcp_kea_dhcp4:
    :param smd_ethernet_interfaces:
    :param nmn_cidr:
    :param all_xname_to_alias:
    :param all_alias_to_xname:
    :param sls_hardware:
    :return:
    """

    # create dynamic set of sets
    list_of_subnet_sets = {}

    # dynamic list of sets to keep track of information per subnet
    for i in range(len(cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'])):
        ip_var = 'ip_' + str(i)
        hostname_var = 'hostname_' + str(i)
        mac_var = 'mac_' + str(i)
        alias_var = 'alias_' + str(i)

        list_of_subnet_sets[ip_var] = set()
        list_of_subnet_sets[hostname_var] = set()
        list_of_subnet_sets[mac_var] = set()
        list_of_subnet_sets[alias_var] = set()

    # create DHCP reservations
    for record in smd_ethernet_interfaces:
        dupe_ip = False
        dupe_hostname = False
        dupe_mac = False

        node_alias = ''
        node_xname = ''

        kea_ips = record.get('IPAddresses', [])
        kea_hostname = record.get('ComponentID', '')
        kea_mac = record.get('MACAddress', '')
        smd_description = record.get('Description', '')
        log.info(f'kea_ip:{kea_ips},kea_hostname:{kea_hostname},kea_mac:{kea_mac}, smd_description:{smd_description}')
        # check kea_mac format
        if kea_mac != '' and ':' not in kea_mac:
            kea_mac = ':'.join(kea_mac[i:i + 2] for i in range(0, 12, 2))

        if kea_ips == [] and kea_hostname != '' and kea_mac != '':
            # try to use the alias if type is node
            if record['Type'] == 'Node' \
                    and kea_hostname in all_xname_to_alias and all_xname_to_alias[kea_hostname] != '':
                temp = all_xname_to_alias.get(kea_hostname, kea_hostname)
                kea_hostname = temp
                cray_dhcp_kea_dhcp4['Dhcp4']['reservations'].append(
                    {'hostname': kea_hostname, 'hw-address': kea_mac})
        # validate possible DHCP reservation creation
        if kea_ips != [] and kea_hostname != '' and kea_mac != '':
            for ip in kea_ips:
                kea_ip = ip['IPAddress']
                if kea_ip == '':
                    break
                for i in range(len(cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'])):
                    if ipaddress.IPv4Address(kea_ip) in ipaddress.IPv4Network(
                            cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['subnet'],
                            strict=False):
                        if kea_ip in list_of_subnet_sets['ip_' + str(i)]:
                            dupe_ip = True
                            log.error(f"Dupe IP detected with: "
                                      f"subnet "
                                      f"{cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['subnet']} "
                                      f"with kea_hostname: {kea_hostname}, "
                                      f"kea_mac: {kea_mac}, kea_hostname: {kea_hostname}")

                        # make sure we use an xname when correcting SMD data
                        if 'x' not in kea_hostname[0].lower():
                            node_alias = kea_hostname
                            node_xname = all_xname_to_alias.get(kea_hostname, kea_hostname)
                            kea_hostname = node_xname
                        if 'x' in kea_hostname[0].lower():
                            node_alias = all_alias_to_xname.get(kea_hostname, kea_hostname)
                            node_xname = kea_hostname
                        # Detect and attempt to automate updating SMD when a node has been replaced or moved
                        # in the same rack.  Usually computes and UANs
                        if kea_hostname in list_of_subnet_sets['hostname_' + str(i)] or kea_hostname in \
                                list_of_subnet_sets['alias_' + str(i)]:
                            repair_component_id = ''
                            repair_mac = ''
                            repair_ip = ''

                            log.warning(f'Possible node move or replacement.  Attempting automated repair')
                            dupe_hostname = True
                            repair_data = {}
                            log.info(
                                f"URL: http://cray-smd/hsm/v2/Inventory/EthernetInterfaces?ComponentID={kea_hostname}")
                            resp = smd_api('GET', 'hsm/v2/Inventory/EthernetInterfaces?ComponentID='
                                           + kea_hostname)
                            repair_data = resp.json()
                            repair_data_resp_status = resp.status_code
                            j = 0
                            if repair_data_resp_status != 400:
                                while j < len(repair_data):
                                    if repair_data[j]['IPAddresses'] == []:
                                        print('repair_data: Deleting entry with no ip')
                                        del repair_data[j]
                                    else:
                                        j += 1
                                print(repair_data)
                            # if length of repair data is not 2, we are unable to automatically fix the SMD data
                            if len(repair_data) != 2:
                                log.error('Automated repair failed')
                                log.error(
                                    f"Error duplicate hostname found in "
                                    f"{cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['subnet']}")
                                log.error(f"ip: {kea_ip}, mac:{kea_mac}, hostname:{kea_hostname}")
                                break
                            else:
                                # getting the dates formatted
                                date0 = datetime.datetime.fromisoformat(repair_data[0]['LastUpdate'][0:19])
                                date1 = datetime.datetime.fromisoformat(repair_data[1]['LastUpdate'][0:19])

                                if date0 < date1:
                                    log.debug(
                                        'URL: http://cray-smd/hsm/v2/Inventory/EthernetInterfaces?ComponentID=' +
                                        repair_data[0][
                                            'ID'])
                                    # remove the IP from the older entry
                                    patch_mac = repair_data[0]['MACAddress']
                                    patch_data = {'MACAddress': patch_mac, 'IPAddresses': []}
                                    resp = smd_api('PATCH',
                                                   'hsm/v2/Inventory/EthernetInterfaces/'
                                                   + repair_data[0]['ID'], json=patch_data)
                                    log.debug(
                                        'URL: http://cray-smd/hsm/v2/Inventory/EthernetInterfaces?ComponentID=' +
                                        repair_data[1][
                                            'ID'])
                                    repair_ip = repair_data[0]['IPAddresses'][0]['IPAddress']
                                    repair_mac = repair_data[1]['MACAddress']
                                    if ':' not in repair_mac:
                                        repair_mac = ':'.join(repair_mac[i:i + 2]
                                                              for i in range(0, 12, 2))
                                    repair_component_id = kea_hostname
                                    patch_data = {'MACAddress': repair_mac, 'IPAddresses': [{'IPAddress': repair_ip}]}
                                    resp = smd_api('PATCH',
                                                   'hsm/v2/Inventory/EthernetInterfaces/'
                                                   + repair_data[1]['ID'], json=patch_data)

                                # move the old ip to the newer interface
                                # delete the ip in the older entry
                                if date1 < date0:
                                    log.debug(
                                        'URL: http://cray-smd/hsm/v2/Inventory/EthernetInterfaces?ComponentID=' +
                                        repair_data[1]['ID'])
                                    # remove the IP from the older entry
                                    patch_mac = repair_data[1]['MACAddress']
                                    patch_data = {'MACAddress': patch_mac, 'IPAddresses': []}
                                    resp = smd_api('PATCH',
                                                   'hsm/v2/Inventory/EthernetInterfaces/' + repair_data[1]['ID'],
                                                   json=patch_data)
                                    log.debug(
                                        'URL: http://cray-smd/hsm/v2/Inventory/EthernetInterfaces?ComponentID=' +
                                        repair_data[0]['ID'])
                                    repair_ip = repair_data[1]['IPAddresses'][0]['IPAddress']
                                    repair_mac = repair_data[0]['MACAddress']
                                    if ':' not in repair_mac:
                                        repair_mac = ':'.join(repair_mac[i:i + 2]
                                                              for i in range(0, 12, 2))
                                    repair_component_id = kea_hostname
                                    patch_data = {'MACAddress': repair_mac, 'IPAddresses': [{'IPAddress': repair_ip}]}
                                    resp = smd_api('PATCH',
                                                   'hsm/v2/Inventory/EthernetInterfaces/'
                                                   + repair_data[0]['ID'], json=patch_data)

                                # delete active lease in kea
                                kea_lease4_delete = {'command': 'lease4-del', 'service': ['dhcp4'],
                                                     'arguments': {'ip-address': repair_ip}}
                                resp = kea_api(
                                    'POST', '/', json=kea_lease4_delete, headers=kea_headers)

                                # update generated kea info
                                for j in range(len(cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['reservations'])):
                                    dhcp_reservation = cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['reservations'][j]
                                    if dhcp_reservation['hostname'] == repair_component_id:
                                        log.info(f'repair data is:')
                                        log.info(
                                            f'repair_component_id:{repair_component_id}, '
                                            f'repair_mac: {repair_mac}, repair_ip:{repair_ip}')
                                        cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i][
                                            'reservations'][j]['hw-address'] = repair_mac
                                        cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i][
                                            'reservations'][j]['ip-address'] = repair_ip
                                        break
                                log.info(f'Automated repair successful')
                                if node_alias != '':
                                    kea_hostname = node_alias
                                dupe_hostname = False

                        if kea_ip in list_of_subnet_sets['ip_' + str(i)]:
                            log.error(
                                f"Dupe IP detected with: subnet "
                                f"{cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['subnet']} with "
                                f"kea_hostname: {kea_hostname}, kea_mac: {kea_mac}, kea_ip: {kea_ip}. "
                                f"Not adding to kea configs")
                            dupe_ip = True
                            break
                        if kea_mac in list_of_subnet_sets['mac_' + str(i)]:
                            log.error(
                                f"Dupe MAC detected with: subnet {cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['subnet']} with "
                                f"kea_hostname: {kea_hostname}, kea_mac: {kea_mac}, "
                                f"kea_hostname: {kea_hostname} "
                                f"Not adding to kea configs")
                            dupe_mac = True
                            break

                        if cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['subnet'] in nmn_cidr:
                            for cidr in nmn_cidr:
                                if ipaddress.IPv4Address(kea_ip) in ipaddress.IPv4Network(
                                        cidr, strict=False):
                                    if kea_hostname in all_xname_to_alias:
                                        kea_hostname = all_xname_to_alias[kea_hostname]

                        if not dupe_ip and not dupe_hostname and not dupe_mac:
                            # standard ipxe filename
                            boot_file = ipxe_boot_filename['ipxe']
                            # debug ipxe boot filename
                            if 'debug' in smd_description:
                                boot_file = ipxe_boot_filename['ipxe_debug']
                            # custom ipxe boot filename defined by "ipxe=$CUSTOMFILENAME"
                            if 'ipxe=' in smd_description:
                                boot_file = smd_description.partition('=')[2].split()[0]

                            if kea_ip != '' and kea_hostname != '' and kea_mac != '':
                                list_of_subnet_sets['ip_' + str(i)].add(kea_ip)
                                list_of_subnet_sets['hostname_' + str(i)].add(node_xname)
                                list_of_subnet_sets['mac_' + str(i)].add(kea_mac)
                                list_of_subnet_sets['alias_' + str(i)].add(node_alias)
                                cray_dhcp_kea_dhcp4['Dhcp4']['subnet4'][i]['reservations'].append(
                                    {'hostname': kea_hostname,
                                     'hw-address': kea_mac,
                                     'ip-address': kea_ip
                                     })

    return cray_dhcp_kea_dhcp4


def create_placeholder_leases(cray_dhcp_kea_dhcp4, kea_dhcp4_leases):
    """
    Create artificial leases as placeholders to speed up DNS or when Rosetta's stop renewing leases
    :param cray_dhcp_kea_dhcp4:
    :param kea_dhcp4_leases:
    :return:
    """

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
                # valid-lft = 600 are place holder leases to speed up DNS hostname creation
                # and Slingshot switch bug with their DHCP client(see SSHOTPLAT-1151 for details)
                place_holder_leases.append(
                    {'hostname': place_holder_hostname,
                     'hw-address': place_holder_mac,
                     'ip-address': place_holder_ip,
                     'valid-lft': 600})
    # Send requests to create DHCP leases via Kea API
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
    '''
    Write kea config to disk
    :param cray_dhcp_kea_dhcp4:
    :return:
    '''
    # write config to disk
    with open( TMP_PATH + '/' + 'cray-dhcp-kea-dhcp4.conf', 'w') as outfile:
        json.dump(cray_dhcp_kea_dhcp4, outfile)


def reload_config():
    """
    Reload Kea configs to update any changes written to disk
    If reload is successful.  Create backup of file.
    If reload is not success, try to load last known good config.
    :return:
    """

    # copy validated config from temp location
    shutil.copyfile( TMP_PATH + '/cray-dhcp-kea-dhcp4.conf',
                    KEA_PATH + '/cray-dhcp-kea-dhcp4.conf')

    # reload config in kea from conf file written
    kea_request_data = {'command': 'config-reload', 'service': ['dhcp4']}
    resp = kea_api('POST', '/', json=kea_request_data, headers=kea_headers)
    log.debug(f'logging config-reload '
              f'{resp.json()}')

    if resp.json()[0]['result'] != 0:
        log.error(f'Config reload failed '
                  f'Trying to load last known good config. '
                  f'{resp.json()}')
        shutil.copyfile(KEA_PATH + '/cray-dhcp-kea-dhcp4.conf.bak', KEA_PATH + '/cray-dhcp-kea-dhcp4.conf')
        # 2nd reload config in kea from last known good config
        kea_request_data = {'command': 'config-reload', 'service': ['dhcp4']}
        resp = kea_api('POST', '/', json=kea_request_data, headers=kea_headers)
        log.debug(f'logging config-reload '
                  f'{resp.json()}')
    else:
        # create backup copy of last known good kea config
        shutil.copyfile(KEA_PATH + '/cray-dhcp-kea-dhcp4.conf',
                        KEA_PATH + '/cray-dhcp-kea-dhcp4.conf.bak')


def validate_config():
    p = subprocess.run(['kea-dhcp4','-t',TMP_PATH + '/' + 'cray-dhcp-kea-dhcp4.conf'],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = p.stdout.decode('utf-8')
    if "Syntax check failed" in output or p.returncode != 0:
        log.error('Error with Kea Config Validation.'
                  f'{output}'
                  f'Exiting and no update(s) to Kea configs')
        sys.exit(1)
    else:
        shutil.copyfile(TMP_PATH + '/cray-dhcp-kea-dhcp4.conf',
                        KEA_PATH + '/cray-dhcp-kea-dhcp4.conf')

def backup_config(cray_dhcp_kea_dhcp4):

    tmp = cray_dhcp_kea_dhcp4

    config_string = json.dumps(tmp).replace('"', '\"')  # String
    config_string = codecs.encode(config_string, encoding='utf-8')  # Bytes object
    config_string = gzip.compress(config_string)
    config_string = base64.b64encode(config_string)
    config_backup_gzip = config_string.decode()

    p = subprocess.run(['kubectl','-n','services','patch','configmaps','cray-dhcp-kea-backup','--type','merge',
                        '-p','{"binaryData":{"keaBackup.conf.gz":"' + config_backup_gzip + '"}}'],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = p.stdout.decode('utf-8')
    log.debug(output)
    if p.returncode != 0:
        log.error('Error backing up cray-dhcp-kea config'
                  f'{output}')


# globals
log = logging.getLogger(__name__)
log.setLevel(level = os.environ['LOG_LEVEL'])

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
log.addHandler(handler)

# variables from env
ipxe_settings_file = os.environ['IPXE_SETTINGS_FILE']
tftp_server_nmn = os.environ['TFTP_SERVER_NMN']
tftp_server_hmn = os.environ['TFTP_SERVER_HMN']
unbound_servers = {}
unbound_servers['NMN'] = os.environ['UNBOUND_SERVER_NMN']
unbound_servers['HMN'] = os.environ['UNBOUND_SERVER_HMN']
hmn_loadbalancer_ip = os.environ['HMN_LOADBALANCER_IP']
nmn_loadbalancer_ip = os.environ['NMN_LOADBALANCER_IP']
black_list_network_names = {'MTL', 'CAN', 'CMN', 'CHN'}

# setup kea configs
KEA_PATH = '/usr/local/kea'
TMP_PATH = '/tmp'
kea_headers = {'Content-Type': 'application/json'}

# setup api urls
kea_api = APIRequest('http://cray-dhcp-kea-api:8000')
smd_api = APIRequest('http://cray-smd')
sls_api = APIRequest('http://cray-sls')
bss_api = APIRequest('http://cray-bss')


def main():
    """
    Main part of the automation that calls the functions in the proper order
    :return:
    """

    # kea config
    cray_dhcp_kea_dhcp4 = {}
    nmn_cidr = []
    main_smd_ip_set = set()
    time_servers_nmn = ''
    time_servers_hmn = ''
    kea_dhcp4_leases = {}
    smd_ethernet_interfaces = {}
    all_xname_to_alias = {}

    # init CLI Argument
    parser = argparse.ArgumentParser()
    parser.add_argument("--init", action="store_true",
                             help="Initial run of dhcp-helper before Kea has started.")
    args = parser.parse_args()

    if args.init:
        log.info('Initial startup run of dhcp-helper.  Skipping the Kea API check')
    else:
        # make sure kea api is up
        check_kea_api()

    # get boot file name
    ipxe_boot_filename = get_ipxe_boot_filename(ipxe_settings_file)
    # query SLS for network data
    sls_networks = get_sls_networks()

    # get list of cidr's that should not get a dynamic dhcp reservation
    black_list_cidr = get_black_list_cidr(sls_networks, black_list_network_names)

    # get nmn cidr
    nmn_cidr = get_nmn_cidr(sls_networks)

    # query SLS for hardware data
    sls_hardware = get_sls_hardware()

    # query SMD for EthernetInterfaces data
    # clean up SMD EthernetInterfaces IP data
    smd_ethernet_interfaces = get_smd_ethernet_interfaces(black_list_cidr, nmn_cidr)

    if args.init:
        log.info('Initial startup run of dhcp-helper.  Skipping the load of active Kea leases.')
        kea_dhcp4_leases = []
    else:
        # query Kea for dhcp4 leases
        kea_dhcp4_leases = get_kea_dhcp4_leases()

    # get templated base kea configs
    cray_dhcp_kea_dhcp4 = import_base_config(ipxe_settings_file)

    # get time servers
    time_servers_nmn = get_time_servers('nmn')
    time_servers_hmn = get_time_servers('hmn')

    # load SLS network data in Kea config
    cray_dhcp_kea_dhcp4 = load_network_configs(
        cray_dhcp_kea_dhcp4, sls_networks, time_servers_nmn, time_servers_hmn, ipxe_boot_filename)

    # get all ips in SMD
    main_smd_ip_set = all_ips_in_smd(smd_ethernet_interfaces)

    # create xname to alias dictionary
    all_xname_to_alias = xname_to_alias_dict(sls_hardware)

    # create alias to xname dictionary
    all_alias_to_xname = alias_to_xname_dict(all_xname_to_alias)

    if args.init:
        log.info('Initial startup run of dhcp-helper.  Skipping interface black list.')
        interface_black_list = []
    else:
        # create list interfaces that do get dynamic dhcp reservations
        interface_black_list = create_interface_black_list(smd_ethernet_interfaces,
                                                           all_alias_to_xname)

    if args.init:
        log.info('Initial startup run of dhcp-helper.  Skipping the compare smd kea information '
                 'and loading of static IPs.')
    else:
        # check for any entries or ips kea has and update smd
        compare_smd_kea_information(
            kea_dhcp4_leases, smd_ethernet_interfaces,
            main_smd_ip_set, interface_black_list, black_list_cidr)
        # load bss cloud-init ncn data into SMD EthernetInterfaces
        load_static_ncn_ips(sls_hardware)


    # create per dhcp reservations per subnet
    cray_dhcp_kea_dhcp4 = create_per_subnet_reservation(
        cray_dhcp_kea_dhcp4, smd_ethernet_interfaces,
        nmn_cidr, all_xname_to_alias, all_alias_to_xname, sls_hardware, ipxe_boot_filename)

    # write kea config to file
    write_config(cray_dhcp_kea_dhcp4)

    # validate kea config
    validate_config()

    if args.init:
        log.info('Initial startup run of dhcp-helper.'
                 'Skipping Kea config reload and creation of placeholder leases.')
    else:
        # reload kea config via api call
        reload_config()

        # create placeholder leases
        create_placeholder_leases(cray_dhcp_kea_dhcp4, kea_dhcp4_leases)
        backup_config(cray_dhcp_kea_dhcp4)

if __name__ == "__main__":
    main()
