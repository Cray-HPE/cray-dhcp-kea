#!/usr/bin/env python

import requests
import json
import ipaddress


resp = requests.get(url='http://cray-sls/v1/search/hardware?type=comptype_cabinet')
cn_nmn_cidr = resp.json()[0]['ExtraProperties']['Networks']['cn']['NMN']['CIDR']
cn_nmn_gateway = resp.json()[0]['ExtraProperties']['Networks']['cn']['NMN']['Gateway']
cn_nmn = ipaddress.ip_network(cn_nmn_cidr)
cn_nmn_total_hosts = cn_nmn.num_addresses
cn_nmn_pool_start = cn_nmn[26]
cn_nmn_pool_end = cn_nmn[cn_nmn_total_hosts -51]
print(cn_nmn_cidr)
print(cn_nmn_gateway)


cn_hmn_cidr = resp.json()[0]['ExtraProperties']['Networks']['cn']['HMN']['CIDR']
cn_hmn_gateway = resp.json()[0]['ExtraProperties']['Networks']['cn']['HMN']['Gateway']
cn_hmn = ipaddress.ip_network(cn_hmn_cidr)
cn_hmn_total_hosts = cn_hmn.num_addresses
cn_hmn_pool_start = cn_hmn[26]
cn_hmn_pool_end = cn_hmn[cn_hmn_total_hosts -51]
print(cn_hmn_cidr)
print(cn_hmn_gateway)


