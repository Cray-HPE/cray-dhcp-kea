# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.19] - 2023-01-06
### Added
### Change
- CASMNET-1994 - Use authentication for csm-helm-charts
### Deprecated
### Removed
### Fixed
### Security

## [0.10.18] - 2022-10-25
### Added
### Change
- CASMNET-1937 - Security remediation for RFC 8357
### Deprecated
### Removed
### Fixed
### Security

## [0.10.17] - 2022-10-25
### Added
### Change
- CAST-3316 - increase timeout on readiness check to match liveness check from default value.
### Deprecated
### Removed
### Fixed
### Security

## [0.10.16] - 2022-09-20
### Added
### Changed
### Deprecated
### Removed
### Fixed
- CASMNET-1880 - Fix race condition between dhcp-helper.py and MEDs
### Security

## [0.10.15] - 2022-08-24
### Added
### Changed
### Deprecated
### Removed
### Fixed
- CASMTRIAGE-3966 - reset variables to not carry incorrect data
### Security

## [0.10.14] - 2022-08-4
### Added
### Changed
### Deprecated
### Removed
### Fixed
- CASMINST-5182 - Kea dhcp-helper.py missing variable assignment
### Security

## [0.10.13] - 2022-07-21
### Added
### Changed
### Deprecated
### Removed
### Fixed
- CASMNET-1727 - index error during auto repair logic
### Security

## [0.10.12] - 2022-07-18
### Added
- CASMNET-1677 - dhcp-helper.py should fail gracefully if BSS metadata is missing
### Changed
- CASMNET-1551 - update cray-dhcp-kea to use HSM V2 API
### Deprecated
### Removed
### Fixed
- CASMNET-1713 - auto repair logic in dhcp-helper.py not consistently working
### Security

## [0.10.11] - 2022-06-08
### Added
- Added back dynamic boot file name loading and made volume mount optional 
for compatibility support for upgrades and installs
### Changed
### Deprecated
### Removed
### Fixed
### Security

## [0.10.10] - 2022-06-06
### Added
### Changed
### Deprecated
### Removed
- removed dynamic tftp filename load, will add back for csm-1.2.6
### Fixed
- CASMTRIAGE-3436 - fix SMD patch logic for dhcp-helper.py
### Security

## [0.10.9] - 2022-5-26
### Added
### Changed
### Deprecated
### Removed
### Fixed
- CASMINST-4706 - fix type-o in volume mount
### Security

## [0.10.8] - 2022-5-09
### Added
- CASMINST-4526 - Update cray-dhcp-kea to load dynamic boot file name for pxe booting
### Changed
### Deprecated
### Removed
### Fixed
### Security

## [0.10.7] - 2022-4-29
### Added
### Changed
### Deprecated
### Removed
### Fixed
- CASMTRIAGE-3275 - manuf network interface vendor lookup doesn't always return a string, enforce string return
### Security

## [0.10.6] - 2022-4-28
### Added
### Changed
### Deprecated
### Removed
### Fixed
- CASMTRIAGE-3269 - add a way to skip none network card entries like usb ports in SMD during mac vendor lookup logic
### Security

## [0.10.5] - 2022-4-22
### Added
### Changed
### Deprecated
### Removed
### Fixed
- CASMNET-1386 - race condition between artificial/placeholder leases and removing IP from SMD EthernetInterface table
### Security

## [0.10.4] - 2022-3-17
### Added
### Changed
- baseos to be rolling version of Alpine 3
### Deprecated
### Removed
### Fixed
### Security


## [0.10.3] - 2022-3-17
### Added
### Changed
### Deprecated
### Removed
### Fixed
- CASMTRIAGE-3111 - Duplicate DNS entries for NCN xnames
- CASMNET-1128 - dhcp-helper:/srv/kea/dhcp-helper.py:61: DeprecationWarning: Using 'method_whitelist' with Retry is deprecated and will be removed in v2.0. Use 'allowed_methods' instead
### Security


## [0.10.1] - 2022-1-26
### Added
### Changed
- CASMNET-1113 - improve kea api check in dhcp-helper
### Deprecated
### Removed
### Fixed
- CASMNET-1104 - dhcp-helper is putting IPs on the wrong interface on bonds
- CASMNET-1103 - dhcp-helper crash when missing alias for compute node
- CASMNET-1108 - NCN bond interface dhcp'ing and getting dhcp reservation
### Security

## [0.10.0] - 2021-12-16
### Added
### Changed
- update to helm v2 api
### Deprecated
### Removed
### Fixed
### Security

## [0.9.13] - 2021-12-2
### Added
### Changed
### Deprecated
### Removed
### Fixed
- CASMNET-1053 - error handling when query bss data if data is returned that is not expected
- CASMNET-1054 - make sure dhcp-helper does not patch in an IP when there is already an IP outside of loading BSS data
- CASMNET-1055 - make sure xname is used when trying to repair SMD data after node move
### Security


## [0.9.12] - 2021-11-30
### Added
### Changed
### Deprecated
### Removed
### Fixed
- CASMNET-1052 - fix csm-1.0 bss data support
### Security

## [0.9.11] - 2021-11-22
### Added
### Changed
- CASMTRIAGE-2729 - remove debug log in dhcp-helper due to not always being valid
- CASMNET-1037 - Update dhcp-helper detect PATCH or POST to SMD when updating data for NCNs
### Deprecated
### Removed
### Fixed
### Security

## [0.9.10] - 2021-11-12
### Added
- CASMNET-946 - add feature to dhcp-helper.py in kea to create dhcp reservations for static ips from cloud-init data
- CASMNET-877 - automation script to update DHCP/DNS/HMS data after hardware swap
- CASMTRIAGE-2615 - fixed scenario where time server lookup created malformed string
- CASMNET-947 - add dhcp-helper.py feature in kea to handle multiple dhcp reservations per MAC in different subnets
- CASMNET-706 - add global reservation duplicate checking when reading from SMD ethernet table
- CASMNET-1006 - Kea should reserve NCN IPs (including NCNs that are added or replaced post-install)

### Changed
- CASMNET-758 - Refactor dhcp-helper and improve performance 
- CASMNET-994 - add python logger to scripts in cray-dhcp-kea
### Deprecated
### Removed
- support for shasta-1.3 that used dnsmasq
### Fixed
### Security


## [0.9.8] - 2021-10-27
### Added
- CASMNET-972 - added function to rollback to last known good config if bad config was generated
### Changed
- CASMNET-813 - none root user in container
### Deprecated
### Removed
### Fixed
### Security

## [0.8.7] - 2021-08-30
### Added
### Changed
- CASMNET-841 - fix for  CVE-2021-3711
### Deprecated
### Removed
### Fixed
### Security

## [0.5.3] - 2021-08-24
### Added
### Changed
 CASMNET-747
  -   Added pod priorityClassName 
### Deprecated
### Removed

## [0.5.3] - 2021-06-09
### Added
### Changed
 CASMNET-754
  -  Added hostname and ip dupe checking in the global reservations
### Deprecated
### Removed

## [0.5.3] - 2021-06-01
### Added
### Changed
 CASMNET-734
  -  Set kea server identifier to be the metalLB IP
### Deprecated
### Removed

## [0.5.2] - 2021-05-26
### Added
### Changed
 CASMNET-731
  -  Change externalTrafficPolicy from Cluster to Local
### Deprecated
### Removed

## [0.5.1] - 2021-05-17
### Added
### Changed
 CASMTRIAGE-2260
  -  Refactor Kea Exporter implementation
### Deprecated
### Removed

## [0.5.0] - 2021-05-13
### Added
- CASMOSS-22
  -  Enabled "exporter" as sidecar container to enable Prometheus scrapping for the Kea service
### Changed

## [0.4.21] - 2021-05-12
### Added
### Changed
- CASMNET-678
  - Increased DHCP lease time to 3600s
### Deprecated
### Removed

## [0.4.20] - 2021-04-13
### Added
### Changed
- CASMNET-639
  - updated dockerfile base image source
  - updated kea to 1.8.2
  - updated log4cplus to 2.0.6
### Deprecated
### Removed

## [0.4.19] - 2021-03-24
### Added
### Changed
- CASMINST-1844
  - added MTL filter to dhcp-helper.py
=======
### Deprecated
### Removed

## [0.4.18] - 2021-03-03
### Added
### Changed
- CASMINST-1632
  - added dupe checking for MAC randomizer
### Deprecated
### Removed

## [0.4.17] - 2021-02-25
### Added
### Changed
- CASMNET-449
  - updated NMN subnet tracking object when loading subnets
### Deprecated
### Removed

## [0.4.16] - 2021-02-20
### Added
### Changed
- CASMTRIAGE-747
  - added wildcard subnet matching for hmn
### Deprecated
### Removed

## [0.4.15] - 2021-02-18
### Added
### Changed
- CASMTRIAGE-730
  -  update static reservation dupe checking logic to filter out mac/ip reservations
### Deprecated
### Removed

## [0.4.14] - 2021-02-17
### Added
### Changed
- CASMINST-1412
  -  update static reservation dupe checking logic
### Deprecated
### Removed

## [0.4.13] - 2021-02-16
### Added
### Changed
- CASMINST-1412
  -  update static reservation dupe checking logic
### Deprecated
### Removed

## [0.4.12] - 2021-02-07
### Added
### Changed
- CASMINST-1325
  -  fix type-o in dhcp-helper.py
### Deprecated
### Removed

## [0.4.11] - 2021-02-01
### Added
### Changed
- CASMINST-1190
  -  Update subnet data load to support new CSI data
### Deprecated
### Removed

## [0.4.8] - 2021-01-29
### Added
- CASMINST-1178
  -  Add CAN network support in Kea
### Changed
### Deprecated
### Removed

## [0.4.7] - 2021-01-26
### Added
### Changed
- CASMINST-1108
  -  fix logic to set alias/mac and alias/mac/ip dhcp reservations
### Deprecated
### Removed

## [0.4.6] - 2021-01-25
### Added
- CASMINST-595
  - Added support for DHCP on MTL
### Changed
- fixed fallback logic for loading time server
### Deprecated
### Removed

## [0.4.5] - 2021-01-15
### Added
- CASMINST-952
  - Dupe hostname/ip checks for dhcp reservations from SLS
- CASMINST-923
  - Fallback mechanism to load time servers
- CASMINST-951
  - Logging config reload when it fails without debug mode enabled
### Changed
- CASMINST-898
  - Remove switch info being loaded into dhcp resservations
### Deprecated
### Removed

## [0.4.4] - 2020-12-7
### Added
- CASMNET-376
    - dhcp-helper improved efficiency for scaling by flattening data objects and reducing nested logic complexity
    - enabled dhcp-helper to work with 1.3.x and 1.4+ shasta system
    - added tcpdump to cray-dhcp-kea container
### Changed
### Deprecated
### Removed
- CASMNET-376
    - removed istio proxy wait on cray-dhcp-kea-api
### Fixed
### Security

## [0.4.3] - 2020-10-12
### Added
- CASMNET-370
    - updated dhcp reservation to be assigned under the subnet instead of global reservations
    - loading static ip reservations from SLS
    - added nslookup module to dhcp-helper
    - loading vlan info from SLS in dhcp-helper
    - enabled sanity checks in Kea 
### Changed
- CASMNET-370
    - tftp ip and unbound ip are set with chart values
    - enabled dhcp-helper to work with systems that use dnsmasq and systems without dnsmasq
    - loading SMD ethernet data once unless an interface is updated instead of twice every run
### Deprecated
- CASMNET-370
    - global reservations will be removed once there are no Shasta 1.3 systems in the field
### Removed
### Fixed
### Security

## [0.3.15] - 2020-10-12
### Added
### Changed
- CASMNET-345
    - updated dhcp-helper to set an active lease for dhcp reservations if there is active lease
    - Updated chart values for loggers from DEBUG->ERROR
### Deprecated
### Removed
### Fixed
### Security

## [0.3.15] - 2020-10-6
### Added
### Changed
- CASMNET-340 
    - Updated kea to use "decline-probation-period" option.
    - Removed forcing of IPs to move and let lease expire naturally to move
    - Load vlan information from SLS with dhcp-helper.py
    - added message to configmap
### Deprecated
### Removed
### Fixed
### Security

## [0.3.14] - 2020-09-3
### Added
### Changed
- CASMNET-304 - updated dhcp helper to assign 51 static ips at start of subnet from 26
### Deprecated
### Removed
### Fixed
### Security

## [0.3.13] - 2020-09-3
### Added
### Changed
- CASMNET-299 - dhcp-helper update to remove bad dhcp leaeses with no MAC
- CASMNET-302 - dhcp-helper moved verbose logging to debug
### Deprecated
### Removed
### Fixed
### Security

## [0.3.12] - 2020-08-17
### Added
### Changed
- dhcp-helper LFC schedule update
### Deprecated
### Removed
### Fixed
### Security

## [0.3.11] - 2020-08-12
### Added
### Changed
### Deprecated
### Removed
### Fixed
- fixed patch update to SMD in dhcp-helper
### Security

## [0.3.10] - 2020-08-5
### Added
### Changed
- updated health check to improve logging on failed health checks
- updated health check to check kea server and api health
- updated chart vaules to increase frequency of health checks
- updated dhcp-helper to not add kea hostname name to SMD
- upgraded to Kea 1.7.10 to resolve high port number bug https://gitlab.isc.org/isc-projects/kea/-/issues/1302
### Deprecated
### Removed
### Fixed
### Security

## [0.3.9] - 2020-07-27
### Added
### Changed
- health monitor to not count the grep pid due to race condition
- optmized dhcp-helper to query larger chunks of data from SMD and SLS
- updated resource requests and limits
### Deprecated
### Removed
- removed postgres cluster and moved to in memory DB
### Fixed
### Security

## [0.3.7] - 2020-07-22
### Added
### Changed
- updated health check to be more intelligent
### Deprecated
### Removed
### Fixed
### Security

## [0.3.6] - 2020-07-21
### Added
### Changed
- during the check of active leases, added a second check to remove any active leases on an ip we want to set
### Deprecated
### Removed
### Fixed
### Security

## [0.3.5] - 2020-07-20
### Added
- added logic to get dns masq server ip
### Changed
### Deprecated
### Removed
### Fixed
### Security

## [0.3.4] - 2020-07-16
### Added
### Changed
- update logic to handle malformed network cidr notation.
- change schedule for dhcp-helper from every 60s to every 180s
### Deprecated
### Removed
### Fixed
### Security

## [0.3.3] - 2020-07-15
### Added
### Changed
- update logic to load all subnet info from SLS and check for duplcate subnets.
### Deprecated
### Removed
### Fixed
### Security

## [0.3.2] - 2020-07-15
### Added
- added logic to not load duplicate IPs to SMD for dhcp-helper.py
### Changed
### Deprecated
### Removed
### Fixed
### Security

## [0.3.0] - 2020-07-1
### Added
### Changed
- refactor dhcp-helper
### Deprecated
### Removed
### Fixed
### Security

## [0.1.10] - 2020-06-30
### Added
### Changed
dhcp-helper updates for setting tftp server, proper hostnames for computes on NMN network and changing dns server list ordering(dnsmasq then unbound)
### Deprecated
### Removed
### Fixed
### Security

## [0.1.10] - 2020-06-28
### Added
- added tftp info to dhcp leases
### Changed
### Deprecated
### Removed
### Fixed
### Security

## [0.1.10] - 2020-06-26
### Added
- added dns info to dhcp leases
### Changed
### Deprecated
### Removed
### Fixed
### Security

## [0.1.10] - 2020-06-25
### Added
### Changed
 - updated cray-service version
### Deprecated
### Removed
### Fixed
### Security

## [0.1.10] - 2020-06-11
### Added
- added dhcp-helper.py that will be a job to get data from SMD/SLS to setup dhcp reservations
### Changed
### Deprecated
### Removed
- removed anisble playbook and build files
### Fixed
 - fixed startup-dhcp.sh missing db password
### Security

## [0.1.8] - 2020-05-14
### Added
- added db init script as configmap and mounted on cray-dhcp-kea container
- added startup script to wait for postgres availability
### Changed
### Deprecated
### Removed
- removed init job that watched for postgres-wait container
### Fixed
### Security

## [0.1.5] - 2020-05-14
### Added
### Changed
### Deprecated
### Removed
### Fixed
- Ansible reservations.j2 template had wrong json labels.
### Security

## [0.1.4] - 2020-04-24
### Added
### Changed
- Updated the cray-service base Helm chart to 1.4.0 to take advantage of using the `appVersion` value as the default image tag. When cray-dhcp-kea Helm chart is deployed it will deploy the docker image with the app version specified in the chart, instead of the latest available image.
### Deprecated
### Removed
### Fixed
### Security
