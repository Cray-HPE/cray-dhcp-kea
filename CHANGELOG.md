# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
