# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
