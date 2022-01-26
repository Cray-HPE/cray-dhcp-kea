# cray-dhcp-kea

![Version: 0.10.1](https://img.shields.io/badge/Version-0.10.1-informational?style=flat-square) ![AppVersion: 0.10.0](https://img.shields.io/badge/AppVersion-0.10.0-informational?style=flat-square)


Kubernetes resources for cray-dhcp-kea

**Homepage:** <https://github.com/Cray-HPE/cray-dhcp-kea>

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| dle-hpe |  |  |

## Requirements

| Repository | Name | Version |
|------------|------|---------|
| https://artifactory.algol60.net/artifactory/csm-helm-charts/ | cray-service | ^7.0.1 |

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| cray-service.containers.cray-dhcp-kea-ctrl-agent.command[0] | string | `"sh"` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.command[1] | string | `"-c"` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.command[2] | string | `"/srv/kea/startup-dhcp-ctrl-agent.sh"` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.env[0].name | string | `"DHCP_CAHOST"` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.env[0].value | string | `"0.0.0.0"` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.env[1].name | string | `"DHCP_CAPORT"` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.env[1].value | string | `"8000"` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.image.repository | string | `"artifactory.algol60.net/csm-docker/stable/cray-dhcp-kea"` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.livenessProbe.exec.command[0] | string | `"/bin/sh"` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.livenessProbe.exec.command[1] | string | `"-c"` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.livenessProbe.exec.command[2] | string | `"/srv/kea/health-check.sh"` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.livenessProbe.initialDelaySeconds | int | `30` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.livenessProbe.periodSeconds | int | `60` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.livenessProbe.timeoutSeconds | int | `20` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.name | string | `"cray-dhcp-kea-ctrl-agent"` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.ports[0].containerPort | int | `8000` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.ports[0].name | string | `"kea-ctrl-tcp"` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.ports[0].protocol | string | `"TCP"` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.readinessProbe.initialDelaySeconds | int | `30` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.readinessProbe.periodSeconds | int | `60` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.readinessProbe.tcpSocket.port | int | `8000` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.volumeMounts[0].mountPath | string | `"/cray-dhcp-kea-socket"` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.volumeMounts[0].name | string | `"cray-dhcp-kea-socket"` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.volumeMounts[0].subPath | string | `"cray-dhcp-kea-socket"` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.volumeMounts[1].mountPath | string | `"/srv/kea"` |  |
| cray-service.containers.cray-dhcp-kea-ctrl-agent.volumeMounts[1].name | string | `"cray-dhcp-kea-jobs"` |  |
| cray-service.containers.cray-dhcp-kea.command[0] | string | `"sh"` |  |
| cray-service.containers.cray-dhcp-kea.command[1] | string | `"-c"` |  |
| cray-service.containers.cray-dhcp-kea.command[2] | string | `"/srv/kea/startup-dhcp.sh"` |  |
| cray-service.containers.cray-dhcp-kea.env[0].name | string | `"TFTP_SERVER_NMN"` |  |
| cray-service.containers.cray-dhcp-kea.env[0].value | string | `"10.92.100.60"` |  |
| cray-service.containers.cray-dhcp-kea.env[1].name | string | `"TFTP_SERVER_HMN"` |  |
| cray-service.containers.cray-dhcp-kea.env[1].value | string | `"10.94.100.60"` |  |
| cray-service.containers.cray-dhcp-kea.env[2].name | string | `"UNBOUND_SERVER_NMN"` |  |
| cray-service.containers.cray-dhcp-kea.env[2].value | string | `"10.92.100.225"` |  |
| cray-service.containers.cray-dhcp-kea.env[3].name | string | `"UNBOUND_SERVER_HMN"` |  |
| cray-service.containers.cray-dhcp-kea.env[3].value | string | `"10.94.100.225"` |  |
| cray-service.containers.cray-dhcp-kea.env[4].name | string | `"NMN_LOADBALANCER_IP"` |  |
| cray-service.containers.cray-dhcp-kea.env[4].value | string | `"10.92.100.222"` |  |
| cray-service.containers.cray-dhcp-kea.env[5].name | string | `"HMN_LOADBALANCER_IP"` |  |
| cray-service.containers.cray-dhcp-kea.env[5].value | string | `"10.94.100.222"` |  |
| cray-service.containers.cray-dhcp-kea.env[6].name | string | `"DHCP_HELPER_INTERVAL_SECONDS"` |  |
| cray-service.containers.cray-dhcp-kea.env[6].value | string | `"120"` |  |
| cray-service.containers.cray-dhcp-kea.image.repository | string | `"artifactory.algol60.net/csm-docker/stable/cray-dhcp-kea"` |  |
| cray-service.containers.cray-dhcp-kea.livenessProbe.exec.command[0] | string | `"/bin/sh"` |  |
| cray-service.containers.cray-dhcp-kea.livenessProbe.exec.command[1] | string | `"-c"` |  |
| cray-service.containers.cray-dhcp-kea.livenessProbe.exec.command[2] | string | `"/srv/kea/health-check.sh"` |  |
| cray-service.containers.cray-dhcp-kea.livenessProbe.initialDelaySeconds | int | `30` |  |
| cray-service.containers.cray-dhcp-kea.livenessProbe.periodSeconds | int | `60` |  |
| cray-service.containers.cray-dhcp-kea.livenessProbe.timeoutSeconds | int | `20` |  |
| cray-service.containers.cray-dhcp-kea.name | string | `"cray-dhcp-kea"` |  |
| cray-service.containers.cray-dhcp-kea.ports[0].containerPort | int | `6067` |  |
| cray-service.containers.cray-dhcp-kea.ports[0].name | string | `"kea-server-udp"` |  |
| cray-service.containers.cray-dhcp-kea.ports[0].protocol | string | `"UDP"` |  |
| cray-service.containers.cray-dhcp-kea.ports[1].containerPort | int | `6067` |  |
| cray-service.containers.cray-dhcp-kea.ports[1].name | string | `"kea-server-tcp"` |  |
| cray-service.containers.cray-dhcp-kea.ports[1].protocol | string | `"TCP"` |  |
| cray-service.containers.cray-dhcp-kea.readinessProbe.exec.command[0] | string | `"/bin/sh"` |  |
| cray-service.containers.cray-dhcp-kea.readinessProbe.exec.command[1] | string | `"-c"` |  |
| cray-service.containers.cray-dhcp-kea.readinessProbe.exec.command[2] | string | `"/srv/kea/health-check.sh"` |  |
| cray-service.containers.cray-dhcp-kea.readinessProbe.initialDelaySeconds | int | `30` |  |
| cray-service.containers.cray-dhcp-kea.readinessProbe.periodSeconds | int | `60` |  |
| cray-service.containers.cray-dhcp-kea.resources.limits.cpu | string | `"6"` |  |
| cray-service.containers.cray-dhcp-kea.resources.limits.memory | string | `"3Gi"` |  |
| cray-service.containers.cray-dhcp-kea.resources.requests.cpu | string | `"2"` |  |
| cray-service.containers.cray-dhcp-kea.resources.requests.memory | string | `"1Gi"` |  |
| cray-service.containers.cray-dhcp-kea.volumeMounts[0].mountPath | string | `"/cray-dhcp-kea-socket"` |  |
| cray-service.containers.cray-dhcp-kea.volumeMounts[0].name | string | `"cray-dhcp-kea-socket"` |  |
| cray-service.containers.cray-dhcp-kea.volumeMounts[0].subPath | string | `"cray-dhcp-kea-socket"` |  |
| cray-service.containers.cray-dhcp-kea.volumeMounts[1].mountPath | string | `"/srv/kea"` |  |
| cray-service.containers.cray-dhcp-kea.volumeMounts[1].name | string | `"cray-dhcp-kea-jobs"` |  |
| cray-service.nameOverride | string | `"cray-dhcp-kea"` |  |
| cray-service.podAnnotations."traffic.sidecar.istio.io/excludeOutboundPorts" | string | `"6067"` |  |
| cray-service.priorityClassName | string | `"csm-high-priority-service"` |  |
| cray-service.service.enabled | bool | `false` |  |
| cray-service.type | string | `"Deployment"` |  |
| cray-service.volumes.cray-dhcp-kea-jobs.configMap.defaultMode | int | `511` |  |
| cray-service.volumes.cray-dhcp-kea-jobs.configMap.name | string | `"cray-dhcp-kea-jobs"` |  |
| cray-service.volumes.cray-dhcp-kea-jobs.name | string | `"cray-dhcp-kea-jobs"` |  |
| cray-service.volumes.cray-dhcp-kea-socket.emptyDir | object | `{}` |  |
| cray-service.volumes.cray-dhcp-kea-socket.name | string | `"cray-dhcp-kea-socket"` |  |
| crayDhcpKeaCtrlAgentConfig.Control-agent.control-sockets.dhcp4.socket-name | string | `"/cray-dhcp-kea-socket/cray-dhcp-kea.socket"` |  |
| crayDhcpKeaCtrlAgentConfig.Control-agent.control-sockets.dhcp4.socket-type | string | `"unix"` |  |
| crayDhcpKeaCtrlAgentConfig.Control-agent.http-host | string | `"0.0.0.0"` |  |
| crayDhcpKeaCtrlAgentConfig.Control-agent.http-port | int | `8000` |  |
| crayDhcpKeaCtrlAgentConfig.Control-agent.loggers[0].name | string | `"cray-dhcp-kea-ctrl-agent"` |  |
| crayDhcpKeaCtrlAgentConfig.Control-agent.loggers[0].output_options[0].output | string | `"stdout"` |  |
| crayDhcpKeaCtrlAgentConfig.Control-agent.loggers[0].severity | string | `"ERROR"` |  |
| global.appVersion | string | `"0.10.0"` |  |
| global.chart.name | string | `"cray-dhcp-kea"` |  |
| global.chart.version | string | `"0.10.0"` |  |
| hmnLoadBalancerIp | string | `"10.94.100.222"` |  |
| nmnLoadBalancerIp | string | `"10.92.100.222"` |  |
| serverPort | int | `6067` |  |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.5.0](https://github.com/norwoodj/helm-docs/releases/v1.5.0)
