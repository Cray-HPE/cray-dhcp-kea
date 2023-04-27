{{/* vim: set filetype=mustache: */}}
{{/*

{{/*
Expand the name of the chart.
*/}}
{{- define "cray-dhcp-kea.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a fully qualified app name
*/}}
{{- define "cray-dhcp-kea.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

<<<<<<< HEAD
{{/*
Create a global for the Chart.yaml appVersion field.
*/}}
{{- define "cray-dhcp-kea.app-version" -}}
{{- default "latest" .Values.global.appVersion | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "cray-dhcp-kea.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
A common set of labels to apply to resources.
*/}}
=======

>>>>>>> f5238ad (- CASMNET-2107 - addional comments)
{{- define "cray-dhcp-kea.labels" }}
helm.sh/chart: {{ include "cray-dhcp-kea.chart" . }}
app.kubernetes.io/name: {{ include "cray-dhcp-kea.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
<<<<<<< HEAD
{{- end -}}
=======
{{- end -}}
>>>>>>> f5238ad (- CASMNET-2107 - addional comments)
