{{/*
Add helper methods here for your chart
*/}}

{{- define "cray-dhcp-kea.image-prefix" -}}
{{ $base := index . "cray-service" }}
{{- if $base.imagesHost -}}
{{- printf "%s/" $base.imagesHost -}}
{{- else -}}
{{- printf "" -}}
{{- end -}}
{{- end -}}