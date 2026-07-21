{{- define "jarswaf.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "jarswaf.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "jarswaf.labels" -}}
helm.sh/chart: {{ include "jarswaf.name" . }}-{{ .Chart.Version | replace "+" "_" }}
{{ include "jarswaf.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "jarswaf.selectorLabels" -}}
app.kubernetes.io/name: {{ include "jarswaf.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "jarswaf.proxySelectorLabels" -}}
{{ include "jarswaf.selectorLabels" . }}
app.kubernetes.io/component: proxy
{{- end }}

{{- define "jarswaf.controllerSelectorLabels" -}}
{{ include "jarswaf.selectorLabels" . }}
app.kubernetes.io/component: controller
{{- end }}
