{{- define "apigw.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "apigw.fullname" -}}
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

{{- define "apigw.selectorLabels" -}}
app.kubernetes.io/name: {{ include "apigw.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "apigw.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "apigw.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "apigw.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "apigw.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "apigw.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{- define "apigw.tlsSecretName" -}}
{{- if .Values.tls.certManager.enabled }}
{{- default (printf "%s-tls" (include "apigw.fullname" .)) .Values.tls.existingSecret }}
{{- else }}
{{- required "set tls.existingSecret or tls.certManager.enabled: every apigw listener is TLS" .Values.tls.existingSecret }}
{{- end }}
{{- end }}

{{/* OTEL_RESOURCE_ATTRIBUTES from a map: key=value pairs, sorted by key. */}}
{{- define "apigw.resourceAttributes" -}}
{{- $pairs := list }}
{{- range $key, $value := . }}
{{- $pairs = append $pairs (printf "%s=%s" $key (toString $value)) }}
{{- end }}
{{- join "," $pairs }}
{{- end }}

{{/* Fails the render unless exactly one API source is set, as apigw itself requires. */}}
{{- define "apigw.validateSource" -}}
{{- $sources := 0 }}
{{- if .Values.api.restApiId }}{{ $sources = add1 $sources }}{{ end }}
{{- if .Values.api.httpApiId }}{{ $sources = add1 $sources }}{{ end }}
{{- if .Values.api.domainNames }}{{ $sources = add1 $sources }}{{ end }}
{{- if .Values.api.openapiFile }}{{ $sources = add1 $sources }}{{ end }}
{{- if ne $sources 1 }}
{{- fail "set exactly one of api.restApiId, api.httpApiId, api.domainNames, or api.openapiFile" }}
{{- end }}
{{- if and (or .Values.api.restApiId .Values.api.httpApiId) (not .Values.api.stage) }}
{{- fail "api.stage is required with api.restApiId or api.httpApiId" }}
{{- end }}
{{- if and .Values.api.domainNames (or .Values.api.stage .Values.api.basePath) }}
{{- fail "api.domainNames cannot be combined with api.stage or api.basePath" }}
{{- end }}
{{- if and (eq .Values.api.domainCertSource "acm") (not .Values.api.domainNames) }}
{{- fail "api.domainCertSource acm needs api.domainNames" }}
{{- end }}
{{- end }}
