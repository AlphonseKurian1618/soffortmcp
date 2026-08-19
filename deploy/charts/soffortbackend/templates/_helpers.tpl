{{- define "soffortbackend.name" -}}
soffortbackend
{{- end }}

{{- define "soffortbackend.fullname" -}}
soffortbackend
{{- end }}

{{- define "soffortbackend.labels" -}}
app.kubernetes.io/name: {{ include "soffortbackend.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: soffortbackend
{{- end }}

{{- define "soffortbackend.selectorLabels" -}}
app.kubernetes.io/name: {{ include "soffortbackend.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

