{{- define "tephra.labels" -}}
app.kubernetes.io/name: tephra
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end }}

{{- define "tephra.agent.selectorLabels" -}}
app.kubernetes.io/name: tephra
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: agent
{{- end }}

{{/* Selector labels of one of the backend components. */}}
{{- define "tephra.selectorLabels" -}}
app.kubernetes.io/name: tephra
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "tephra.lokiUrl" -}}
{{- if .Values.collector.lokiUrl -}}
{{ .Values.collector.lokiUrl }}
{{- else -}}
http://{{ .Release.Name }}-loki.{{ .Release.Namespace }}.svc:3100
{{- end -}}
{{- end }}

{{/* Settings shared by the backend containers: nothing is written to the
image, nothing runs as root, no capability is kept. */}}
{{- define "tephra.restricted" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
capabilities:
  drop: ["ALL"]
seccompProfile:
  type: RuntimeDefault
{{- end }}
