{{- define "kerberos-auth-proxy.mitm-cert-name" }}
{{- printf "%s:%s" .Values.mitm.caKey .Values.mitm.caPem | sha256sum | trunc 10 | printf "mitm-cert-%s" -}}
{{- end }}

{{- define "kerberos-auth-proxy.mitm-auth-name" }}
{{- if not .Values.mitm.authPassword -}}
{{- sha256sum "" | trunc 10 | printf "mitm-auth-%s" -}}
{{- else -}}
{{- printf "%s:%s" .Values.mitm.authPassword (.Values.kerberos.keytabs | keys | sortAlpha | toJson) | sha256sum | trunc 10 | printf "mitm-auth-%s" -}}
{{- end -}}
{{- end }}

{{- define "kerberos-auth-proxy.trust-cas-name" }}
{{- .Values.trustCAs | toJson | sha256sum | trunc 10 | printf "trust-cas-%s" -}}
{{- end }}

{{- define "kerberos-auth-proxy.kerberos-conf-name" }}
{{- .Values.kerberos.krb5Conf | sha256sum | trunc 10 | printf "kerberos-conf-%s" -}}
{{- end }}

{{- define "kerberos-auth-proxy.kerberos-keytabs-name" }}
{{- .Values.kerberos.keytabs | toJson | sha256sum | trunc 10 | printf "kerberos-keytabs-%s" -}}
{{- end }}
