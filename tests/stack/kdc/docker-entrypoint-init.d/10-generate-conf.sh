#!/usr/bin/env bash

set -euo pipefail

# Generate the krb5.conf from environment substitution on krb5.conf.template

if ! [ -e "$KRB5_CONFIG" ]; then
    if [ -e "$KRB5_CONFIG_TEMPLATE" ]; then
        envsubst <"$KRB5_CONFIG_TEMPLATE" >"$KRB5_CONFIG"
        chown "$USER_UID:$USER_GID" "$KRB5_CONFIG"

        echo >&2 "INFO: generated $KRB5_CONFIG via environment substitution in template $KRB5_CONFIG_TEMPLATE"
    else
        echo >&2 "ERROR: configuration file $KRB5_CONFIG doesn't exist, neither does a template $KRB5_CONFIG_TEMPLATE"
        exit 1
    fi
else
    echo >&2 "INFO: using configuration file at $KRB5_CONFIG"
fi
