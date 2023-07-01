#!/usr/bin/env bash

set -euo pipefail

# Create principals and keytabs specified in $KERBEROS_INIT_PRINCIPALS

(
    IFS=$' \t\n,'
    identifiers=(${KERBEROS_INIT_PRINCIPALS:-})

    for identifier in "${identifiers[@]+"${identifiers[@]}"}"; do
        [ -z "$identifier" ] || krb5-setup-principal "$identifier"
    done

)
