#!/usr/bin/env bash

set -euo pipefail

# Initialize Kerberos

kdb5_util -P "$KDC_MASTER_PASSWORD" -r "$KERBEROS_REALM" create -s
echo >&2 "INFO: realm $KERBEROS_REALM initialized"
