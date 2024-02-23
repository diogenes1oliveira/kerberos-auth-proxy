#!/usr/bin/env bash

set -euo pipefail

# source all .sh scripts in /docker-entrypoint-init.d
if [ -d '/docker-entrypoint-init.d' ]; then
  find '/docker-entrypoint-init.d' -type f -name "*.sh" -print0 | sort -z | while IFS= read -r -d $'\0' s; do
    echo >&2 "INFO: sourcing $s"
    source "$s"
  done
fi

exec "$@"
