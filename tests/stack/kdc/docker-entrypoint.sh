#!/usr/bin/env bash

set -euo pipefail

if [ -d '/docker-entrypoint-init.d' ]; then
    echo >&2 "INFO: looking for initialization scripts"

    find '/docker-entrypoint-init.d' -type f -name "*.sh" -print0 | sort -z | while IFS= read -r -d $'\0' s; do
        echo >&2 "INFO: sourcing initialization script $s"
        source "$s"
    done

    echo >&2 "INFO: initialization complete"
fi

exec "$@"
