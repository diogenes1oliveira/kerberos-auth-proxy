#!/bin/sh

set -eu

i=0
MAX_TRIES="${MAX_TRIES:-20}"

echo >&2 "INFO: trying to run $*"

while [ "$i" -le "$MAX_TRIES" ]; do
    if "$@"; then
        echo >&2 "INFO: command succeeded"
        exit 0
    fi

    echo >&2 "INFO: command failed ($i/$MAX_TRIES), trying again in 3s"
    i="$((i + 1))"
    sleep 3
done

echo >&2 "INFO: command failed"
exit 1
