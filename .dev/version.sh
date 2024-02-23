#!/bin/sh

set -eu

version="$(
    grep -E '^version' pyproject.toml \
        | head -n 1 \
        | awk -F '"' '{print $2}'
)"

if [ -z "$version" ]; then
    echo >&2 "ERROR: failed to get version"
    exit 1
fi

if [ -t 1 ]; then
    echo "$version"
else
    printf '%s' "$version"
fi
