#!/usr/bin/env bash

if [ -d /usr/local/share/ca-certificates/ ] && ! [ -z "$(find /usr/local/share/ca-certificates/ -name '*.crt')" ]; then
    echo >&2 "INFO: adding trust CAs at /usr/local/share/ca-certificates/"
    update-ca-certificates --verbose
else
    echo >&2 "INFO: no .crt files at /usr/local/share/ca-certificates/, skipping trust CAs"
fi
