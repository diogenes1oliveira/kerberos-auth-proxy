#!/usr/bin/env bash

if [ -f "${MITM_TLS_CA_PEM:-}" ]; then
    if ! [ -f "${MITM_TLS_CA_KEY:-}" ]; then
        echo >&2 "ERROR: CA at '$MITM_TLS_CA_PEM' doesn't have a private key at '$MITM_TLS_CA_KEY'"
        exit 1
    fi

    echo >&2 "INFO: found CA at '$MITM_TLS_CA_PEM' and '$MITM_TLS_CA_KEY'"
    rm -rf "$MITM_SET_CONFDIR"
    mkdir -p "$MITM_SET_CONFDIR"

    cat "$MITM_TLS_CA_PEM" > "$MITM_SET_CONFDIR/mitmproxy-ca.pem"
    echo >> "$MITM_SET_CONFDIR/mitmproxy-ca.pem"
    cat "$MITM_TLS_CA_KEY" >> "$MITM_SET_CONFDIR/mitmproxy-ca.pem"

    echo >&2 "INFO: wrote CA to '$MITM_SET_CONFDIR/mitmproxy-ca.pem'"

elif [ -f "${MITM_TLS_CA_KEY:-}" ]; then
    echo >&2 "ERROR: private key at '$MITM_TLS_CA_KEY' doesn't have a CA at '$MITM_TLS_CA_PEM'"
    exit 1
else
    echo >&2 "WARNING: no CA found, MITM will use its own"
fi

if [ -d /usr/local/share/ca-certificates/ ] && ! [ -z "$(find /usr/local/share/ca-certificates/ -name '*.crt')" ]; then
    echo >&2 "INFO: adding trust CAs at /usr/local/share/ca-certificates/"
    update-ca-certificates --verbose
else
    echo >&2 "INFO: no .crt files at /usr/local/share/ca-certificates/, skipping trust CAs"
fi
