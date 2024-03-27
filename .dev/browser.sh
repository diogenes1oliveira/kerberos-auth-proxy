#!/usr/bin/env bash

set -euo pipefail

mkdir -p var/firefox

export http_proxy='http://localhost:8081'
export https_proxy='http://localhost:8081'
firefox --profile var/firefox