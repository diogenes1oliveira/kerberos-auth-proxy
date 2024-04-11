#!/usr/bin/env bash

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
mkdir -p var/firefox

export http_proxy='http://localhost:8081'
export https_proxy='http://localhost:8081'
firefox --profile var/firefox
