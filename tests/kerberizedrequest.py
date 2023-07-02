#!/usr/bin/env python3

import os
from pprint import pprint
import tempfile
import subprocess
import sys

from mitmproxy.http import HTTPFlow, Request

from kerberos_auth_proxy.mitm.filters import do_with_kerberos, METADATA_KERBEROS_PRINCIPAL

URL, PRINCIPAL, KEYTAB = sys.argv[1:]

with tempfile.TemporaryDirectory() as tempdir:
    os.environ['KRB5CCNAME'] = os.path.join(tempdir, 'cache.tmp')
    subprocess.run(['kinit', '-kt', KEYTAB, PRINCIPAL], check=True)

    flow = HTTPFlow(None, None)
    flow.request = Request.make('GET', URL)
    flow.metadata[METADATA_KERBEROS_PRINCIPAL] = PRINCIPAL

    do_with_kerberos()(flow)

    pprint({
        'status': flow.response.status_code,
        'content': flow.response.raw_content,
        'headers': flow.response.headers,
    })
