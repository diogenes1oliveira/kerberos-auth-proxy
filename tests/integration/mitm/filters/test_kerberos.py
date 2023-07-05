import json
import os

from mitmproxy.http import HTTPFlow, Request
import pytest

from kerberos_auth_proxy.mitm.filters.kerberos import (
    do_with_kerberos,
    METADATA_KERBEROS_PRINCIPAL,
)

if not os.path.exists(os.getenv('KRB5CCNAME') or ''):
    pytest.skip("no credentials cache in $KRB5CCNAME, can't run integration test", allow_module_level=True)


async def test_do_with_kerberos(kerberosprincipal: str, kerberizedserver: str):
    flow = HTTPFlow(None, None)
    flow.request = Request.make('GET', kerberizedserver + "/private/")
    flow.metadata[METADATA_KERBEROS_PRINCIPAL] = kerberosprincipal

    await do_with_kerberos()(flow)

    data = json.loads(flow.response.content)

    assert flow.response.status_code == 200
    assert data['principal'] == kerberosprincipal
