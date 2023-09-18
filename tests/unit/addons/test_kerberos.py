from urllib.parse import urlparse
from typing import List, Mapping, Set

from kerberos_auth_proxy.utils import no_warnings
with no_warnings(DeprecationWarning):
    from mitmproxy.http import HTTPFlow, Response, Request
import pytest

from kerberos_auth_proxy.mitm.addons.kerberos import (
    check_spnego,
    check_knox,
)


@pytest.mark.parametrize(
    "spnego_codes,response_code,response_headers,expected_result", [
        (frozenset([401]), 401, {b'WWW-Authenticate': 'Negotiate'}, True),
        (frozenset([401]), 401, {}, False),
        (frozenset([401]), 401, {b'WWW-Authenticate': 'Negotiate some stuff'}, True),
        (frozenset([401]), 401, {b'WWW-Authenticate': 'Negotiate-NonStandard'}, False),
        (frozenset([401]), 429, {b'WWW-Authenticate': 'Negotiate '}, False),
        (frozenset(), 401, {b'WWW-Authenticate': 'Negotiate'}, False),
    ],
)
async def test_check_spnego(
    spnego_codes: Set[int],
    response_code: int,
    response_headers: Mapping[bytes, str],
    expected_result: bool,
):
    response = Response.make(response_code, headers=response_headers)
    flow = HTTPFlow(None, None)
    flow.response = response

    assert check_spnego(spnego_codes)(flow) == expected_result


@pytest.mark.parametrize(
    "knox_urls,redirect_codes,response_code,response_headers,expected_result", [
        ([urlparse("http://knox/some")], frozenset([301]), 301,
            {b'Location': "http://knox/some/stuff"}, True),
        ([urlparse("http://knox/some")], frozenset([301]), 307,
            {b'Location': "http://knox/some/stuff"}, False),
        ([urlparse("http://knox/some")], frozenset([301]), 301,
            {b'Location': "http://knox/other/path"}, False),
        ([urlparse("http://knox/some")], frozenset(), 301,
            {b'Location': "http://knox/some/stuff"}, False),
    ]
)
async def test_check_knox(
    knox_urls: List[str],
    redirect_codes: Set[int],
    response_code: int,
    response_headers: Mapping[bytes, str],
    expected_result: bool,
):
    response = Response.make(response_code, headers=response_headers)
    flow = HTTPFlow(None, None)
    flow.request = Request.make('GET', 'http://localhost')
    flow.response = response

    assert check_knox(redirect_codes, knox_urls, '')(flow) == expected_result


async def test_check_knox_overrides_user_agent():
    knox_url = 'http://knox:8000/'
    urls = [urlparse(knox_url)]
    code = 301
    user_agent = 'curl'
    filter = check_knox({code}, urls, user_agent)

    flow = HTTPFlow(None, None)
    flow.request = Request.make('GET', 'http://app.localhost')
    flow.response = Response.make(code, headers={b'Location': f'{knox_url}/stuff'})

    assert filter(flow)
    assert flow.request.headers.get(b'User-Agent') == user_agent
