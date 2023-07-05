from urllib.parse import urlparse
from typing import List, Mapping, Optional, Set

from mitmproxy.http import HTTPFlow, Response, Request
import pytest

from kerberos_auth_proxy.mitm.filters.base import NULL_FILTER
from kerberos_auth_proxy.mitm.filters.kerberos import (
    check_knox,
    check_spnego,
    Filter,
)


@pytest.mark.parametrize(
    "spnego_codes,response_code,response_headers,expected_filter", [
        (frozenset([401]), 401, {b'WWW-Authenticate': 'Negotiate'}, NULL_FILTER),
        (frozenset([401]), 401, {}, None),
        (frozenset([401]), 401, {b'WWW-Authenticate': 'Negotiate some stuff'}, NULL_FILTER),
        (frozenset([401]), 401, {b'WWW-Authenticate': 'Negotiate-NonStandard'}, None),
        (frozenset([401]), 429, {b'WWW-Authenticate': 'Negotiate '}, None),
        (frozenset(), 401, {b'WWW-Authenticate': 'Negotiate'}, None),
    ],
)
async def test_check_spnego(
    spnego_codes: Set[int],
    response_code: int,
    response_headers: Mapping[bytes, str],
    expected_filter: Optional[Filter],
):
    response = Response.make(response_code, headers=response_headers)
    flow = HTTPFlow(None, None)
    flow.response = response

    assert await check_spnego(spnego_codes, NULL_FILTER)(flow) == expected_filter


@pytest.mark.parametrize(
    "knox_urls,redirect_codes,response_code,response_headers,expected_filter", [
        ([urlparse("http://knox/some")], frozenset([301]), 301,
            {b'Location': "http://knox/some/stuff"}, NULL_FILTER),
        ([urlparse("http://knox/some")], frozenset([301]), 307,
            {b'Location': "http://knox/some/stuff"}, None),
        ([urlparse("http://knox/some")], frozenset([301]), 301,
            {b'Location': "http://knox/other/path"}, None),
        ([urlparse("http://knox/some")], frozenset(), 301,
            {b'Location': "http://knox/some/stuff"}, None),
    ]
)
async def test_check_knox(
    knox_urls: List[str],
    redirect_codes: Set[int],
    response_code: int,
    response_headers: Mapping[bytes, str],
    expected_filter: Optional[Filter],
):
    response = Response.make(response_code, headers=response_headers)
    flow = HTTPFlow(None, None)
    flow.request = Request.make('GET', 'http://localhost')
    flow.response = response

    assert await check_knox(redirect_codes, knox_urls, '', NULL_FILTER)(flow) == expected_filter


async def test_check_knox_overrides_user_agent():
    knox_url = 'http://knox:8000/'
    urls = [urlparse(knox_url)]
    code = 301
    user_agent = 'curl'
    filter = check_knox({code}, urls, user_agent, NULL_FILTER)

    flow = HTTPFlow(None, None)
    flow.request = Request.make('GET', 'http://app.localhost')
    flow.response = Response.make(code, headers={b'Location': f'{knox_url}/stuff'})

    await filter(flow)
    assert flow.request.headers.get(b'User-Agent') == user_agent
