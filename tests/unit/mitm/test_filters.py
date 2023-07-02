import importlib
import json
import os
from typing import List, Mapping

from mitmproxy.http import HTTPFlow, Response, Request
import pytest

from kerberos_auth_proxy.mitm import filters

KERBEROS_FILTER = filters.do_with_kerberos.__name__
HEADERS_FILTER = filters.add_headers({}).__name__


@pytest.mark.parametrize(
    "spnego_codes,response_code,response_headers,expected_filters", [
        ('401', 401, {b'WWW-Authenticate': 'Negotiate'}, [KERBEROS_FILTER]),
        ('401', 401, {}, []),
        ('401', 401, {b'WWW-Authenticate': 'Negotiate some stuff'}, [KERBEROS_FILTER]),
        ('401', 401, {b'WWW-Authenticate': 'Negotiate-NonStandard'}, []),
        ('401', 429, {b'WWW-Authenticate': 'Negotiate '}, []),
        ('', 401, {b'WWW-Authenticate': 'Negotiate'}, []),
    ],
)
def test_check_spnego(
    spnego_codes: str,
    response_code: int,
    response_headers: Mapping[bytes, str],
    expected_filters: bool,
):
    response = Response.make(response_code, headers=response_headers)
    flow = HTTPFlow(None, None)
    flow.response = response

    os.environ['SPNEGO_AUTH_CODES'] = spnego_codes
    _reload()

    names = [f.__name__ for f in filters.check_spnego(flow) or []]
    assert names == expected_filters


@pytest.mark.parametrize(
    "knox_urls,knox_redirect_codes,response_code,override_user_agent,response_headers,expected_filters", [
        ("http://knox/some", "301", 301, None,
            {b'Location': "http://knox/some/stuff"}, [KERBEROS_FILTER]),
        ("http://knox/some", "301", 301, 'curl',
            {b'Location': "http://knox/some/stuff"}, [HEADERS_FILTER, KERBEROS_FILTER]),
        ("http://knox/some", "301", 307, None,
            {b'Location': "http://knox/some/stuff"}, []),
        ("http://knox/some", "301", 301, None,
            {b'Location': "http://knox/other/path"}, []),
        ("http://knox/some", "", 301, None,
            {b'Location': "http://knox/some/stuff"}, []),
    ]
)
def test_check_knox(
    knox_urls: str,
    knox_redirect_codes: str,
    response_code: int,
    override_user_agent: str,
    response_headers: Mapping[bytes, str],
    expected_filters: List[str],
):
    response = Response.make(response_code, headers=response_headers)
    flow = HTTPFlow(None, None)
    flow.response = response

    os.environ['KNOX_URLS'] = knox_urls
    os.environ['KNOX_REDIRECT_CODES'] = knox_redirect_codes
    os.environ['KNOX_USER_AGENT_OVERRIDE'] = override_user_agent
    _reload()

    names = [f.__name__ for f in filters.check_knox(flow) or []]
    assert names == expected_filters


def test_do_with_kerberos(kerberosprincipal: str, kerberizedserver: str):
    flow = HTTPFlow(None, None)
    flow.request = Request.make('GET', kerberizedserver + "/private/")
    flow.metadata['kerberos_principal'] = kerberosprincipal

    filters.do_with_kerberos(flow)

    data = json.loads(flow.response.content)

    assert flow.response.status_code == 200
    assert data['principal'] == kerberosprincipal


def _reload():
    global filters
    filters = importlib.reload(filters)
