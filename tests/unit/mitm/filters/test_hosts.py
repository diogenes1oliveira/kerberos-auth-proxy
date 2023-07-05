from typing import Optional, Mapping, Tuple
from urllib.parse import urlparse, ParseResult

from mitmproxy.http import HTTPFlow, Request, Response
import pytest

from kerberos_auth_proxy.mitm.filters.hosts import (
    remap_request_hosts,
    remap_redirect_response_hosts,
    METADATA_MAPPED_URLS,
)

HOST_MAPPINGS = [
    (urlparse('http://example0.com/v1'), urlparse('http://internal0/api/v1')),
    (urlparse('http://example1.com'), urlparse('http://internal1:8080')),
]


@pytest.mark.parametrize(
    "request_url,expected_remapped_url,expected_host_mapping", [
        ('http://example0.com/v1/some/path', 'http://internal0/api/v1/some/path', HOST_MAPPINGS[0]),
        ('http://example0.com/', 'http://example0.com/', None),
        ('http://example1.com/v1/some/path', 'http://internal1:8080/v1/some/path', HOST_MAPPINGS[1]),
    ],
)
async def test_remap_request_hosts(
    request_url: str,
    expected_remapped_url: str,
    expected_host_mapping: Optional[Tuple[ParseResult, ParseResult]],
):
    filter = remap_request_hosts(HOST_MAPPINGS)

    flow = HTTPFlow(None, None)
    flow.request = Request.make('GET', request_url)

    assert (await filter(flow)) is None
    assert flow.metadata.get(METADATA_MAPPED_URLS) == expected_host_mapping
    assert flow.request.url == expected_remapped_url


@pytest.mark.parametrize(
    "host_mapping,status_code,response_headers,expected_headers", [
        (HOST_MAPPINGS[0], 301, {'Location': 'http://internal0/api/v1/some/path'},
         {'Location': 'http://example0.com/v1/some/path'}),
        (HOST_MAPPINGS[0], 200, {'Location': 'http://internal0/api/v1/some/path'},
         {'Location': 'http://internal0/api/v1/some/path'}),
        (None, 301, {'Location': 'http://internal0/api/v1/some/path'},
         {'Location': 'http://internal0/api/v1/some/path'}),
    ],
)
async def test_remap_redirect_response_hosts(
    host_mapping: Optional[Tuple[ParseResult, ParseResult]],
    status_code: int,
    response_headers: Mapping[bytes, str],
    expected_headers: Mapping[bytes, str],
):
    filter = remap_redirect_response_hosts()
    response_headers['Content-Length'] = '0'
    expected_headers['Content-Length'] = '0'

    flow = HTTPFlow(None, None)
    flow.response = Response.make(status_code, headers=response_headers)
    flow.metadata[METADATA_MAPPED_URLS] = host_mapping

    assert (await filter(flow)) is None
    assert dict(flow.response.headers) == expected_headers
