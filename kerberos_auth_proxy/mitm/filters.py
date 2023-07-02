'''
Module containing the built-in MITM filters
'''

from contextlib import closing
import os
from typing import Annotated, Callable, List, Optional, Mapping, FrozenSet
from urllib.parse import ParseResult, urlparse

import gssapi
from requests import Request, Session
from requests_gssapi import HTTPSPNEGOAuth
from mitmproxy.http import Headers, HTTPFlow, Response

from kerberos_auth_proxy.utils import env_to_list

Filter = Annotated[
    Callable[[HTTPFlow], Optional[List['Filter']]],
    'A function that accepts a flow and returns a list with the next filters to be applied'
]
Filters = Optional[List['Filter']]


def check_spnego(flow: HTTPFlow) -> Filters:
    '''
    Adds the Kerberos filter if the response is a SPNEGO access denial
    '''
    www_authenticate = flow.response.headers.get(b'WWW-Authenticate') or ''
    if (
        flow.response.status_code in SPNEGO_AUTH_CODES
        and (www_authenticate.startswith('Negotiate ') or www_authenticate == 'Negotiate')
    ):
        return [do_with_kerberos]


def check_knox(flow: HTTPFlow) -> Filters:
    '''
    Adds the Kerberos filter if the response is a redirect to KNOX, overriding the
    request header 'User-Agent' to a non-browser one beforehand
    '''
    if flow.response.status_code not in KNOX_REDIRECT_CODES:
        return

    location = flow.response.headers.get(b'Location') or ''

    # let's play safe and let Python parse the URL instead of doing a simple .startswith()
    parsed = urlparse(location)
    for u in KNOX_URLS:
        if u.hostname == parsed.hostname and u.port == parsed.port and parsed.path.startswith(u.path):
            if KNOX_USER_AGENT_OVERRIDE:
                # so that apps won't presume we're a browser
                return [
                    add_headers({b'User-Agent': KNOX_USER_AGENT_OVERRIDE}),
                    do_with_kerberos,
                ]
            else:
                return [do_with_kerberos]


def add_headers(headers: Mapping[bytes, str]) -> Filter:
    '''
    Creates a filter that adds the specified headers to the request
    '''
    def filter_add_headers(flow: HTTPFlow) -> None:
        flow.request.headers.update(headers)
    return filter_add_headers


def do_with_kerberos(flow: HTTPFlow, opportunistic_auth=True) -> None:
    '''
    Sends the request with Kerberos authentication.

    This requires the flow.metadata['kerberos_principal'] to point to the principal full name
    (i.e., with the realm spec) and such principal to already be authenticated in the ticket cache
    '''
    requests_headers = {h: flow.request.headers.get(h) for h in flow.request.headers}

    with closing(Session()) as session:
        principal = flow.metadata['kerberos_principal']
        name = gssapi.Name(principal, gssapi.NameType.kerberos_principal)
        creds = gssapi.Credentials(name=name, usage="initiate")
        gssapi_auth = HTTPSPNEGOAuth(creds=creds, opportunistic_auth=opportunistic_auth)

        request = Request(
            flow.request.method,
            url=flow.request.url,
            data=flow.request.raw_content,
            headers=requests_headers,
            auth=gssapi_auth,
        )
        prepped = session.prepare_request(request)
        settings = session.merge_environment_settings(prepped.url, {}, None, None, None)
        response = session.send(prepped, **settings)

        # handle gzipped, chunked, etc... responses
        data = response.content
        response.headers.pop('Transfer-Encoding', None)
        response.headers.pop('Content-Encoding', None)
        response.headers['Content-Length'] = str(len(data or b''))

        flow.response = Response.make(
            status_code=response.status_code,
            headers=Headers(**response.headers),
            content=data,
        )


SPNEGO_AUTH_CODES: FrozenSet[int] = frozenset(env_to_list('SPNEGO_AUTH_CODES', int))
KNOX_REDIRECT_CODES: FrozenSet[int] = frozenset(env_to_list('KNOX_REDIRECT_CODES', int))
KNOX_URLS: FrozenSet[ParseResult] = frozenset(env_to_list('KNOX_URLS', urlparse))
KNOX_USER_AGENT_OVERRIDE = os.getenv('KNOX_USER_AGENT_OVERRIDE') or ''
