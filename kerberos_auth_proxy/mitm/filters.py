'''
Module containing the built-in MITM filters
'''

import logging
from re import Pattern
from typing import Annotated, Awaitable, Callable, List, Optional, Set
from urllib.parse import ParseResult, urlparse

import aiohttp
import gssapi
from multidict import CIMultiDict, MultiDict
from requests_gssapi import HTTPSPNEGOAuth
from requests_gssapi.exceptions import SPNEGOExchangeError
from mitmproxy.http import Headers, HTTPFlow, Response


Filter = Annotated[
    Callable[[HTTPFlow], Awaitable[Optional['Filter']]],
    'A function that accepts a flow, processes it and optionally returns the next filter to apply'
]
logger = logging.getLogger(__name__)

METADATA_KERBEROS_PRINCIPAL = 'kerberos_auth_proxy.principal'
METADATA_KERBEROS_WRAPPED = 'kerberos_auth_proxy.wrapped-by-kerberos'


def check_spnego(unauthorized_codes: Set[int], next_filter: Filter) -> Filter:
    '''
    Adds the next filter to retry the request to the same server if the response was
    a SPNEGO authentication denial.

    Args:
        redirect_codes: recognized HTTP codes for access denial (e.g.: 401, 407)
    '''
    @debug_filter
    async def filter_check_spnego(flow: HTTPFlow) -> Optional[Filter]:
        www_authenticate = flow.response.headers.get(b'WWW-Authenticate') or ''
        if (
            flow.response.status_code in unauthorized_codes
            and (www_authenticate.startswith('Negotiate ') or www_authenticate == 'Negotiate')
        ):
            logger.info('SPNEGO access denial, will retry with Kerberos')
            # flow.response = None
            return next_filter

    return filter_check_spnego


def check_knox(
    redirect_codes: Set[int],
    urls: List[ParseResult],
    user_agent_override: Optional[str],
    next_filter: Filter,
) -> Filter:
    '''
    Adds the next filter to retry the request to the same server if the response was a redirect to KNOX.

    Args:
        redirect_codes: recognized HTTP codes for redirections (e.g., 301, 307...)
        urls: list of possible KNOX URLs. The retry will be done if the Location header starts with any of these
        user_agent_override: override the request header 'User-Agent' before retrying the request. This can help
            convince some apps we're not a browser so it shouldn't just redirect to KNOX again.
    '''
    @debug_filter
    async def filter_check_knox(flow: HTTPFlow) -> Optional[Filter]:
        if flow.response.status_code not in redirect_codes:
            logging.info('not KNOX, unknown redirect code %s', flow.response.status_code)
            return

        if flow.request.method != "GET":
            logging.info('not KNOX, unknown method %s', flow.request.method)
            return

        location = flow.response.headers.get(b'Location') or ''

        # let's play safe and let Python parse the URL instead of doing a simple .startswith()
        parsed = urlparse(location)
        for u in urls:
            if u.hostname == parsed.hostname and u.port == parsed.port and parsed.path.startswith(u.path):
                if user_agent_override:
                    flow.request.headers[b'User-Agent'] = user_agent_override
                    logger.info('KNOX redirect, will retry with Kerberos overriding the user agent')
                else:
                    logger.info('KNOX redirect, will retry with Kerberos')
                # flow.response = None
                return next_filter

    return filter_check_knox


def do_with_kerberos(
    next_filter: Optional[Filter] = None,
) -> None:
    '''
    Sends the request with Kerberos authentication.

    This requires the flow.metadata[METADATA_KERBEROS_PRINCIPAL] to point to the principal full name
    (i.e., with the realm spec) and such principal to already be authenticated in the ticket cache
    '''
    def _to_headers(headers: Headers) -> MultiDict:
        return CIMultiDict()

    @debug_filter
    async def filter_do_with_kerberos(flow: HTTPFlow) -> Optional[Filter]:
        principal = flow.metadata[METADATA_KERBEROS_PRINCIPAL]
        name = gssapi.Name(principal, gssapi.NameType.kerberos_principal)
        creds = gssapi.Credentials(name=name, usage="initiate")

        gssapi_auth = HTTPSPNEGOAuth(
            creds=creds,
            opportunistic_auth=True,
            target_name='HTTP',
        )
        try:
            negotiate = gssapi_auth.generate_request_header(None, flow.request.host, True)
            flow.request.headers[b'Authorization'] = negotiate
        except SPNEGOExchangeError:
            logger.exception('error while generating header')
            return None

        async with aiohttp.ClientSession() as session:
            kwargs = dict(
                method=flow.request.method,
                url=flow.request.url,
                headers=flow.request.headers,
                data=flow.request.raw_content,
            )

            logger.info(f'sending request with principal {principal}')
            async with session.request(**kwargs) as response:
                flow.response = Response.make(
                    status_code=response.status,
                    headers=response.raw_headers,
                    content=await response.content.read(),
                )
                flow.response.headers.pop('WWW-Authenticate', None)

        flow.metadata[METADATA_KERBEROS_WRAPPED] = True
        return next_filter

    return filter_do_with_kerberos


def match_hosts(host_regexps: List[Pattern], next_filter: Filter) -> Filter:
    """
    Applies the next filter if the hostname matches any of the given regexps

    Args:
        host_regexps: list of regexp patterns to match the host against (including the port)
        next_filter: filter to apply if the host matches
    """
    async def filter_match_hosts(flow: HTTPFlow) -> Optional[Filter]:
        for host_regexp in host_regexps:
            if host_regexp.match(flow.request.host):
                return next_filter

    return filter_match_hosts


def kerberos_flow(
    realm: str,
    spnego_filter: Filter,
    knox_filter: Filter,
) -> None:
    '''
    Sets the kerberos.metadata[METADATA_KERBEROS_PRINCIPAL] based on the authentication
    '''
    @debug_filter
    async def filter_kerberos_flow(flow: HTTPFlow) -> Optional[Filter]:
        username, *_ = list(flow.metadata.get('proxyauth') or []) + ['']
        if not username:
            logger.info('no authenticated user, skipping Kerberos flow')
            return

        principal = f'{username}@{realm}'
        flow.metadata[METADATA_KERBEROS_PRINCIPAL] = principal
        logger.info('enabling Kerberos flow with principal %s', principal)

        filter = await spnego_filter(flow) or await knox_filter(flow)
        if filter:
            return await filter(flow)

    return filter_kerberos_flow


def debug_filter(f):
    # nothing to do by now
    return f
