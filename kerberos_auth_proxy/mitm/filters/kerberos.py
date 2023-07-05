'''
Filters for handling Kerberos negotiations
'''

import logging
from typing import List, Optional, Set
from urllib.parse import ParseResult, urlparse

import aiohttp
import gssapi
from requests_gssapi import HTTPSPNEGOAuth
from requests_gssapi.exceptions import SPNEGOExchangeError
from mitmproxy.http import HTTPFlow, Response

from kerberos_auth_proxy.mitm.filters.base import Filter
from kerberos_auth_proxy.mitm.hostutils import url_matches

logger = logging.getLogger(__name__)

METADATA_KERBEROS_PRINCIPAL = 'kerberos_auth_proxy.principal'
METADATA_KERBEROS_WRAPPED = 'kerberos_auth_proxy.wrapped-by-kerberos'
METADATA_HOST_REMAPPED = 'kerberos_auth_proxy.host-remapped'


def check_spnego(unauthorized_codes: Set[int], next_filter: Filter) -> Filter:
    '''
    Adds the next filter to retry the request to the same server if the response was
    a SPNEGO authentication denial.

    Args:
        redirect_codes: recognized HTTP codes for access denial (e.g.: 401, 407)
    '''
    async def filter_check_spnego(flow: HTTPFlow) -> Optional[Filter]:
        www_authenticate = flow.response.headers.get(b'WWW-Authenticate') or ''
        if (
            flow.response.status_code in unauthorized_codes
            and (www_authenticate.startswith('Negotiate ') or www_authenticate == 'Negotiate')
        ):
            logger.info('SPNEGO access denial, will retry with Kerberos')
            return next_filter

    return filter_check_spnego


def check_knox(
    redirect_codes: Set[int],
    knox_urls: List[ParseResult],
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
    async def filter_check_knox(flow: HTTPFlow) -> Optional[Filter]:
        if flow.response.status_code not in redirect_codes:
            logger.debug('not KNOX, unknown redirect code %s', flow.response.status_code)
            return

        if flow.request.method != "GET":
            logger.debug('not KNOX, unknown method %s', flow.request.method)
            return

        location_url = urlparse(flow.response.headers.get(b'Location') or '')

        for knox_url in knox_urls:
            if not url_matches(knox_url, location_url):
                continue

            if user_agent_override:
                flow.request.headers[b'User-Agent'] = user_agent_override
                logger.info('KNOX redirect, will retry with Kerberos overriding the user agent')
            else:
                logger.info('KNOX redirect, will retry with Kerberos')

            return next_filter
        else:
            logger.debug('not a recognized KNOX redirect')

    return filter_check_knox


def do_with_kerberos(
    next_filter: Optional[Filter] = None,
) -> Filter:
    '''
    Sends the request with Kerberos authentication.

    This requires the flow.metadata[METADATA_KERBEROS_PRINCIPAL] to point to the principal full name
    (i.e., with the realm spec) and such principal to already be authenticated in the ticket cache
    '''
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
            logger.exception('error while generating SPNEGO header')
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


def kerberos_flow(
    realm: str,
    spnego_filter: Filter,
    knox_filter: Filter,
) -> Filter:
    '''
    Sets the kerberos.metadata[METADATA_KERBEROS_PRINCIPAL] based on the authentication
    '''
    async def filter_kerberos_flow(flow: HTTPFlow) -> Optional[Filter]:
        proxy_auth = flow.metadata.get('proxyauth')
        if not proxy_auth:
            logger.info('no authenticated user, skipping Kerberos flow')
            return

        username = proxy_auth[0]
        principal = f'{username}@{realm}'
        flow.metadata[METADATA_KERBEROS_PRINCIPAL] = principal
        logger.info('enabling Kerberos flow with principal %s', principal)

        return (await spnego_filter(flow)) or (await knox_filter(flow))

    return filter_kerberos_flow
