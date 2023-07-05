'''
Filters for handling hosts
'''

import logging
from re import compile, Pattern
from urllib.parse import ParseResult
from typing import Iterable, List, Tuple

from mitmproxy.http import HTTPFlow

from kerberos_auth_proxy.mitm.filters.base import Filter
from kerberos_auth_proxy.mitm.hostutils import (
    request_rebase,
    redirect_rebase,
    url_default_port
)

METADATA_MAPPED_URLS = 'kerberos_auth_proxy.mapped_urls'
METADATA_MAPPED_PROXY = 'kerberos_auth_proxy.mapped_proxy'

PROXY_PATH_PATTERN = compile(
    r'/(?P<scheme>https?)/(?P<netloc>(?P<hostname>[a-z0-9.-]+)(:(?P<port>[0-9]+))?)(?P<path>$|/.*)'
)
logger = logging.getLogger(__name__)


def remap_request_hosts(host_mappings: Iterable[Tuple[ParseResult, ParseResult]]) -> Filter:
    '''
    Remaps external request URLs into internal URLs

    This also sets METADATA_MAPPED_URLS to a tuple of the matched (external_url, internal_url)

    Args:
        hosts_mappings: list of tuples (external_url, internal_url)
    '''
    async def remap_request_hosts_filter(flow: HTTPFlow) -> None:
        for external_url, internal_url in host_mappings:
            if request_rebase(flow.request, external_url, internal_url):
                flow.metadata[METADATA_MAPPED_URLS] = (external_url, internal_url)
                logger.info('Remapped request to %s to the internal URL %s (final URL: %s)',
                            external_url, internal_url, flow.request.url)
                break
        else:
            logger.debug('No URL to remap to, skipping')

    return remap_request_hosts_filter


def remap_redirect_response_hosts() -> Filter:
    '''
    Remaps redirects to internal URLs into the external URLs

    This requires the METADATA_MAPPED_URLS to have a tuple of the matched (external_url, internal_url)

    Args:
        hosts_mappings: list of tuples (external_url, internal_url)
    '''
    async def remap_redirect_response_hosts_filter(flow: HTTPFlow) -> None:
        mapped_urls = flow.metadata.get(METADATA_MAPPED_URLS)
        if not mapped_urls:
            logger.debug('Not an internally remapped request, skipping')
            return

        matcher_url, target_url = mapped_urls
        if redirect_rebase(flow.response, target_url, matcher_url):
            logger.info('Rebased redirect to %s to %s', target_url, matcher_url)
        else:
            logger.info("Internally remapped request didn't return a recognized redirect, nothing to do")
            logger.debug("target_url=%s matcher_url=%s status=%s headers=%s", target_url,
                         matcher_url, flow.response.status_code, flow.response.headers)

    return remap_redirect_response_hosts_filter


def proxy_hosts_request(proxy_hostname: str, allowed_hostnames: List[Pattern]):
    async def proxy_hosts_request_filter(flow: HTTPFlow) -> None:
        if flow.request.host != proxy_hostname:
            logger.debug('Not a proxy request, skipping')
            return

        match = PROXY_PATH_PATTERN.match(flow.request.path)
        if not match:
            logger.debug('Not a valid proxy request, skipping')
            return

        host = match.group('host')
        if not any(h.match(host) for h in allowed_hostnames):
            logger.warn('Not an allowed hostname, skipping')
            return

        original_url = flow.request.url

        flow.request.scheme = match.group('scheme')
        flow.request.host = host
        flow.request.host_header = match.group('netloc')
        flow.request.port = match.group('port') or url_default_port(match.group('scheme'))
        flow.request.path = match.group('path') or ''

        logger.info('rewrote request from %s to %s', original_url, flow.request.url)
        flow.metadata[METADATA_MAPPED_PROXY] = True

    return proxy_hosts_request_filter
