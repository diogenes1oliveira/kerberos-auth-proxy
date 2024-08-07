from logging import getLogger
from typing import Optional
from urllib.parse import urlparse, ParseResult

import aiohttp
from mitmproxy.http import HTTPFlow
from timelength import TimeLength

from kerberos_auth_proxy.kerberos import KerberosCache
from kerberos_auth_proxy.mitm.hostutils import url_matches
from kerberos_auth_proxy.mitm.username import get_username

from kerberos_auth_proxy.mitm.addons.spnego import generate_spnego_negotiate
from kerberos_auth_proxy.utils import ExpiringCache

LOGGER = getLogger(__name__)


class BearerSpnegoAddon:
    def __init__(
        self,
        urls: list[ParseResult],
        token_url: str,
        token_method: Optional[str] = None,
        token_headers: Optional[dict[str, str]] = None,
        expiration: Optional[float] = None,
    ) -> None:
        self.urls = urls
        self.token_url = token_url
        self.token_method = token_method or 'POST'
        self.token_headers = token_headers or {}
        self.expiration = expiration or 10*60
        self.kerberos_cache = KerberosCache()
        self.token_cache = ExpiringCache[str](
            init=self._get_token,
            expiration=expiration or 10*60,
        )

    async def _get_token(self, username: str) -> str:
        return await generate_bearer_spnego_token(
            cache=self.kerberos_cache,
            username=username,
            token_url=self.token_url,
            token_method=self.token_method,
            token_headers=self.token_headers,
        )

    @classmethod
    def create(
        cls,
        urls: list[str],
        token_url: str,
        token_method: Optional[str] = None,
        token_headers: Optional[dict[str, str]] = None,
        expiration: Optional[str] = None,
    ) -> 'BearerSpnegoAddon':
        return cls(
            urls=list(map(urlparse, urls or [])),
            token_url=token_url,
            token_method=token_method,
            token_headers=token_headers,
            expiration=TimeLength(expiration).total_seconds if expiration else None,
        )

    async def request(self, flow: HTTPFlow):
        flow_url = urlparse(flow.request.url)
        if not (username := get_username(flow)):
            LOGGER.debug('skipping Bearer SPNEGO flow, no valid username')
            return

        if not any(url_matches(url, flow_url) for url in self.urls):
            LOGGER.debug('skipping Bearer SPNEGO flow, URL does not match: %s', flow.request.url)
            return

        token, _ = await self.token_cache.get(username)
        if token:
            flow.request.headers[b'Authorization'] = f'Bearer {token}'


async def generate_bearer_spnego_token(
    cache: KerberosCache,
    username: str,
    token_url: str,
    token_method: str,
    token_headers: Optional[dict[str, str]] = None,
) -> Optional[str]:
    token_headers = token_headers or {}
    authority = urlparse(token_url).netloc
    negotiate = await generate_spnego_negotiate(
        cache=cache,
        username=username,
        authority=authority,
    )
    headers = {**token_headers, 'Authorization': negotiate}

    LOGGER.info('generating Bearer SPNEGO token from %s %s', token_method, token_url)
    async with aiohttp.ClientSession() as session:
        async with session.request(method=token_method, url=token_url, headers=headers) as response:
            if response.ok:
                return await response.text()
            else:
                LOGGER.warning('request failed with status=%d: %r', response.status, await response.text())
