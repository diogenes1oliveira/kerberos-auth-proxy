'''
Filters for handling Kerberos negotiations
'''

import asyncio
import logging
import os
import time
from typing import Callable, Collection, Mapping, Optional, Set
from urllib.parse import ParseResult, urlparse

import aiohttp
import gssapi
from timelength import TimeLength
from requests_gssapi import HTTPSPNEGOAuth
from requests_gssapi.exceptions import SPNEGOExchangeError

from kerberos_auth_proxy.utils import string_to_list, no_warnings
from kerberos_auth_proxy.mitm.hostutils import url_matches

with no_warnings(DeprecationWarning):
    from mitmproxy import ctx
    from mitmproxy.http import HTTPFlow, Response
    from mitmproxy.addonmanager import Loader

logger = logging.getLogger(__name__)

METADATA_PRINCIPAL = 'kerberos_principal'

OPTION_REALM = 'kerberos_realm'
OPTION_SPNEGO_CODES = 'kerberos_spnego_codes'
OPTION_KNOX_URLS = 'kerberos_knox_urls'
OPTION_KNOX_CODES = 'kerberos_knox_codes'
OPTION_KNOX_UA_OVERRIDE = 'kerberos_knox_user_agent_override'
OPTION_KEYTABS_PATH = 'kerberos_keytabs_path'
OPTION_CACHE_EXPIRATION = 'kerberos_cache_expiration'

Predicate = Callable[[HTTPFlow], bool]


def check_spnego(unauthorized_codes: Collection[int]) -> Predicate:
    def check_spnego_predicate(flow: HTTPFlow):
        www_authenticate = flow.response.headers.get(b'WWW-Authenticate') or ''

        if flow.response.status_code not in unauthorized_codes:
            ctx.log.debug(f'not SPNEGO, unknown HTTP code {flow.response.status_code}')
            return False

        if www_authenticate != 'Negotiate' and not www_authenticate.startswith('Negotiate '):
            ctx.log.debug(f'not SPNEGO, unrecognized WWW-Authenticate header {www_authenticate!r}')
            return False

        ctx.log.info('SPNEGO access denial, should retry with Kerberos')
        return True

    return check_spnego_predicate


def check_knox(
    redirect_codes: Collection[int],
    knox_urls: Collection[ParseResult],
    user_agent_override: Optional[str],
) -> Predicate:
    def check_knox_predicate(flow: HTTPFlow):
        if flow.response.status_code not in redirect_codes:
            ctx.log.debug(f'not KNOX, unknown redirect code {flow.response.status_code}')
            return False

        if flow.request.method != "GET":
            ctx.log.debug(f'not KNOX, unsupported HTTP method {flow.request.method!r}')
            return False

        location_header = flow.response.headers.get(b'Location') or ''
        if not location_header:
            ctx.log.debug('not KNOX, no Location header')
            return False

        location_url = urlparse(location_header)

        for knox_url in knox_urls:
            if not url_matches(knox_url, location_url):
                continue

            if user_agent_override:
                flow.request.headers[b'User-Agent'] = user_agent_override
                ctx.log.info('KNOX redirect, should retry with Kerberos overriding the user agent')
            else:
                ctx.log.info('KNOX redirect, should retry with Kerberos')

            return True
        else:
            ctx.log.debug(f"not KNOX, URL {location_header} doesn't any of {knox_urls}")
            return False

    return check_knox_predicate


class KerberosCache:
    def __init__(self, realm: str, keytabs_path: str, expiration: float):
        self.realm = realm
        self.keytabs_path = keytabs_path
        self.expiration = expiration
        self.last_kinits: Mapping[str, float] = {}
        self.principals: Mapping[str, str] = {}
        self.lock = asyncio.Lock()

    async def get_principal(self, username: str, refresh: bool = False) -> Optional[str]:
        if username in self.principals and not refresh:
            return self.principals[username]

        keytab_path = self.get_keytab_path(username)

        ctx.log.debug(f'getting principal from keytab {keytab_path}')
        principal = await self.get_principal_from_keytab(keytab_path)
        if not principal:
            ctx.log.info(f'no credencials available for user {username!r}')
            return

        self.principals[username] = principal
        return principal

    def get_keytab_path(self, username: str) -> str:
        return os.path.join(self.keytabs_path, username + '.keytab')

    async def login(self, username: str, refresh: bool = False) -> Optional[str]:
        '''
        Returns the principal corresponding to the username
        '''
        principal = await self.get_principal(username, refresh=True)
        if not principal:
            ctx.log.info(f'no credencials available for user {username!r}')
            return

        keytab_path = self.get_keytab_path(username)

        ctx.log.debug(f'principal for {username!r} is {principal}, now acquiring cache lock')

        async with self.lock:
            if not refresh and self.has_valid_login(username):
                ctx.log.info(f'now using cached credentials for user {username!r}')
                return principal

            ctx.log.debug(f'getting credencials for {principal} from keytab {keytab_path}')
            process = await asyncio.create_subprocess_exec(
                'kinit', '-kt', keytab_path, principal,
            )
            await process.communicate()
            if process.returncode != 0:
                ctx.log.warn(f'failed to authenticate {username} using principal {principal}')
                return

            self.last_kinits[username] = time.monotonic()
            self.principals[principal] = principal

            ctx.log.debug(f'successfully authenticated {principal} from keytab {keytab_path}')
            return principal

    def has_valid_login(self, username) -> bool:
        last_kinit = self.last_kinits.get(username)
        return last_kinit and time.monotonic() - last_kinit <= self.expiration

    async def get_principal_from_keytab(self, keytab_path: str) -> Optional[str]:
        process = await asyncio.create_subprocess_exec(
            'klist', '-kt', keytab_path,
            stdout=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate()
        if process.returncode != 0:
            return None

        stdout: str = stdout and stdout.decode('ascii') or ''
        for line in stdout.splitlines():
            parts = line.split(' ')
            if parts and parts[-1].endswith('@' + self.realm):
                return parts[-1]


async def generate_spnego_negotiate(host: str, principal: str) -> str:
    def _generate_spnego_negotiate_blocking(host: str, principal: str) -> str:
        name = gssapi.Name(principal, gssapi.NameType.kerberos_principal)
        creds = gssapi.Credentials(name=name, usage="initiate")

        gssapi_auth = HTTPSPNEGOAuth(
            creds=creds,
            opportunistic_auth=True,
            target_name='HTTP',
        )
        return gssapi_auth.generate_request_header(None, host, True)

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _generate_spnego_negotiate_blocking, host, principal)


async def do_with_kerberos(flow: HTTPFlow, principal: str):
    '''
    Sends the request with Kerberos authentication.

    This requires the principal to already be authenticated in the ticket cache
    '''
    try:
        negotiate = await generate_spnego_negotiate(flow.request.host, principal)
        flow.request.headers[b'Authorization'] = negotiate
    except SPNEGOExchangeError:
        ctx.log.warn('error while generating SPNEGO header')
        raise

    async with aiohttp.ClientSession() as session:
        # Prevent aiohttp from injecting its supported encoding schemes
        if b'Accept-Encoding' not in flow.request.headers:
            flow.request.headers[b'Accept-Encoding'] = ''

        kwargs = dict(
            method=flow.request.method,
            url=flow.request.url,
            headers=flow.request.headers,
            data=flow.request.raw_content,
        )

        ctx.log.debug(f'sending Kerberized request with principal {principal}')

        async with session.request(**kwargs) as response:
            ctx.log.debug(f'aiohttp request headers: {response.request_info.headers}')
            flow.response = Response.make(
                status_code=response.status,
                headers=response.raw_headers,
                content=await response.content.read(),
            )
            flow.response.headers.pop('WWW-Authenticate', None)


class KerberosAddon:
    def __init__(self):
        self.is_knox: Predicate = None
        self.is_spnego: Predicate = None
        self.kerberos_cache: KerberosCache = None
        self.configured = False

    def load(self, loader: Loader):
        loader.add_option(
            name=OPTION_REALM,
            typespec=str,
            default="LOCALHOST",
            help="Kerberos realm",
        )
        loader.add_option(
            name=OPTION_SPNEGO_CODES,
            typespec=str,
            default='401',
            help="List of SPNEGO access denial HTTP status codes",
        )
        loader.add_option(
            name=OPTION_KNOX_URLS,
            typespec=str,
            default='',
            help="List of recognized KNOX redirect URLs",
        )
        loader.add_option(
            name=OPTION_KNOX_CODES,
            typespec=str,
            default='302',
            help="List of KNOX redirect HTTP status codes",
        )
        loader.add_option(
            name=OPTION_KNOX_UA_OVERRIDE,
            typespec=str,
            default='curl/7.61.1',
            help="Override User-Agent when retrying requests that yielded KNOX redirects",
        )
        loader.add_option(
            name=OPTION_KEYTABS_PATH,
            typespec=str,
            default='/etc/security/keytabs/',
            help="Path with the .keytab files",
        )
        loader.add_option(
            name=OPTION_CACHE_EXPIRATION,
            typespec=str,
            default='12h',
            help="Kerberos ticket cache expiration time",
        )

    def configure(self, _updated: Optional[Set[str]] = None):
        ctx.log.info('(re)configuring kerberos addon')

        cache_name = os.getenv('KRB5CCNAME') or ''
        if not cache_name.startswith('DIR:'):
            raise ValueError('$KRB5CCNAME should be set to a DIR: type')

        self.kerberos_cache = KerberosCache(
            realm=getattr(ctx.options, OPTION_REALM),
            keytabs_path=getattr(ctx.options, OPTION_KEYTABS_PATH),
            expiration=TimeLength(getattr(ctx.options, OPTION_CACHE_EXPIRATION)).total_seconds,
        )
        self.is_spnego = check_spnego(
            unauthorized_codes=string_to_list(getattr(ctx.options, OPTION_SPNEGO_CODES), int),
        )
        self.is_knox = check_knox(
            redirect_codes=string_to_list(getattr(ctx.options, OPTION_KNOX_CODES), int),
            knox_urls=string_to_list(getattr(ctx.options, OPTION_KNOX_URLS), urlparse),
            user_agent_override=getattr(ctx.options, OPTION_KNOX_UA_OVERRIDE),
        )

    async def response(self, flow: HTTPFlow):
        if not self.is_spnego(flow) and not self.is_knox(flow):
            ctx.log.debug('not a kerberos response, skipping')
            return

        proxy_auth = flow.metadata.get('proxyauth')
        if not proxy_auth:
            ctx.log.info('no authenticated user, skipping Kerberos flow')
            return

        username = proxy_auth[0]

        if self.kerberos_cache.has_valid_login(username):
            ctx.log.info(f'using cached credentials for user {username!r}')
        else:
            await self.kerberos_cache.login(username)

        principal = await self.kerberos_cache.login(username)
        if not principal:
            ctx.log.debug('no credentials available for Kerberos, skipping')
            return

        await do_with_kerberos(flow, principal)


addons = [KerberosAddon()]
