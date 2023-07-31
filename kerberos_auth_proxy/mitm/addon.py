
import logging
import os
import re
from urllib.parse import ParseResult, urlparse
from typing import FrozenSet, List

from mitmproxy.http import HTTPFlow, Response

from kerberos_auth_proxy.mitm.filters.base import chain_filters
from kerberos_auth_proxy.mitm.filters.kerberos import (
    check_knox,
    check_spnego,
    do_with_kerberos,
    kerberos_flow,
)
from kerberos_auth_proxy.mitm.filters.hosts import (
    remap_request_hosts,
    remap_redirect_response_hosts,
)
from kerberos_auth_proxy.mitm.auth import AuthAddon
from kerberos_auth_proxy.utils import env_to_list, env_to_map

SPNEGO_AUTH_CODES: FrozenSet[int] = frozenset(env_to_list('SPNEGO_AUTH_CODES', int))
KNOX_REDIRECT_CODES: FrozenSet[int] = frozenset(env_to_list('KNOX_REDIRECT_CODES', int))
KNOX_URLS: List[ParseResult] = env_to_list('KNOX_URLS', urlparse)
KNOX_USER_AGENT_OVERRIDE = os.getenv('KNOX_USER_AGENT_OVERRIDE') or ''
KERBEROS_MATCH_HOSTS: List[re.Pattern] = env_to_list('KERBEROS_MATCH_HOSTS', re.compile)
KERBEROS_REALM = os.environ['KERBEROS_REALM']
HOST_MAPPINGS = [(urlparse(k), urlparse(v)) for k, v in env_to_map('HOST_MAPPINGS').items()]
PROXY_HTPASSWD_PATH = os.environ['PROXY_HTPASSWD_PATH']

auth_addon = AuthAddon([u[0].hostname for u in HOST_MAPPINGS], PROXY_HTPASSWD_PATH)


class KerberosAddon:
    def __init__(self):
        self.request_flow = remap_request_hosts(HOST_MAPPINGS)

        kerberos_filter = kerberos_flow(
            KERBEROS_REALM,
            check_spnego(SPNEGO_AUTH_CODES, do_with_kerberos()),
            check_knox(KNOX_REDIRECT_CODES, KNOX_URLS, KNOX_USER_AGENT_OVERRIDE, do_with_kerberos()),
        )
        self.response_flow = chain_filters(kerberos_filter, remap_redirect_response_hosts())

    async def request(self, flow: HTTPFlow):
        '''
        Remaps the hosts
        '''
        if not auth_addon.assert_auth(flow):
            logging.info('not authenticated')
        else:
            await self.request_flow(flow)

    async def response(self, flow: HTTPFlow):
        '''
        Retries requests with recognized non-authorized responses using Kerberos/GSSAPI
        '''
        if not auth_addon.assert_auth(flow):
            logging.info('not authenticated')
            return

        logging.debug('final request %s %s://%s:%s%s %s', flow.request.method,
                      flow.request.scheme,
                      flow.request.host,
                      flow.request.port,
                      flow.request.path,
                      flow.request.headers,
                      )
        logging.debug('original response status=%s %s', flow.response.status_code, flow.response.headers)
        await self.response_flow(flow)
        if not flow.response:
            flow.response = Response.make(500, b'No data', {'Content-type': 'text/plain'})
            logging.error('filtering deleted the whole response')


logging.basicConfig(level=logging.DEBUG)

addons = [auth_addon, KerberosAddon()]
