
import logging
import os
import re
from urllib.parse import ParseResult, urlparse
from typing import FrozenSet, List

from mitmproxy.http import HTTPFlow, Response

from kerberos_auth_proxy.mitm.filters import (
    check_knox,
    check_spnego,
    do_with_kerberos,
    kerberos_flow,
)
from kerberos_auth_proxy.utils import env_to_list

SPNEGO_AUTH_CODES: FrozenSet[int] = frozenset(env_to_list('SPNEGO_AUTH_CODES', int))
KNOX_REDIRECT_CODES: FrozenSet[int] = frozenset(env_to_list('KNOX_REDIRECT_CODES', int))
KNOX_URLS: List[ParseResult] = env_to_list('KNOX_URLS', urlparse)
KNOX_USER_AGENT_OVERRIDE = os.getenv('KNOX_USER_AGENT_OVERRIDE') or ''
KERBEROS_MATCH_HOSTS: List[re.Pattern] = env_to_list('KERBEROS_MATCH_HOSTS', re.compile)
KERBEROS_REALM = os.environ['KERBEROS_REALM']

KERBEROS_FILTER = do_with_kerberos()

KERBEROS_FILTER = kerberos_flow(
    KERBEROS_REALM,
    check_spnego(SPNEGO_AUTH_CODES, KERBEROS_FILTER),
    check_knox(KNOX_REDIRECT_CODES, KNOX_URLS, KNOX_USER_AGENT_OVERRIDE, KERBEROS_FILTER),
)


class Addon:
    async def response(self, flow: HTTPFlow):
        '''
        Retries requests with recognized non-authorized responses using Kerberos/GSSAPI
        '''
        await KERBEROS_FILTER(flow)
        if not flow.response:
            flow.response = Response.make(500, b'No data', {'Content-type': 'text/plain'})
            logging.error('filtering deleted the whole response')


addons = [Addon()]
