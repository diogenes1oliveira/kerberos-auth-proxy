#!/usr/bin/env python3

from typing import List

from mitmproxy.http import HTTPFlow
from mitmproxy.addons.proxyauth import ProxyAuth, Htpasswd, make_auth_required_response

METADATA_AUTH_EXTERNAL = 'kerberos_auth_proxy.auth_external'


class AuthAddon(ProxyAuth):
    def __init__(self, external_hosts: List[str], htpasswd_path: str):
        super().__init__()
        self.external_hosts = external_hosts
        self.htpasswd_path = htpasswd_path

    def load(self, loader):
        pass

    def configure(self, updated):
        self.validator = Htpasswd('@' + self.htpasswd_path)

    def _remap_auth(self, flow: HTTPFlow) -> None:
        if flow.request.host in self.external_hosts:
            value = flow.request.headers.pop('Authorization', '')
            flow.request.headers['Proxy-Authorization'] = value
            flow.metadata[METADATA_AUTH_EXTERNAL] = True
        else:
            flow.metadata[METADATA_AUTH_EXTERNAL] = False

    def http_connect(self, flow: HTTPFlow) -> None:
        self._remap_auth(flow)
        return super().http_connect(flow)

    def requestheaders(self, flow: HTTPFlow) -> None:
        self._remap_auth(flow)
        return super().requestheaders(flow)

    def assert_auth(self, flow: HTTPFlow) -> bool:
        if not flow.metadata.get('proxyauth'):
            is_external = flow.metadata.get(METADATA_AUTH_EXTERNAL)
            flow.response = make_auth_required_response(is_proxy=not is_external)
            return False
        else:
            return True
