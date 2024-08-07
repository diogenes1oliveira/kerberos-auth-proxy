import re
from mitmproxy.http import Request, Response, HTTPFlow

from kerberos_auth_proxy.mitm.filters.base import Filter


class SpnegoFilter(Filter):
    def __init__(
        self,
        urls: list[re.Pattern],
        keytab: str,
        cache_seconds: float,
    ) -> None:
        self.urls = urls
        self.keytab = keytab
        self.cache_seconds = cache_seconds

    def match(self, flow: HTTPFlow) -> bool:
        return False

    def apply(self, flow: HTTPFlow):
        pass
