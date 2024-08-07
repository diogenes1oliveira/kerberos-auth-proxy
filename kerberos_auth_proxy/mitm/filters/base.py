from mitmproxy.http import Request, Response


class Filter:
    def match(self, request: Request) -> bool:
        return False

    def apply(self, request: Request):
        pass
