
from mitmproxy.http import HTTPFlow

from .filters import (
    check_knox,
    check_spnego,
)

RESPONSE_FILTERS = [
    check_spnego,
    check_knox,
]


def response(flow: HTTPFlow):
    '''
    Retries requests with recognized non-authorized responses using Kerberos/GSSAPI
    '''
    filters = RESPONSE_FILTERS.copy()
    while filters:
        filter = filters.pop(0)
        next_filters = filter(flow) or []

        for next_filter in next_filters:
            if next_filter not in filters:
                filters.append(next_filter)
