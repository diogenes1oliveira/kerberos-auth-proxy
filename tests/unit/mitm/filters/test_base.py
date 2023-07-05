
from mitmproxy.http import HTTPFlow

from kerberos_auth_proxy.mitm.filters.base import chain_filters


async def test_chain_filters():
    filter_calls = []

    async def filter0(_f):
        filter_calls.append('filter0')
        None

    async def filter1(_f):
        filter_calls.append('filter1')
        return filter0

    async def filter2(_f):
        filter_calls.append('filter2')
        return filter1

    combined_filter = chain_filters(filter1, filter0, filter2)

    flow = HTTPFlow(None, None)
    await combined_filter(flow)

    assert filter_calls == [
        'filter1', 'filter0',
        'filter0',
        'filter2', 'filter1', 'filter0',
    ]
