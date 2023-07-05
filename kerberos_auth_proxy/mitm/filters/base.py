'''
Base definitions
'''

from mitmproxy.http import HTTPFlow

from typing import Annotated, Awaitable, Callable, Iterable, Optional

Filter = Annotated[
    Callable[[HTTPFlow], Awaitable[Optional['Filter']]],
    'An async function that accepts a flow, processes it and optionally returns the next filter to apply'
]


async def NULL_FILTER(_flow: HTTPFlow) -> None:
    '''
    A dummy filter that does nothing
    '''
    pass


def chain_filters(*filters: Iterable[Filter]):
    '''
    Chains filters by calling them recursively in depth-first fashion
    '''
    async def chain_filters_filter(flow: HTTPFlow) -> None:
        for filter in filters:
            while filter:
                filter = await filter(flow)

    return chain_filters_filter
