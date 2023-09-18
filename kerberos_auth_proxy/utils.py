'''
Miscellaneous utilities
'''

from contextlib import contextmanager
from typing import Callable, Generator, List, Mapping, Optional, TypeVar
import warnings

T = TypeVar('T')
Mapper = Callable[[str], T]


def string_to_map(s: Optional[str]) -> Mapping[str, str]:
    '''
    Parses a string with a set of key=value items into a Python dict

    The values might be space or comma-delimited

    >>> string_to_map(None)
    {}

    >>> string_to_map('k1=v1 k2=v2')
    {'k1': 'v1', 'k2': 'v2'}

    >>> string_to_map('k1=v1,k2=v2')
    {'k1': 'v1', 'k2': 'v2'}

    >>> string_to_map('k1=v1 nokeyvalue ')
    Traceback (most recent call last):
        ...
    ValueError: invalid mapping 'nokeyvalue'
    '''
    value = (s or '').replace(',', ' ')
    parts = value.split()
    result = {}

    for part in parts:
        key, sep, value = part.partition('=')
        if not (key and sep):
            raise ValueError(f'invalid mapping {part!r}')
        result[key] = value

    return result


def string_to_list(s: Optional[str], mapper: Mapper) -> List[T]:
    '''
    Explodes a string to a list of converted values

    The values might be space or comma-delimited

    >>> string_to_list('1 2', mapper=int)
    [1, 2]

    >>> string_to_list(None, mapper=int)
    []
    '''
    s = s or ''
    return [mapper(item) for item in s.replace(',', ' ').split() if item]


@contextmanager
def no_warnings(*categories) -> Generator[None, None, None]:
    '''
    Disables the given warnings within the context
    '''
    with warnings.catch_warnings():
        for category in categories:
            warnings.filterwarnings("ignore", category=category)
        yield
