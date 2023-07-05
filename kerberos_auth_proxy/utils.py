'''
Miscellaneous utilities
'''

from contextlib import contextmanager
import os
from typing import Callable, Generator, List, Mapping, TypeVar
import warnings

T = TypeVar('T')
Mapper = Callable[[str], T]


def env_to_map(name: str) -> Mapping[str, str]:
    '''
    Extracts the mappings defined by '=' contained in the environment variable

    An empty or unset environment variable always yields an empty list
    '''
    value = (os.getenv(name) or '').replace(',', ' ')
    parts = value.split()
    result = {}

    for part in parts:
        key, sep, value = part.partition('=')
        if not (key and sep and value):
            raise ValueError('Invalid mapping ' + part)
        result[key] = value

    return result


def env_to_list(name: str, mapper: Mapper) -> List[T]:
    '''
    Splits the environment variable value by whitespace or comma, removing empty
    items from the result

    An empty or unset environment variable always yields an empty list
    '''
    value = os.getenv(name) or ''
    return [mapper(item) for item in value.replace(',', ' ').split()]


@contextmanager
def no_warnings(*categories) -> Generator[None, None, None]:
    '''
    Disables the given warnings within the context
    '''
    with warnings.catch_warnings():
        for category in categories:
            warnings.filterwarnings("ignore", category=category)
        yield
