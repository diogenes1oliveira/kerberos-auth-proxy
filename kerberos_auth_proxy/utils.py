"""
Miscellaneous utilities
"""

from contextlib import contextmanager
from dotenv import load_dotenv
import os
import re
import sys
from pathlib import Path
import time
from typing import (
    Awaitable,
    Callable,
    Generator,
    Generic,
    Iterable,
    List,
    Mapping,
    Optional,
    TypeVar,
    Tuple,
)
import warnings

T = TypeVar("T")
Mapper = Callable[[str], T]


def string_to_map(s: Optional[str]) -> Mapping[str, str]:
    """
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
    """
    value = (s or "").replace(",", " ")
    parts = value.split()
    result = {}

    for part in parts:
        key, sep, value = part.partition("=")
        if not (key and sep):
            raise ValueError(f"invalid mapping {part!r}")
        result[key] = value

    return result


def string_to_list(s: Optional[str], mapper: Mapper) -> List[T]:
    """
    Explodes a string to a list of converted values

    The values might be space or comma-delimited

    >>> string_to_list('1 2', mapper=int)
    [1, 2]

    >>> string_to_list(None, mapper=int)
    []
    """
    s = s or ""
    return [mapper(item) for item in s.replace(",", " ").split() if item]


@contextmanager
def no_warnings(*categories) -> Generator[None, None, None]:
    """
    Disables the given warnings within the context
    """
    with warnings.catch_warnings():
        for category in categories:
            warnings.filterwarnings("ignore", category=category)
        yield


def _env_index(env_name: str) -> Tuple[str, int]:
    m = re.match(r".*_([0-9]+)$", env_name)
    if m:
        index = int(m.group(1))
        env_name = re.sub(r"_[0-9]+$", "", env_name)
        return [index, env_name]
    else:
        return [0, env_name]


def env_to_options(env: os._Environ) -> Iterable[str]:
    """
    Maps the environment variables to a set of mitm options

    >>> list(env_to_options({'MITM_SET_KERBEROS_REALM': 'LOCALHOST', 'MITM_SET_KERBEROS_SPNEGO_CODES': '401,407'}))
    ['--set', 'kerberos_realm=LOCALHOST', '--set', 'kerberos_spnego_codes=401,407']

    >>> list(env_to_options({'MITM_OPT_LISTEN_PORT': '3128'}))
    ['--listen-port', '3128']

    >>> list(env_to_options({'MITM_OPT_NO_WEB_OPEN_BROWSER': '-'}))
    ['--no-web-open-browser']

    >>> list(env_to_options({'MITM_OPT_MAP_REMOTE_1': 'v1', 'MITM_OPT_MAP_REMOTE_0': 'v0'}))
    ['--map-remote', 'v0', '--map-remote', 'v1']
    """

    # sort env alphabetically
    sorted_env = dict(sorted(env.items()), key=lambda item: item[0])
    # sort env by index suffix
    sorted_env = dict(sorted(env.items()), key=lambda item: _env_index(item[0])[1])

    for env_name, env_value in sorted_env.items():
        m = re.match(r".*_([0-9]+)$", env_name)
        if m:
            env_name = re.sub(r"_[0-9]+$", "", env_name)

        if env_name.startswith("MITM_SET_"):
            set_name = env_name[len("MITM_SET_") :].lower()
            yield "--set"
            yield f"{set_name}={env_value}"
        elif env_name.startswith("MITM_OPT_"):
            opt_name = env_name[len("MITM_OPT_") :].lower().replace("_", "-")
            yield f"--{opt_name}"
            if env_value != "-":
                yield env_value


class ExpiringCache(Generic[T]):
    def __init__(
        self,
        expiration: float,
        init: Callable[[str], Awaitable[T]],
    ):
        self.expiration = expiration
        self.init = init
        self._values: dict[str, T] = {}
        self._last_updates: dict[str, float] = {}

    async def get(self, key: str) -> Tuple[Optional[T], Optional[float]]:
        now = time.monotonic()
        last_update = self._last_updates.get(key)
        if last_update:
            age = now - last_update
        else:
            age = None

        if not age or age >= self.expiration:
            self._values[key] = await self.init(key)
            self._last_updates[key] = time.monotonic()
            age = None

        return self._values[key], age


def dotenv_from_args(argv: list[str]) -> Optional[Path]:
    """
    Recognizes a --env-file argument passed
    """
    print("INFO: checking --env-file arg")

    if len(argv) < 2:
        return

    if argv[1] == "--env-file":
        if len(argv) >= 3:
            env_path = argv[2]
            argv.pop(2)
            argv.pop(1)
        else:
            env_path = None
    elif argv[1].startswith("--env-file="):
        env_path = argv[1][len("--env-file=") :]
        argv.pop(1)
    else:
        return

    if not env_path:
        raise Exception("no value set for --env-file")

    env_path = Path(env_path).absolute()
    print(f"INFO: loading .env from {env_path}", file=sys.stderr)
    load_dotenv(dotenv_path=env_path, verbose=True, override=True)

    print(f"INFO: switching to directory {env_path.parent}")
    os.chdir(env_path.parent)

    return env_path
