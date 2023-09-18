from contextlib import closing
import os
import re
import sys
import socket
import subprocess
from unittest.mock import MagicMock
from typing import Generator

import pytest
from kerberos_auth_proxy.utils import no_warnings

with no_warnings(DeprecationWarning):
    from mitmproxy import ctx

from tests.stack.kerberizedserver import (
    __file__ as kerberizedserver_path,
    wait_for_url
)


@pytest.fixture(autouse=True)
def restore_env():
    env_backup = os.environ.copy()
    try:
        yield
    finally:
        os.environ = env_backup


@pytest.fixture()
def kerberizedserver() -> Generator[str, None, None]:
    _, hostname, _ = re.split('[/@]', os.environ.get('HTTP_KERBEROS_USER') or '')
    if not hostname:
        raise ValueError('No hostname in HTTP_KERBEROS_USER')

    port = _random_port()
    url = f'http://{hostname}:{port}'

    process = subprocess.Popen([
        sys.executable, kerberizedserver_path, str(port), 'WARN'
    ])

    def on_retry(_):
        if process.poll() is not None:
            raise Exception('process ended abruptly')

    wait_for_url(f'{url}/ping', on_retry=on_retry)

    try:
        yield url
    finally:
        process.kill()
        process.wait()


@pytest.fixture
def kerberosprincipal() -> str:
    return os.environ['DEV_KERBEROS_USER']


# quite ugly, but it works... I couldn't find a way to make the mock recognized
@pytest.fixture(autouse=True)
def mock_ctx_log():
    if hasattr(ctx, 'log'):
        restore_after = True
        bkp = ctx.log
    else:
        restore_after = False

    ctx.log = MagicMock()
    ctx.log.info = MagicMock()
    ctx.log.debug = MagicMock()

    try:
        yield
    finally:
        if restore_after:
            ctx.log = bkp

# quite ugly, but it works... I couldn't find a way to make the mock recognized


@pytest.fixture(autouse=True)
def mock_ctx_options():
    if hasattr(ctx, 'options'):
        restore_after = True
        bkp = ctx.options
    else:
        restore_after = False

    class Dummy:
        pass
    ctx.options = Dummy()

    try:
        yield ctx.options
    finally:
        if restore_after:
            ctx.options = bkp


def _random_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(('', 0))
        return s.getsockname()[1]
