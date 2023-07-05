from contextlib import closing
import os
import re
import sys
import socket
import subprocess
from typing import Generator

import pytest

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


def _random_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(('', 0))
        return s.getsockname()[1]
