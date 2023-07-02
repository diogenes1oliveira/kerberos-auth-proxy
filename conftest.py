from contextlib import closing
import os
import re
import sys
import socket
import subprocess
from typing import Generator

import pytest

from tests.kerberizedserver import (
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
    http_user = os.environ['HTTP_KERBEROS_USER']
    http_keytab = os.environ['HTTP_KERBEROS_KEYTAB']

    service, hostname, realm = re.split('[/@]', http_user)
    if service != 'HTTP' or not hostname or not realm:
        raise ValueError('Invalid value for HTTP_KERBEROS_USER')

    port = _random_port()
    url = f'http://{hostname}:{port}'

    process = subprocess.Popen(
        args=[sys.executable, kerberizedserver_path, str(port), hostname, 'WARN'],
        env={**os.environ, 'KRB5_KTNAME': http_keytab},
    )

    wait_for_url(f'{url}/ping')

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
