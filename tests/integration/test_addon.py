from contextlib import contextmanager
import os
import socket
import subprocess
import time
from uuid import uuid4

import pytest
import requests

from kerberos_auth_proxy.mitm import addon
from tests.utils import get_free_port_number

if not os.path.exists(os.getenv('KRB5CCNAME') or ''):
    pytest.skip("no credentials cache in $KRB5CCNAME, can't run integration test", allow_module_level=True)


def _port_is_used(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.2)
        return s.connect_ex(('localhost', port)) == 0


@contextmanager
def mitmproxy_command(port, environ=None):
    environ = {**os.environ, **(environ or {})}

    process = subprocess.Popen([
        'mitmproxy',
        '-s', addon.__file__,
        '--set', 'ssl_verify_upstream_trusted_ca=' + os.environ['SSL_CERT_FILE'],
        '--listen-port', str(port),
    ], env=environ)
    try:
        t0 = time.monotonic()
        while not _port_is_used(port):
            if time.monotonic() - t0 > 10.0:
                raise Exception('timeout exceeded')
            time.sleep(0.2)
        yield
    finally:
        process.terminate()


async def test_with_proxy(kerberosprincipal: str, kerberizedserver: str):
    private_url = kerberizedserver + "/private/"
    mitmproxy_port = get_free_port_number()

    with mitmproxy_command(mitmproxy_port):
        user, _, _ = kerberosprincipal.partition('@')
        password = os.environ['PROXY_PASSWORD']
        proxy_no_auth_url = f'http://localhost:{mitmproxy_port}'
        proxy_auth_url = f'http://{user}:{password}@localhost:{mitmproxy_port}'

        response = requests.get(private_url, proxies={'http': proxy_no_auth_url})
        assert response.status_code == 407

        response = requests.get(private_url, proxies={'http': proxy_auth_url})
        assert response.status_code == 200
        assert response.json() == {"status": "private", "principal": kerberosprincipal}


async def test_with_host_mapping(kerberosprincipal: str, kerberizedserver: str):
    dev_hostname = os.environ['DEV_EXTERNAL_HOSTNAME']
    mitmproxy_port = get_free_port_number()

    env = {'HOST_MAPPINGS': f'http://{dev_hostname}:{mitmproxy_port}={kerberizedserver}'}

    with mitmproxy_command(mitmproxy_port, env):
        private_url = f"http://{dev_hostname}:{mitmproxy_port}/private/"
        response = requests.get(private_url, headers={'Host': str(uuid4())})
        assert response.status_code == 407

        response = requests.get(private_url)
        assert response.status_code == 401

        user, _, _ = kerberosprincipal.partition('@')
        password = os.environ['PROXY_PASSWORD']
        private_auth_url = f"http://{user}:{password}@{dev_hostname}:{mitmproxy_port}/private/"

        response = requests.get(private_auth_url)
        assert response.status_code == 200
