from contextlib import contextmanager
import os
import socket
import subprocess
import time

import pytest
import requests

from kerberos_auth_proxy.mitm.addons import kerberos
from tests.utils import get_free_port_number

if not os.path.exists((os.getenv('KRB5CCNAME') or '').split('DIR:')[1]):
    pytest.skip("no credentials cache in $KRB5CCNAME, can't run integration test", allow_module_level=True)


def _port_is_used(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.2)
        return s.connect_ex(('localhost', port)) == 0


@contextmanager
def mitmproxy_command(port, env=None):
    env = {**os.environ, **(env or {})}

    process = subprocess.Popen([
        'mitmweb',
        '--no-web-open-browser',
        '--proxyauth', '@' + env['PROXY_HTPASSWD_PATH'],
        '-s', kerberos.__file__,
        '--set', 'ssl_verify_upstream_trusted_ca=' + env['SSL_CERT_FILE'],
        '--listen-port', str(port),
        '--web-port', str(get_free_port_number()),
        '--set', 'kerberos_realm=' + env['KERBEROS_REALM'],
        '--set', 'kerberos_spnego_codes=401',
        '--set', 'kerberos_knox_urls=',
        '--set', 'kerberos_keytabs_path=' + env['KEYTABS_PATH'],
        '--set', 'hosts_mappings=' + (env.get('HOSTS_MAPPINGS') or ''),
    ], env=env)
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
