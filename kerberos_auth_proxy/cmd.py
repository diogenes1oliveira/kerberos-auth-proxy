'''
Start up a mitmweb instance using the authentication addons
'''

import os
import re
import sys
from typing import Iterable, Tuple

from kerberos_auth_proxy.mitm.addons import kerberos


def _env_index(env_name: str) -> Tuple[str, int]:
    m = re.match(r'.*_([0-9]+)$', env_name)
    if m:
        index = int(m.group(1))
        env_name = re.sub(r'_[0-9]+$', '', env_name)
        return [index, env_name]
    else:
        return [0, env_name]


def env_to_options(env: os._Environ) -> Iterable[str]:
    '''
    Maps the environment variables to a set of mitm options

    >>> list(env_to_options({'MITM_SET_KERBEROS_REALM': 'LOCALHOST', 'MITM_SET_KERBEROS_SPNEGO_CODES': '401,407'}))
    ['--set', 'kerberos_realm=LOCALHOST', '--set', 'kerberos_spnego_codes=401,407']

    >>> list(env_to_options({'MITM_OPT_LISTEN_PORT': '3128'}))
    ['--listen-port', '3128']

    >>> list(env_to_options({'MITM_OPT_NO_WEB_OPEN_BROWSER': '-'}))
    ['--no-web-open-browser']

    >>> list(env_to_options({'MITM_OPT_MAP_REMOTE_1': 'v1', 'MITM_OPT_MAP_REMOTE_0': 'v0'}))
    ['--map-remote', 'v0', '--map-remote', 'v1']
    '''

    # sort env alphabetically
    sorted_env = dict(sorted(env.items()), key=lambda item: item[0])
    # sort env by index suffix
    sorted_env = dict(sorted(env.items()), key=lambda item: _env_index(item[0])[1])

    for env_name, env_value in sorted_env.items():
        m = re.match(r'.*_([0-9]+)$', env_name)
        if m:
            env_name = re.sub(r'_[0-9]+$', '', env_name)

        if env_name.startswith('MITM_SET_'):
            set_name = env_name[len('MITM_SET_'):].lower()
            yield '--set'
            yield f'{set_name}={env_value}'
        elif env_name.startswith('MITM_OPT_'):
            opt_name = env_name[len('MITM_OPT_'):].lower().replace('_', '-')
            yield f'--{opt_name}'
            if env_value != '-':
                yield env_value


def main():
    plugin_path = os.path.abspath(kerberos.__file__)
    env_options = list(env_to_options(os.environ))

    args = ['mitmweb', '-s', plugin_path] + env_options + sys.argv[1:]
    os.execlp('mitmweb', *args)


if __name__ == '__main__':
    main()
