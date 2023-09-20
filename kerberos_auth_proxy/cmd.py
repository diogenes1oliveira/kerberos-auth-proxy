'''
Start up a mitmweb instance using the authentication addons
'''

import os
import re
import sys
from typing import List

from kerberos_auth_proxy.mitm.addons import kerberos


def env_to_options(env: os._Environ) -> List[str]:
    '''
    Maps the environment variables to a set of mitm options

    >>> env_to_options({'MITM_SET_KERBEROS_REALM': 'LOCALHOST'})
    ['--set', 'kerberos_realm=LOCALHOST']

    >>> env_to_options({'MITM_OPT_LISTEN_PORT': '3128'})
    ['--listen-port', '3128']

    >>> env_to_options({'MITM_OPT_NO_WEB_OPEN_BROWSER': '-'})
    ['--no-web-open-browser']

    >>> env_to_options({'MITM_OPT_MAP_REMOTE_1': 'v1', 'MITM_OPT_MAP_REMOTE_0': 'v0'})
    ['--map-remote', 'v0', '--map-remote', 'v1']
    '''
    args = []

    for name, value in sorted(env.items(), key=lambda i: i[0]):
        if name.startswith('MITM_SET_'):
            opt = name[len('MITM_SET_'):].lower()
            args += ['--set', f'{opt}={value}']
        elif name.startswith('MITM_OPT_'):
            opt = name[len('MITM_OPT_'):].lower()
            opt = re.sub(r'_[0-9]+$', '', opt)
            opt = opt.replace('_', '-')
            if value == '-':
                args += [f'--{opt}']
            else:
                args += [f'--{opt}', value]

    return args


def main():
    args = ['mitmweb', '-s', os.path.abspath(kerberos.__file__)] + env_to_options(os.environ) + sys.argv[1:]
    os.execlp('mitmweb', *args)


if __name__ == '__main__':
    main()
