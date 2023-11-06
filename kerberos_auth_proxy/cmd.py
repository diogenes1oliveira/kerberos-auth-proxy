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
    args_by_opt = {}

    for env_name, env_value in sorted(env.items(), key=lambda i: i[0]):
        index = 0
        m = re.match(r'.*_([0-9]+)$', env_name)
        if m:
            index = int(m.group(1))
            env_name = re.sub(r'_[0-9]+$', '', env_name)

        if env_name.startswith('MITM_SET_'):
            set_name = env_name[len('MITM_SET_'):].lower()
            opt_args = args_by_opt.setdefault('--set', {})
            opt_args[index] = f'{set_name}={env_value}'
        elif env_name.startswith('MITM_OPT_'):
            opt_name = '--' + env_name[len('MITM_OPT_'):].lower().replace('_', '-')
            opt_args = args_by_opt.setdefault(opt_name, {})
            if env_value != '-':
                opt_args[index] = env_value
            else:
                opt_args[index] = None

    args = []

    for opt, opt_args in args_by_opt.items():
        opt_args = [i[1] for i in sorted(opt_args.items(), key=lambda item: item[0])]
        for arg in opt_args:
            args.append(opt)
            if arg is not None:
                args.append(arg)

    return args


def main():
    args = ['mitmweb', '-s', os.path.abspath(kerberos.__file__)] + env_to_options(os.environ) + sys.argv[1:]
    os.execlp('mitmweb', *args)


if __name__ == '__main__':
    main()
