"""
Start up a mitmweb instance using the authentication addons
"""

import os
from pathlib import Path
import shlex
import sys

from kerberos_auth_proxy.utils import env_to_options
from kerberos_auth_proxy.utils import dotenv_from_args


def setup_certificates():
    print("INFO: writing mitmproxy-ca.pem", file=sys.stderr)

    confdir = Path(os.environ["MITM_SET_CONFDIR"])
    crt = Path(os.environ["MITM_TLS_CA_CRT"])
    key = Path(os.environ["MITM_TLS_CA_KEY"])

    confdir.mkdir(parents=True, exist_ok=True)

    for old in confdir.glob("mitmproxy-ca*"):
        old.unlink()

    dest = confdir / "mitmproxy-ca.pem"
    dest.touch()
    dest.chmod(0o600)

    with dest.open("w") as bundle:
        bundle.write(crt.read_text())
        bundle.write(key.read_text())


def main():
    dotenv_from_args(sys.argv)
    setup_certificates()

    from kerberos_auth_proxy.mitm.addons import setup

    plugin_path = os.path.realpath(setup.__file__)
    env_options = list(env_to_options(os.environ))

    if len(sys.argv) <= 1 or sys.argv[1] not in ('mitmdump', 'mitmweb', 'mitmproxy'):
        raise Exception('No valid command')

    args = [sys.argv[1], "-s", plugin_path] + env_options + sys.argv[2:]
    print(f"$ {shlex.join(args)}", file=sys.stderr)

    return os.execvpe(args[0], args, os.environ)


if __name__ == "__main__":
    main()
