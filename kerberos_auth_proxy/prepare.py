from pathlib import Path
import os
import secrets
import string
import subprocess
import sys
from typing import Optional

from kerberos_auth_proxy.utils import dotenv_from_args

DEFAULT_SUBJECT = '/O=Dev/OU=Development/CN=Kerberos Auth Proxy Self-Signed CA'


def generate_ca(ca_path: str, key_path: str, subject: Optional[str] = None):
    ca_path: Path = Path(ca_path)
    key_path: Path = Path(key_path)
    subject = subject or DEFAULT_SUBJECT

    if ca_path.exists():
        if not key_path.exists():
            raise Exception(f'CA {ca_path} without corresponding key {key_path}')
        elif not user_confirm(f'CA already exists at {ca_path}, recreate'):
            return

    ca_path.absolute().parent.mkdir(parents=True, exist_ok=True)
    key_path.absolute().parent.mkdir(parents=True, exist_ok=True)

    print(f'generating private key to {key_path}', file=sys.stderr)
    cmd = ['openssl', 'genrsa', '-out', str(key_path)]
    subprocess.run(cmd, check=True)

    print(f'generating self-signed CA to {ca_path} (subj={subject})')
    cmd = ['openssl', 'req', '-x509', '-new', '-nodes', '-key',
           str(key_path), '-sha256', '-days', '1825', '-out', str(ca_path), '-subj', subject]
    subprocess.run(cmd, check=True)


def generate_password(path: str) -> str:
    path: Path = Path(path)

    if path.exists():
        if not user_confirm(f'password file already exists at {path}, recreate'):
            return path.read_text()

    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()
    path.chmod(0o600)

    print(f'writing password to {path}', file=sys.stderr)
    chars = list(set(string.ascii_letters) - set('aeiouAEIOU') | set(string.digits))
    password = ''.join(secrets.choice(chars) for _ in range(15))

    path.write_text(password)
    return password


def generate_htpasswd(path: str, password: str, usernames: list[str]):
    path: Path = Path(path)

    if path.exists():
        if not user_confirm(f'.htpasswd file already exists at {path}, recreate'):
            return

    print(f'writing htpasswd file to {path}', file=sys.stderr)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()
    path.chmod(0o600)

    with path.open('w') as fp:
        for username in usernames:
            print(f'adding username {username!r} to htpasswd file', file=sys.stderr)
            cmd = ['htpasswd', '-n', '-i', '-B', username]
            process = subprocess.run(
                cmd,
                input=f'{password}\n',
                stdout=subprocess.PIPE,
                check=True,
                universal_newlines=True,
            )
            line = process.stdout.strip() + '\n'
            fp.write(line)


def user_confirm(prompt: str) -> bool:
    try:
        answer = input(f'{prompt} (y/N)? ')
    except EOFError:
        answer = 'N'

    answer = answer.strip().upper()
    if answer != 'Y':
        print(f'Cancelled.', file=sys.stderr)
        return False
    else:
        return True


def prepare(usernames: list[str]):
    ca_path = os.environ['MITM_TLS_CA_CRT']
    key_path = os.environ['MITM_TLS_CA_KEY']
    proxyauth = os.environ['MITM_OPT_PROXYAUTH']

    generate_ca(ca_path, key_path)

    if proxyauth.startswith('@'):
        htpasswd_path = proxyauth[1:]
        password_path = htpasswd_path + '.pwd'

        password = generate_password(password_path)
        generate_htpasswd(htpasswd_path, password, usernames)
    else:
        print(f'$MITM_OPT_PROXYAUTH does not point to an .htpasswd file, skipping', file=sys.stderr)


def main():
    dotenv_from_args(sys.argv)
    prepare(sys.argv[1:])


if __name__ == '__main__':
    main()
