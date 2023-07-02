#!/usr/bin/env python3

import logging
import socket
from threading import Thread
import time
from typing import Optional

from flask import Flask

from kerberos_auth_proxy.utils import no_warnings

with no_warnings(DeprecationWarning):
    from flask_kerberos import init_kerberos, requires_authentication

import requests
from werkzeug.serving import make_server


def wait_for_url(get_url, max_tries=30, pause=0.1):
    '''
    Waits until the URL returns a non-error response

    Args:
        url: URL to send a GET request to
        max_tries: max number of attempts to try before giving up
        pause: time in seconds to wait between each retry

    Raises:
        IOError: URL not available after the retries have been exhausted
    '''
    for i in range(max_tries):
        try:
            response = requests.get(get_url)
            response.raise_for_status()
        except Exception:
            time.sleep(pause)
        else:
            logging.info('request to %s succeeded after %d try(ies)', get_url, i + 1)
            return

    raise IOError(f'{get_url} still not available after {max_tries} tries')


class KerberizedServer(Thread):
    '''
    Starts a simple test server with the routes:

    - /public/** -> returns {"status": "public"}
    - /private/** -> returns {"status": "private", "principal": "<PRINCIPAL>"} (requires SPNEGO)
    - /ping -> returns "pong"
    '''

    def __init__(self, hostname, port: Optional[int] = None):
        '''
        Args:
            hostname: Kerberos hostname presented to the client. The server socket always binds to 127.0.0.1,
                but this argument must match the one sent in the URL and must contain the realm domain.
                For instance, if the realm domain is .localhost, this hostname must match *.localhost,
                can't be just 'localhost'
            port: port to bind the server to. Defaults to a random free TCP port
        '''
        super().__init__()
        self.daemon = True
        self.hostname = hostname

        if not port:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.bind(('', 0))
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.port = self.socket.getsockname()[1]
        else:
            self.socket = None
            self.port = port

        self.server = None
        self.app = Flask(__name__)

        @self.app.route("/ping")
        def ping():
            return "pong"

        @self.app.route("/public/", defaults={'path': ''})
        @self.app.route("/public/<path:path>")
        def public(path):
            return {"status": "public"}

        @self.app.route("/private/", defaults={'path': ''})
        @self.app.route("/private/<path:path>")
        @requires_authentication
        def private(principal, path):
            return {"status": "private", "principal": principal}

        init_kerberos(self.app, hostname=self.hostname)

    def run(self):
        '''
        threading internal method, don't call directly
        '''
        self.server = make_server('127.0.0.1', self.port, self.app)
        with no_warnings(DeprecationWarning):
            self.ctx = self.app.app_context()
            self.ctx.push()
            self.server.serve_forever()

    @property
    def url(self):
        return f"http://{self.hostname}:{self.port}"

    def serve(self):
        '''
        Starts the server, waiting until it's ready to return
        '''
        self.start()
        wait_for_url(self.url)

    def close(self):
        '''
        Stops the server and waits until it's dead
        '''
        if self.socket:
            logging.info('Closing socket at :%d', self.port)
            self.socket.close()
            self.socket = None
        if self.server:
            logging.info('Closing server')
            self.server.shutdown()
            self.server = None
        self.join()


if __name__ == '__main__':
    from logging.config import dictConfig
    import sys

    args = dict(enumerate(sys.argv))

    port = int(args.get(1) or '8080')
    hostname = args.get(2) or 'test.localhost'
    level = args.get(3) or 'INFO'

    dictConfig({
        'version': 1,
        'formatters': {'default': {
            'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
        }},
        'handlers': {'wsgi': {
            'class': 'logging.StreamHandler',
            'stream': 'ext://flask.logging.wsgi_errors_stream',
            'formatter': 'default'
        }},
        'root': {
            'level': level,
            'handlers': ['wsgi']
        }
    })
    server = KerberizedServer(hostname, port)
    server.serve()

    try:
        while True:
            time.sleep(600.0)
    except KeyboardInterrupt:
        server.close()
