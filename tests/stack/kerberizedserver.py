#!/usr/bin/env python3

import logging
import os
import re
from threading import Thread
import time
from typing import Callable, Optional

from flask import Flask, request

from kerberos_auth_proxy.utils import no_warnings
from tests.utils import get_free_port

with no_warnings(DeprecationWarning):
    from flask_kerberos import init_kerberos, requires_authentication

import requests
from werkzeug.serving import make_server


def wait_for_url(get_url, max_tries=30, pause=0.1, on_retry: Optional[Callable[[Exception], None]] = None):
    '''
    Waits until the URL returns a non-error response

    Args:
        url: URL to send a GET request to
        max_tries: max number of attempts to try before giving up
        pause: time in seconds to wait between each retry
        on_retry: function to call on errors

    Raises:
        IOError: URL not available after the retries have been exhausted
    '''
    for i in range(max_tries):
        try:
            response = requests.get(get_url)
            response.raise_for_status()
        except Exception as e:
            on_retry and on_retry(e)
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

    def __init__(self, port: Optional[int] = None):
        '''
        Args:
            port: port to bind the server to. Defaults to a random free TCP port
        '''
        super().__init__()

        http_user = os.environ['HTTP_KERBEROS_USER']
        os.environ['KRB5_KTNAME'] = os.environ['HTTP_KERBEROS_KEYTAB']

        service, hostname, realm = re.split('[/@]', http_user)
        if service != 'HTTP' or not hostname or not realm:
            raise ValueError('Invalid value for HTTP_KERBEROS_USER')

        self.daemon = True
        self.hostname = hostname

        if not port:
            self.port, self.socket = get_free_port()
        else:
            self.socket = None
            self.port = port

        self.server = None
        self.app = Flask(__name__)

        @self.app.before_request
        def do_log():
            logging.info("url: %s, headers: %s", request.url, request.headers)

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
        wait_for_url(f"{self.url}/ping")

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

    port = int(args.get(1) or '8081')
    level = args.get(2) or 'INFO'

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
    server = KerberizedServer(port)
    server.serve()

    try:
        while True:
            time.sleep(600.0)
    except KeyboardInterrupt:
        server.close()
