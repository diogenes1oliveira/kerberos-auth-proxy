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


class KerberizedServer(Thread):
    def __init__(self, hostname, port: Optional[int] = None):
        super().__init__()
        self.daemon = True

        if not port:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.bind(('', 0))
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.port = self.socket.getsockname()[1]
        else:
            self.socket = None
            self.port = port

        self.url = f"http://{hostname}:{self.port}"
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

        init_kerberos(self.app, hostname=hostname)

    def run(self):
        self.server = make_server('127.0.0.1', self.port, self.app)
        with no_warnings(DeprecationWarning):
            self.ctx = self.app.app_context()
            self.ctx.push()
            self.server.serve_forever()

    def wait_ready(self, url=None):
        url = url or f'{self.url}/ping'

        while True:
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    logging.info('Server is ready at %s', url)
                    break
            except Exception:
                pass
            time.sleep(0.1)

    def serve(self):
        self.start()
        self.wait_ready()

    def close(self):
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
