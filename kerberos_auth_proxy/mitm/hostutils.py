'''
Miscellaneous utilities for remapping hosts and URLs
'''

from typing import Optional
from urllib.parse import urlparse, urlunparse, ParseResult

from mitmproxy.http import Request, Response

REDIRECT_CODES = [301, 302, 303, 307, 307, 308]


def request_rebase(request: Request, matcher_url: ParseResult, target_url: ParseResult) -> Optional[bool]:
    '''
    Checks if the request url matches the matcher parameter and if so rebases it into the target URL

    >>> matcher_url = urlparse('http://example.external:8080/api/v1')
    >>> target_url = urlparse('http://example.internal:8080/api/v2')
    >>> request = Request.make('GET', 'http://example.external:8080/api/v1/do/stuff')
    >>> rebased = request_rebase(request, matcher_url, target_url)
    >>> rebased and request.path == '/api/v2/do/stuff'
    True

    >>> matcher_url = urlparse('http://example.com/')
    >>> target_url = urlparse('http://google.com/')
    >>> request = Request.make('GET', 'http://other')
    >>> request_rebase(request, matcher_url, target_url) is None
    True
    '''
    if not url_parts_matches(matcher_url, request.host, request.port, request.path):
        return

    request.scheme = target_url.scheme
    request.host = target_url.hostname
    request.host_header = target_url.netloc
    request.port = url_port(target_url)
    request.path = path_rebase(matcher_url.path, request.path, target_url.path)

    return request


def redirect_rebase(response: Response, matcher_url: ParseResult, target_url: ParseResult) -> bool:
    '''
    Checks if the response is a redirect and if its Location matches the matcher parameter. If so,
    rebase it into the target URL

    >>> response = Response.make(200, headers={})
    >>> redirect_rebase(response, None, None)
    False

    >>> matcher_url = urlparse('http://internal:80/v1')
    >>> response = Response.make(301, headers={'Location': ''})
    >>> redirect_rebase(response, matcher_url, None)
    False

    >>> matcher_url = urlparse('http://internal:80/v1')
    >>> target_url = urlparse('http://external:80/v2')
    >>> response = Response.make(307, headers={'Location': 'http://non-matching/v1/resource'})
    >>> redirect_rebase(response, matcher_url, target_url)
    False

    >>> matcher_url = urlparse('http://internal:80/v1')
    >>> target_url = urlparse('http://external:80/v2')
    >>> response = Response.make(301, headers={'Location': 'http://internal/v1/resource'})
    >>> redirected = redirect_rebase(response, matcher_url, target_url)
    >>> redirected and response.headers[b'Location']
    'http://external/v2/resource'

    '''
    if response.status_code not in REDIRECT_CODES:
        return False

    try:
        location = response.headers.get(b'Location')
        location_url = urlparse(location or '')
    except Exception:
        return False

    if not location_url.scheme:
        return False

    rebased_url = url_rebase(matcher_url, location_url, target_url)
    if rebased_url:
        response.headers[b'Location'] = urlunparse(rebased_url)
        return True

    return False


def url_rebase(matcher_url: ParseResult, url: ParseResult, target_url: ParseResult) -> Optional[ParseResult]:
    '''
    Checks if the url matches the matcher parameter and if so rebases it into the target URL

    >>> matcher_url = urlparse('http://example.external:8080/api/v1')
    >>> url = urlparse('http://example.external:8080/api/v1/path')
    >>> target_url = urlparse('http://internal:8081/v2')
    >>> url_rebase(matcher_url, url, target_url)
    ParseResult(scheme='http', netloc='internal:8081', path='/v2/path', params='', query='', fragment='')

    >>> matcher_url = urlparse('http://example.external:8080/api/v1')
    >>> url = urlparse('http://example.external:8080/api/v3/path')
    >>> target_url = urlparse('http://internal:8081/v2')
    >>> url_rebase(matcher_url, url, target_url)

    >>> matcher_url = ParseResult(scheme='http', netloc='internal:80', path='/v1', params='', query='', fragment='')
    >>> url = ParseResult(scheme='http', netloc='internal', path='/v1/resource', params='', query='', fragment='')
    >>> target_url = ParseResult(scheme='http', netloc='external:80', path='/v2', params='', query='', fragment='')
    >>> url_rebase(matcher_url, url, target_url)
    ParseResult(scheme='http', netloc='external', path='/v2/resource', params='', query='', fragment='')
    '''
    if not url_parts_matches(matcher_url, url.hostname, url_port(url), url.path):
        return

    return url._replace(
        scheme=target_url.scheme,
        netloc=f'{url_netloc(target_url)}',
        path=path_rebase(matcher_url.path, url.path, target_url.path)
    )


def path_rebase(matcher_path: str, path: str, target_path: str) -> str:
    '''
    Rebase a given path onto a target path by replacing the matched portion of the path

    >>> path_rebase('/v1/', '/v1/some/stuff', '/v2/')
    '/v2/some/stuff'
    '''
    base_path = path[len(matcher_path):]
    return target_path + base_path


def url_parts_matches(matcher_url: ParseResult, hostname: str, port: int, path: str):
    '''
    Checks if the hostname, port and path all match the matcher_url parameter

    >>> matcher_url = urlparse('http://localhost:8080/v1')
    >>> url_parts_matches(matcher_url, 'localhost', 8080, '/v1/sub/path')
    True

    >>> matcher_url = urlparse('http://localhost:8080/v1')
    >>> url_parts_matches(matcher_url, 'localhost', 8080, '/v2/sub/path')
    False

    >>> matcher_url = urlparse('http://localhost:8080/v1')
    >>> url_parts_matches(matcher_url, 'test.localhost', 8080, '/v1')
    False

    >>> matcher_url = urlparse('http://localhost:8080/v1')
    >>> url_parts_matches(matcher_url, 'localhost', 8081, '/v1')
    False
    '''
    if port != url_port(matcher_url):
        return False

    if not path.startswith(matcher_url.path):
        return False

    if hostname != matcher_url.hostname:
        return False

    return True


def url_matches(matcher_url: ParseResult, url: ParseResult) -> bool:
    '''
    Checks if the hostname, port and path all match the matcher_url parameter

    >>> matcher_url = urlparse('http://example/some')
    >>> url = urlparse('http://example/some/stuff')
    >>> url_matches(matcher_url, url)
    True

    >>> matcher_url = urlparse('http://example/some')
    >>> url = urlparse('http://example:80/some/stuff')
    >>> url_matches(matcher_url, url)
    True
    '''
    return url_parts_matches(matcher_url, url.hostname, url_port(url), url.path)


def url_port(url: ParseResult) -> int:
    '''
    Gets the url port or a default one based on the protocol.

    Raises:
        ValueError: no port set and unrecognized protocol

    >>> url = urlparse('http://localhost:8080/v1')
    >>> url_port(url)
    8080

    >>> url = urlparse('http://example.com/v1')
    >>> url_port(url)
    80

    >>> url = urlparse('https://example.com')
    >>> url_port(url)
    443

    >>> url = urlparse('unknown://example.com')
    >>> url_port(url)
    Traceback (most recent call last):
        ...
    ValueError: unknown scheme: 'unknown'
    '''
    if url.port is not None:
        return url.port
    if url.scheme == 'http':
        return 80
    elif url.scheme == 'https':
        return 443
    else:
        raise ValueError(f"unknown scheme: '{url.scheme}'")


def url_netloc(url: ParseResult) -> int:
    '''
    Gets the url netloc, removing the port if it's the default one based on the protocol

    >>> url = urlparse('http://localhost:8080/v1')
    >>> url_netloc(url)
    'localhost:8080'

    >>> url = urlparse('http://example.com/v1')
    >>> url_netloc(url)
    'example.com'

    >>> url = urlparse('https://example.com:443')
    >>> url_netloc(url)
    'example.com'
    '''
    if url.scheme == 'http' and url.port == 80:
        return url.hostname
    elif url.scheme == 'https' and url.port == 443:
        return url.hostname
    else:
        return url.netloc


def url_default_port(scheme: str) -> int:
    '''
    Gets the default url port for the given scheme

    Raises:
        ValueError: unrecognized protocol

    >>> url_default_port('http')
    80

    >>> url_default_port('https')
    443

    >>> url_default_port('unknown')
    Traceback (most recent call last):
        ...
    ValueError: unknown scheme 'unknown'
    '''
    if scheme == 'http':
        return 80
    elif scheme == 'https':
        return 443
    else:
        raise ValueError(f"unknown scheme '{scheme}'")
