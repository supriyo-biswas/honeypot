__all__ = (
    'BadRequest',
    'FileResponse',
    'HTTPError',
    'InvalidRequestLine',
    'NotModified',
    'Request',
    'RequestNotReceived',
    'RequestedRangeNotSatisfiable',
    'Response',
    'TemplateResponse',
)

import json
import mimetypes
import os
import re
import secrets

from http import HTTPStatus
from jinja2 import Template
from multidict import CIMultiDict
from time import gmtime, mktime, strftime, strptime
from urllib.parse import parse_qs, quote_plus, unquote
from utils import readline

HTTP_DATE_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'


def guess_mimetype(path):
    if re.search(r'\.(cgi|php|aspx?|html?)$', path):
        return 'text/html'

    return mimetypes.guess_type(path)[0] or 'application/octet-stream'


def create_multidict(dct=None):
    if isinstance(dct, CIMultiDict):
        return dct

    result = CIMultiDict()
    if not dct:
        return result

    for key, value in dct.items():
        if not (isinstance(value, str) and isinstance(value, bytes)):
            result.add(key, value)

    return result


class RequestNotReceived(ValueError):
    pass


class InvalidRequestLine(ValueError):
    pass


class HTTPError(ValueError):
    __slots__ = 'status', 'headers'

    def __init__(self, status, headers=None):
        self.status = status
        self.headers = create_multidict(headers)


class NotModified(HTTPError):
    def __init__(self, headers=None):
        super().__init__(304, headers)


class BadRequest(HTTPError):
    def __init__(self, headers=None):
        super().__init__(400, headers)


class RequestedRangeNotSatisfiable(HTTPError):
    def __init__(self, headers=None):
        super().__init__(416, headers)


class Request:
    __slots__ = 'method', 'uri', 'headers', 'body', 'version', 'incomplete'

    def __init__(self, version, method, uri, headers=None, body=b''):
        self.method = method.upper()
        self.uri = uri
        self.body = bytearray(body)
        self.version = version
        self.headers = create_multidict(headers)
        self.incomplete = False

    @property
    def keep_alive(self):
        if self.incomplete or self.version == '1.0':
            return False

        return self.headers.get('Connection') != 'close'

    @property
    def content_length(self):
        if self.method in ['GET', 'HEAD', 'CONNECT']:
            return 0

        result = self.headers.get('Content-Length')
        if result is None or not result.isdigit():
            return 0

        return int(result)

    @property
    def path(self):
        return unquote(self.uri.split('?', 1)[0])

    @property
    def form(self):
        content_type = self.headers.get('Content-Type', '')
        if content_type in ['', 'application/x-www-form-urlencoded']:
            return create_multidict(parse_qs(self.body.decode('latin-1')))

        return create_multidict(self.body.decode('latin-1'))

    @property
    def json(self):
        try:
            return json.loads(self.body.decode())
        except (UnicodeError, json.decoder.JSONDecodeError):
            pass

    @property
    def query(self):
        try:
            return create_multidict(parse_qs(unquote(self.uri.split('?', 1)[1])))
        except IndexError:
            return create_multidict()

    def log_format(self):
        result = {
            'method': self.method,
            'uri': self.uri,
            'version': self.version,
            'headers': [],
            'body': self.body.decode('latin-1'),
        }

        for header, value in self.headers.items():
            result['headers'].append([header, value])

        return result

    def from_request_line(line):
        match = re.match(rb'([a-z-]+)\s+(\S+)\s+HTTP/([\d.]+)', line, re.I)
        if not match:
            raise InvalidRequestLine(line)

        return Request(match[3].decode(), match[1].decode(), match[2].decode('latin-1'))

    def add_header_from_line(self, line):
        match = re.match(rb'([^\s:]+)\s*:\s*([^\r\n]+)', line)
        if not match:
            return False

        self.headers.add(match[1].decode('latin-1'), match[2].decode('latin-1'))
        return True

    def from_socket(socket, headers_max_size=16384, body_max_size=16384):
        first_line = readline(socket)
        if not first_line:
            raise RequestNotReceived()

        request = Request.from_request_line(first_line)
        headers_size = 0
        while True:
            line = readline(socket)
            if not line.rstrip(b'\r\n'):
                break

            if not request.add_header_from_line(line):
                self.incomplete = True
                return request

            headers_size += len(line)
            if headers_size > headers_max_size:
                self.incomplete = True
                return request

        content_length = min(request.content_length, body_max_size)
        while content_length > 0:
            data = socket.recv(content_length)
            if not data:
                if content_length > 0:
                    self.incomplete = True
                break

            request.body.extend(data)
            content_length -= len(data)

        return request


class Response:
    __slots__ = 'status', 'body', 'headers', 'sent'

    def __init__(self, status=200, body=b'', headers=None):
        self.status = status
        self.body = body
        self.headers = create_multidict(headers)
        self.sent = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_cb):
        self.close()

    def close(self):
        pass

    def _get_header_lines(self, version):
        result = []
        phrase = HTTPStatus(self.status).phrase
        result.append(
            b'HTTP/%s %i %s' % (version.encode(), self.status, phrase.encode())
        )

        for header, value in self.headers.items():
            result.append(b'%s: %s' % (header.encode(), value.encode()))

        result.append(b'\r\n')
        return b'\r\n'.join(result)

    def _set_connection(self, request):
        if 'Connection' not in self.headers:
            if request is not None and request.keep_alive:
                self.headers['Connection'] = 'keep-alive'
            else:
                self.headers['Connection'] = 'close'

    def send(self, socket, request):
        if isinstance(self.body, str):
            self.body = self.body.encode()
        elif not isinstance(self.body, bytes):
            self.body = str(self.body).encode()

        self.headers['Content-Length'] = str(len(self.body))
        self.headers['Date'] = strftime(HTTP_DATE_FORMAT)
        self._set_connection(request)

        version = '1.0' if request is None else request.version
        socket.send(self._get_header_lines(version))

        self.sent = True
        if request is None or request.method != 'HEAD':
            socket.send(self.body)

    def log_format(self):
        return {'status': self.status}


class TemplateResponse(Response):
    __slots__ = 'path', 'status', 'body', 'headers', 'sent'

    def __init__(self, path):
        self.status = 200
        self.path = path
        self.headers = create_multidict()
        self.sent = False

    def set_status(self, status):
        self.status = status
        return ''

    def set_header(self, header, value):
        self.headers.add(header, value)
        return ''

    def redirect(self, uri, temporary=True):
        self.status = 302 if temporary else 301
        self.headers['Location'] = uri
        return ''

    def _render(self, request):
        with open(self.path) as f:
            template = re.sub(r'\s*(\{\{|\}\})|(\{%|%\})\s*', r'\1\2', f.read())

        self.body = Template(template).render(
            {
                'request': request,
                'response': self,
                'token_hex': secrets.token_hex,
                'urlencode': quote_plus,
                'urldecode': unquote,
            }
        )
        if not self.headers.get('Content-Type'):
            self.headers['Content-Type'] = guess_mimetype(
                '.'.join(self.path.split('.')[:-1])
            )

    def send(self, socket, request):
        self._render(request)
        super().send(socket, request)


class FileResponse(Response):
    __slots__ = 'path', 'file', 'stat', 'etag', 'status', 'headers', 'sent'

    def __init__(self, path, headers=None):
        self.path = path
        self.file = open(path, 'rb')
        self.stat = os.stat(path)
        self.headers = create_multidict(headers)
        self.etag = "'%x'" % int(self.stat.st_mtime)
        self.sent = False

    def close(self):
        self.file.close()

    def conditional_match(self, request):
        try:
            since_header = request.headers['If-Modified-Since']
            since = mktime(strptime(since_header, HTTP_DATE_FORMAT))
            if since == self.stat.st_mtime:
                return True
        except (ValueError, KeyError):
            return request.headers.get('If-None-Match') == self.etag

    def last_modified_headers(self):
        return {
            'Last-Modified': strftime(HTTP_DATE_FORMAT, gmtime(self.stat.st_mtime)),
            'Etag': self.etag,
        }

    def send(self, socket, request):
        last_modified_headers = self.last_modified_headers()
        if self.conditional_match(request):
            raise NotModified(last_modified_headers)

        offset = 0
        count = self.stat.st_size

        range_header = request.headers.get('Range')
        if range_header:
            match = re.match(r'bytes=([0-9]+)-([0-9]*)$', range_header)
            if match:
                offset = int(match[1])
                if match[2]:
                    count = int(match[2]) - offset + 1

            if count < 1 or count + offset > self.stat.st_size:
                raise RequestedRangeNotSatisfiable()

        for header, value in last_modified_headers.items():
            self.headers[header] = value

        self.status = 200
        self.headers['Content-Length'] = str(count)
        self.headers['Date'] = strftime(HTTP_DATE_FORMAT)
        self.headers['Content-Type'] = guess_mimetype(self.path)
        self._set_connection(request)

        version = '1.0' if request is None else request.version
        socket.send(self._get_header_lines(version))

        self.sent = True
        if request is None or (request.method != 'HEAD' and not count == 0):
            socket.sendfile(self.file, offset, count)
