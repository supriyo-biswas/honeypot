import os
import utils

from http import HTTPStatus
from httpcore import *


def add_default_headers(response):
    if not response.headers.get('Server'):
        response.headers['Server'] = 'nginx'

    if isinstance(response, (FileResponse, TemplateResponse)):
        if '.php' in response.path:
            response.headers['X-Powered-By'] = 'PHP/5.6.40'

    return response


def default_response(status, headers=None):
    response = Response(status, headers=headers)
    if status != 304:
        response.headers['Content-Type'] = 'text/html'
        response.body = '\r\n'.join(
            [
                '<html>',
                '<head><title>{0} {1}</title></head>',
                '<body>',
                '<center><h1>{0} {1}</center></h1>',
                '<hr><center>nginx</center>',
                '<body>',
                '<html>',
            ]
        ).format(status, HTTPStatus(status).phrase)

    return response


def redirect(status, location):
    response = default_response(status)
    response.headers['Location'] = location
    return response


def serve_file_handler(request, config):
    if request.path[0] != '/':
        raise BadRequest()

    webroot = config['protocols.http.root'].rstrip('/')
    path = '%s/%s' % (webroot, utils.clean_path(request.path))
    if path.endswith('.j2'):
        raise FileNotFoundError()

    if os.path.isdir(path):
        if request.path[-1] != '/':
            return redirect(301, '%s/' % request.path)

        exts = config.get('protocols.http.index_exts', ['php', 'cgi', 'html', 'xml'])
        for ext in exts:
            index_file = '%s/index.%s' % (path, ext)
            if os.path.isfile(index_file):
                return FileResponse(index_file)

        for ext in exts:
            template_file = '%s/index.%s.j2' % (path, ext)
            if os.path.isfile(template_file):
                return TemplateResponse(template_file)

        raise PermissionError()
    elif os.path.isfile('%s.j2' % path):
        return TemplateResponse('%s.j2' % path)
    else:
        return FileResponse(path)


def main(sock, dport, logger, config):
    ip = sock.getpeername()[0]
    keep_alive = True

    while keep_alive:
        keep_alive = False
        request = None
        response = None
        request_line = None

        try:
            request = Request.from_socket(sock)
            simple_proxy = request.uri.startswith('http:')
            connect_proxy = request.method == 'CONNECT'
            keep_alive = request.keep_alive and not (simple_proxy or connect_proxy)

            if simple_proxy:
                server_ip = utils.get_original_dest(sock)[0]
                response = Response(200, server_ip)
            elif connect_proxy:
                response = Response(200)
            else:
                response = serve_file_handler(request, config)

            add_default_headers(response)
            response.send(sock, request)
            response.close()
            if connect_proxy:
                request.body = sock.recv(1024)

            continue
        except RequestNotReceived:
            break
        except InvalidRequestLine as e:
            request_line = e.args[0].decode('latin-1')
            response = default_response(400)
            break
        except HTTPError as e:
            response = default_response(e.status, e.headers)
        except PermissionError:
            response = default_response(403)
        except FileNotFoundError:
            response = default_response(404)
        finally:
            # an error response will have not been sent yet
            if response is not None and not response.sent:
                add_default_headers(response)
                response.headers['connection'] = 'close'
                response.send(sock, request)

            # it only makes sense to log the request if something was
            # received
            if request is not None:
                logger.log(ip=ip, dport=dport, request=request, response=response)
            elif request_line is not None:
                logger.log(
                    ip=ip,
                    dport=dport,
                    data=request_line,
                    response=response,
                )
