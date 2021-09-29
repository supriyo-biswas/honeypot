#!/usr/bin/env python3

import json
import re
import select
import socket
import socketserver
import sys

from argparse import ArgumentParser
from utils import get_original_dest, Logger

supported_protocols = ['http', 'https', 'telnet', 'ssh', 'smtp', 'hexdump']


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def get_config(path):
    with open(path or 'config.json') as f:
        return json.load(f)


def run_honeypot(args):
    config = get_config(args.config)
    loggers = {}
    handlers = {}

    for protocol in supported_protocols:
        handlers[protocol] = __import__('%s_handler' % protocol).main
        loggers[protocol] = Logger(
            '%s/%s.jsonl' % (config['logging.dir'], protocol),
            config['logging.rotate'],
            config['logging.keep'],
        )

    class ConnectionHandler(socketserver.BaseRequestHandler):
        def handle(self):
            sock = self.request
            _, port = get_original_dest(sock)

            try:
                if port == 22:
                    handlers['ssh'](sock, port, loggers['ssh'], config)
                elif port == 23:
                    handlers['telnet'](sock, port, loggers['telnet'], config)
                elif port in [25, 587]:
                    handlers['smtp'](sock, port, loggers['smtp'], config)
                elif port in [80, 8080]:
                    handlers['http'](sock, port, loggers['http'], config)
                elif port in [443, 8443]:
                    handlers['https'](sock, port, loggers['https'], config)
                else:
                    rlist, _, _ = select.select([sock], [], [], 15)
                    if rlist:
                        data = sock.recv(2048, socket.MSG_PEEK)
                        if data.startswith(b'SSH-2.0-'):
                            handlers['ssh'](sock, port, loggers['ssh'], config)
                        elif re.match(rb'([a-z-]+)\s+(\S+)\s+HTTP/', data, re.I):
                            handlers['http'](sock, port, loggers['http'], config)
                        else:
                            handlers['hexdump'](sock, port, loggers['hexdump'], config)
            finally:
                sock.close()

    server = Server(('', args.port), ConnectionHandler)

    try:
        print('* Starting catch-all server on port %d' % args.port)
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        server.shutdown()
        server.server_close()
        for logger in loggers.values():
            logger.close()


def test_handler(args):
    config = get_config(args.config)
    handler = __import__('%s_handler' % args.protocol).main
    logger = Logger(
        '%s/%s.jsonl' % (config['logging.dir'], args.protocol),
        config['logging.rotate'],
        config['logging.keep'],
    )

    class ConnectionHandler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                handler(self.request, 0, logger, config)
            finally:
                self.request.close()

    server = Server(('', args.port), ConnectionHandler)

    try:
        print('* Starting %s server on port %d' % (args.protocol, args.port))
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        server.shutdown()
        server.server_close()
        logger.close()


def main():
    parser = ArgumentParser()
    parser.add_argument('--config', help='path to configuration file')
    subparsers = parser.add_subparsers()

    run_parser = subparsers.add_parser('run', help='run the honeypot')
    run_parser.add_argument('port', type=int, help='port number to use')
    run_parser.set_defaults(func=run_honeypot)

    test_parser = subparsers.add_parser('test', help='run a protocol handler')
    test_parser.add_argument('protocol', help='protocol to use')
    test_parser.add_argument('port', type=int, help='port number to use')
    test_parser.set_defaults(func=test_handler)

    if len(sys.argv) == 1:
        parser.print_help()
        parser.exit()

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
