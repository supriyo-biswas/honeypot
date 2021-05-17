import os
import re

from munch import munchify
from utils import *


def telnet_readline(sock, strip_newlines=False):
    line = readline(sock)
    if not line:
        return line

    result = bytearray()
    for match in re.findall(b'[^\xff]+|\xff(?:\xff|\xfd.|..)', line):
        # we handle DO + option with WONT + option, and ignore
        # WILL/WONT by not having a condition
        if match[0] != 255:
            result.extend(match)
        elif match[0] == 253:  # DO
            sock.send(b'\xff\xfc' + match[2:])
        elif match[0] == 255:
            result.append(match[0])

    if result.endswith(b'\n'):
        if strip_newlines:
            return bytes(result.rstrip(b'\r\n'))

    return bytes(result)


def send_handler(sock, fd):
    while True:
        data = os.read(fd, 4096)
        sock.send(data.replace(b'\xff', b'\xff\xff'))
        if len(data) < 4096:
            break


def recv_handler(sock, fd):
    data = telnet_readline(sock)
    if not data:
        raise ExitCmdlineLoop()

    os.write(fd, data.replace(b'\r\n', b'\n'))


run_cmdline = run_cmdline_factory(send_handler, recv_handler)


def main(sock, dport, logger, config):
    ip = sock.getpeername()[0]

    try:
        banner = config.protocols.telnet.banner.encode()
    except AttributeError:
        banner = b''

    sock.send(b'%sLogin: ' % banner)
    username = telnet_readline(sock, True).decode('latin-1')
    sock.send(b'Password: ')
    password = telnet_readline(sock, True).decode('latin-1')

    try:
        telnet_auth = config.protocols.telnet.auth
    except AttributeError:
        telnet_auth = []

    allow = is_valid_username(username) and match_rules(
        telnet_auth, username=username, password=password
    )
    logger.log(ip=ip, dport=dport, username=username, password=password, allow=allow)

    if not allow:
        sock.send(b'Login failed\r\n')
        return

    sock.send(b'Login successful\r\n')
    with ShellLogger(sock, logger, dport, username) as chan:
        run_cmdline(chan, config.get('shell', {}), get_shell_command(username))
