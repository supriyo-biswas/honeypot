__all__ = (
    'AssociatedDataLogger',
    'ExitCmdlineLoop',
    'Logger',
    'ShellLogger',
    'clean_path',
    'dispatch_protocol',
    'get_exec_command',
    'get_original_dest',
    'get_shell_command',
    'is_valid_username',
    'match_rules',
    'readline',
    'run_cmdline_factory',
    'ssl_wrap',
)

import calendar
import collections
import glob
import json
import os
import re
import secrets
import select
import socket
import ssl
import struct
import subprocess
import threading
import time


class Logger:
    DATE_FORMAT = '%Y-%m-%d %H:%M:%S %Z'
    __slots__ = '_path', '_fp', '_lock', '_rotate', '_keep', '_time', '_files'

    def __init__(self, path, rotate, keep):
        self._path = path
        self._rotate = rotate
        self._keep = keep
        self._lock = threading.Lock()

        self._fp = open(self._path, 'a+')
        self._fp.seek(0)

        try:
            first_line = self._fp.readline()
            self._time = calendar.timegm(
                time.strptime(json.loads(first_line)['ts'], self.__class__.DATE_FORMAT)
            )
        except (IndexError, json.decoder.JSONDecodeError):
            self._time = None

        name, ext = os.path.splitext(self._path)
        self._files = collections.deque(glob.glob('%s_[0-9:-]*-[A-Z]*%s' % (name, ext)))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_cb):
        self.close()

    def close(self):
        self._fp.close()

    def log(self, **kwargs):
        now = time.time()
        ts = time.strftime(self.__class__.DATE_FORMAT, time.gmtime(now))
        for key, value in kwargs.items():
            if hasattr(value, 'log_format'):
                kwargs[key] = value.log_format()

        data = '{"ts": "%s", %s\n' % (ts, json.dumps(kwargs)[1:])

        self._lock.acquire()
        if self._time is None:
            self._time = now
            rotate = False
        else:
            rotate = (now - self._time) > self._rotate

        if rotate:
            self._fp.close()

            name, ext = os.path.splitext(self._path)
            log_date = time.strftime(self.__class__.DATE_FORMAT, time.gmtime(now))
            self._files.appendleft('%s_%s%s' % (name, log_date.replace(' ', '-'), ext))
            os.rename(self._path, self._files[0])

            while len(self._files) > self._keep:
                try:
                    os.remove(self._files.pop())
                except OSError:
                    pass

            self._fp = open(self._path, 'a+')
            self._time = time.time()

        self._fp.write(data)
        self._fp.flush()
        self._lock.release()


class AssociatedDataLogger:
    __slots__ = '_logger', '_data'

    def __init__(self, logger, data):
        self._logger = logger
        self._data = data

    def log(self, **kwargs):
        self._logger.log(**self._data, **kwargs)


class ShellLogger(AssociatedDataLogger):
    __slots__ = '_sock', '_logger', '_recvbuf', '_recv_accepts_flags'

    def __init__(self, sock, logger, dport, user, recv_accepts_flags=True):
        self._sock = sock
        self._recvbuf = bytearray()
        self._recv_accepts_flags = recv_accepts_flags
        super().__init__(
            logger, {'ip': sock.getpeername()[0], 'dport': dport, 'username': user}
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_cb):
        return self.flush()

    def flush(self):
        if self._recvbuf:
            self._logger.log(cmd=self._recvbuf.decode('latin-1'))

    def recv(self, length, flags=0):
        if self._recv_accepts_flags:
            data = self._sock.recv(length, flags)
        else:
            data = self._sock.recv(length)

        # skip logging if the socket is only being peeked
        if not self._recv_accepts_flags or (flags & socket.MSG_PEEK == 0):
            self._recvbuf.extend(data)
            if self._recvbuf:
                lines = list(filter(None, re.split(b'[\r\n]+', self._recvbuf)))
                if self._recvbuf[-1] in [10, 13]:  # ends with \r or \n
                    for line in lines:
                        super().log(cmd=line.decode('latin-1'))
                    self._recvbuf.clear()
                else:
                    for i in range(len(lines) - 1):
                        super().log(cmd=lines[i].decode('latin-1'))

                    self._recvbuf.clear()
                    self._recvbuf.extend(lines[-1])

        return data

    def __getattr__(self, name):
        def method(*args, **kwargs):
            return getattr(self._sock, name)(*args, **kwargs)

        return method


class PeekableSocket:
    __slots__ = '_sock', '_ps_pending'

    def __init__(self, sock):
        if type(sock) == socket.socket:
            raise TypeError('socket.socket is already peekable')

        self._sock = sock
        self._ps_pending = bytearray()

    def wait_until_readable(self):
        if not self._ps_pending:
            select.select([self._sock], [], [])

    def recv(self, length, flags=0):
        if flags != 0 and flags != socket.MSG_PEEK:
            raise ValueError('only socket.MSG_PEEK flag is supported')

        data = bytearray()
        if self._ps_pending:
            data.extend(self._ps_pending[:length])
            if flags != socket.MSG_PEEK:
                del self._ps_pending[:length]

        if not data and length - len(data) > 0:
            rcvd = self._sock.recv(length - len(data))
            data.extend(rcvd)
            if flags == socket.MSG_PEEK:
                self._ps_pending.extend(rcvd)

        return bytes(data)

    def __getattr__(self, name):
        def method(*args, **kwargs):
            return getattr(self._sock, name)(*args, **kwargs)

        return method


class ExitCmdlineLoop(Exception):
    pass


def dispatch_protocol(sock, dport, ports, matchers={}):
    for port, handler in ports.items():
        if dport == port:
            return handler

    if matchers:
        rlist, _, _ = select.select([sock], [], [], 10)
        if rlist:
            data = sock.recv(2048, socket.MSG_PEEK)
            for matcher, handler in matchers.items():
                if matcher.match(data):
                    return handler

    return ports.get('*')


def clean_path(path):
    parts = []
    for part in path.split('/'):
        if part == '..' and len(parts) > 0:
            parts.pop()
        elif part in ['', '.']:
            pass
        else:
            parts.append(part)

    return '/'.join(parts)


def match_condition(rule, s):
    if s == None:
        return False
    elif rule[0] == '/' and rule[-1] == '/':
        return bool(re.search(rule[1:-1], s))
    elif rule[0] == '/' and rule[-2:] == '/i':
        return bool(re.search(rule[1:-2], s, re.I))

    return rule == s


def match_rule(rule, values):
    for key, value in rule.items():
        if key != 'should' and not match_condition(value, values.get(key)):
            return False

    return True


def match_rules(rules, **kwargs):
    for rule in rules:
        if match_rule(rule, kwargs):
            return rule.get('should') == 'allow'

    return False


def ssl_wrap(sock, keyfile, certfile):
    return PeekableSocket(ssl.wrap_socket(sock, keyfile, certfile, True))


def readline(sock, delim=b'\n', max_length=2048):
    data = bytearray()
    should_use_select = not isinstance(sock, PeekableSocket)
    while len(data) < max_length:
        if should_use_select:
            select.select([sock], [], [])
        else:
            sock.wait_until_readable()
        rcvd = sock.recv(max_length, socket.MSG_PEEK)
        if not rcvd:
            break
        index = rcvd.find(delim)
        if index == -1:
            data.extend(sock.recv(max_length - len(data)))
        else:
            data.extend(sock.recv(index + len(delim)))
            break

    return bytes(data)


def get_original_dest(sock):
    SO_ORIGINAL_DST = 80
    data = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    _, port, o1, o2, o3, o4 = struct.unpack('!HHBBBBxxxxxxxx', data)
    return '%i.%i.%i.%i' % (o1, o2, o3, o4), port


def is_valid_username(username):
    return bool(re.match('[a-z][a-z0-9-_]+$', username, re.I))


def get_shell_command(user):
    if user == 'root':
        return ['/bin/sh', '-c', 'cd /root; /bin/sh -i +m']

    return [
        '/bin/sh',
        '-c',
        'adduser -D %s; cd /home/%s; su %s -c "/bin/sh -i +m"' % (user, user, user),
    ]


def get_exec_command(user, command):
    if user == 'root':
        return ['/bin/sh', '-c', command]

    return [
        '/bin/sh',
        '-c',
        'adduser -D %s; cd /home/%s; su %s -c "%s"'
        % (user, user, user, re.sub(r'([$"\\\n`])', r'\\\1', command)),
    ]


def run_cmdline_factory(send_handler, recv_handler):
    def run_cmdline(sock, config, command):
        name = 'sbx_%s' % secrets.token_hex(4)
        # fmt:off
        run_command = [
            'docker', 'run', '--rm', '-i',
            '--network', 'none',
            '--name', name,
            '--mount', 'type=tmpfs,destination=/tmp,tmpfs-size=32M',
            '--cpus', str(config.get('shell.cpu', 0.05)),
            '--memory', '%sm' % config.get('shell.memory', 16),
            '--pids-limit', str(config.get('shell.max_processes', 20)),
            config.get('shell.image', 'alpine:latest')
        ]
        # fmt:on

        run_command.extend(command)  # Do it this way to satisfy black

        try:
            r_stdin, w_stdin = os.pipe()
            r_stdout, w_stdout = os.pipe()
            r_stderr, w_stderr = os.pipe()

            process = subprocess.Popen(
                run_command,
                bufsize=0,
                stdin=r_stdin,
                stdout=w_stdout,
                stderr=w_stderr,
            )
            while process.poll() is None:
                read_fds, _, _ = select.select([r_stdout, r_stderr, sock], [], [], 1)
                if not read_fds:
                    continue

                if r_stderr in read_fds:
                    send_handler(sock, r_stderr)

                if r_stdout in read_fds:
                    send_handler(sock, r_stdout)

                if sock in read_fds:
                    _, write_fds, _ = select.select([], [w_stdin], [], 0)
                    if write_fds:
                        recv_handler(sock, w_stdin)
        except ExitCmdlineLoop:
            pass
        finally:
            if process.poll() is None:
                subprocess.run(
                    ['docker', 'rm', '-f', name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

            for fd in [r_stdin, w_stdin, r_stdout, w_stdout, r_stderr, w_stderr]:
                os.close(fd)

            sock.close()

    return run_cmdline
