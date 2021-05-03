__all__ = (
    'Logger',
    'ShellLogger',
    'clean_path',
    'get_exec_command',
    'get_original_dest',
    'get_shell_command',
    'is_valid_username',
    'match_rules',
    'readline',
    'run_cmdline_factory',
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
                except OSError as e:
                    pass

            self._fp = open(self._path, 'a+')
            self._time = time.time()

        self._fp.write(data)
        self._fp.flush()
        self._lock.release()


class ShellLogger:
    __slots__ = '_sock', '_logger', '_recvbuf', '_ip', '_dport', '_user'

    def __init__(self, sock, logger, dport, user):
        self._sock = sock
        self._logger = logger
        self._recvbuf = bytearray()
        self._ip = sock.getpeername()[0]
        self._dport = dport
        self._user = user

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_cb):
        return self.flush()

    def flush(self):
        if self._recvbuf:
            self._logger.log(
                ip=self._ip, dport=self._dport, cmd=self._recvbuf.decode('latin-1')
            )

    def recv(self, *args, **kwargs):
        data = self._sock.recv(*args, **kwargs)
        self._recvbuf.extend(data)

        if self._recvbuf:
            lines = list(filter(None, re.split(b'[\r\n]+', self._recvbuf)))
            if self._recvbuf[-1] in [10, 13]:  # ends with \r or \n
                for line in lines:
                    self._logger.log(
                        ip=self._ip,
                        dport=self._dport,
                        username=self._user,
                        cmd=line.decode('latin-1'),
                    )

                self._recvbuf.clear()
            else:
                for line in lines[:-1]:
                    self._logger.log(
                        ip=self._ip,
                        dport=self._dport,
                        username=self._user,
                        cmd=line.decode('latin-1'),
                    )

                self._recvbuf.clear()
                self._recvbuf.extend(lines[-1])

        return data

    def __getattr__(self, name):
        def method(*args, **kwargs):
            return getattr(self._sock, name)(*args, **kwargs)

        return method


def clean_path(path):
    parts = []
    for part in path.split('/'):
        if part == '..' and part:
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


def readline(sock, delim=b'\n', max_length=2048):
    if type(sock) == socket.socket:
        while True:
            select.select([sock], [], [])
            data = sock.recv(max_length, socket.MSG_PEEK)
            if not data:
                return data

            if len(data) == max_length:
                return sock.recv(max_length)

            index = data.find(delim)
            if index != -1:
                return sock.recv(index + len(delim))

    else:
        data = bytearray()
        while True:
            char = sock.recv(1)
            if not char:
                return bytes(data)

            data.extend(char)
            if char.endswith(delim) or len(data) > max_length:
                return bytes(data)


def get_original_dest(sock):
    SO_ORIGINAL_DST = 80
    data = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    _, port, o1, o2, o3, o4 = struct.unpack('!HHBBBBxxxxxxxx', data)
    return '%i.%i.%i.%i' % (o1, o2, o3, o4), port


def is_valid_username(username):
    return re.match('[a-z][a-z0-9-_]+', username, re.I)


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
            '--cpus', config.get('cpu', '0.05'),
            '--memory', config.get('memory', '16m'),
            '--pids-limit', config.get('max_processes', '20'),
            config.get('image', 'alpine:latest')
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
        finally:
            subprocess.run(['docker', 'rm', '-f', name], check=False)
            for fd in [r_stdin, w_stdin, r_stdout, w_stdout, r_stderr, w_stderr]:
                os.close(fd)

            sock.close()

    return run_cmdline
