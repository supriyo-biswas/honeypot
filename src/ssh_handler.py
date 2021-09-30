import os
import paramiko
import paramiko.sftp as sftp
import re
import secrets
import select
import socket
import threading
import time
import traceback

from httpcore import Response, REQUEST_LINE_PATTERN
from utils import *


def get_channel(transport, chanid):
    for _ in range(10):
        time.sleep(0.1)
        channel = transport._channels.get(chanid)
        if channel is not None:
            return channel


def run_thread(target, args=()):
    threading.Thread(target=target, args=args).start()


def send_handler(sock, fd):
    while True:
        data = os.read(fd, 4096)
        sock.send(data.replace(b'\n', b'\r\n'))
        if len(data) < 4096:
            break


def recv_handler(sock, fd):
    data = sock.recv(1024)
    if not data:
        raise ExitCmdlineLoop()

    os.write(fd, data.replace(b'\r', b'\n'))
    sock.send(data.replace(b'\r', b'\r\n'))


run_cmdline = run_cmdline_factory(send_handler, recv_handler)


def run_shell(channel, dport, username, config, logger):
    shell_command = get_shell_command(username)
    with ShellLogger(channel, logger, dport, username) as chan:
        run_cmdline(chan, config, shell_command)


class SFTPServer(paramiko.BaseSFTP, paramiko.SubsystemHandler):
    def __init__(self, channel, name, server):
        paramiko.BaseSFTP.__init__(self)
        paramiko.SubsystemHandler.__init__(self, channel, name, server)

    def log_event(self, **kwargs):
        server = self.get_server()
        server.log_event(username=server.transport.get_username(), **kwargs)

    def send_status(self, request_number, code, desc=None):
        if desc is None:
            try:
                desc = sftp.SFTP_DESC[code]
            except IndexError:
                desc = 'Unknown'

        self.send_response(request_number, sftp.CMD_STATUS, code, desc, '')

    def send_response(self, request_number, t, *arg):
        msg = paramiko.Message()
        msg.add_int(request_number)

        for item in arg:
            if isinstance(item, int):
                msg.add_int(item)
            elif isinstance(item, str):
                msg.add_string(item)
            elif type(item) is paramiko.SFTPAttributes:
                item._pack(msg)
            else:
                raise Exception("unknown type")

        self._send_packet(t, msg)

    def start_subsystem(self, name, transport, channel):
        self.sock = channel
        username = self.get_server().transport.get_username()
        home = 'root' if username == 'root' else 'home/%s' % username

        self._send_server_version()
        while True:
            try:
                t, data = self._read_packet()
                msg = paramiko.Message(data)
                req_num = msg.get_int()

                if t == sftp.CMD_REALPATH:
                    path = msg.get_text()
                    self.log_event(sftp_cmd='realpath', path=path)
                    self.send_response(
                        req_num,
                        sftp.CMD_NAME,
                        1,
                        '/' + clean_path(home + '/' + path.replace('\\', '/')),
                        '',
                        paramiko.SFTPAttributes(),
                    )
                elif t == sftp.CMD_OPEN:
                    self.log_event(sftp_cmd='open', path=msg.get_text())
                    self.send_response(req_num, sftp.CMD_HANDLE, secrets.token_hex(4))
                elif t == sftp.CMD_CLOSE:
                    self.log_event(sftp_cmd='close')
                    self.send_status(req_num, paramiko.SFTP_OK)
                elif t == sftp.CMD_READ:
                    self.log_event(sftp_cmd='read')
                    self.send_status(req_num, paramiko.SFTP_BAD_MESSAGE)
                elif t == sftp.CMD_WRITE:
                    self.log_event(sftp_cmd='write')
                    self.send_status(req_num, paramiko.SFTP_OK)
                elif t == sftp.CMD_REMOVE:
                    self.log_event(sftp_cmd='remove', path=msg.get_text())
                    self.send_status(req_num, paramiko.SFTP_PERMISSION_DENIED)
                elif t == sftp.CMD_RENAME:
                    self.log_event(
                        sftp_cmd='rename',
                        source=msg.get_text(),
                        destination=msg.get_text(),
                    )
                    self.send_status(req_num, paramiko.SFTP_PERMISSION_DENIED)
                elif t == sftp.CMD_MKDIR:
                    self.log_event(sftp_cmd='mkdir', path=msg.get_text())
                    self.send_status(req_num, paramiko.SFTP_PERMISSION_DENIED)
                elif t == sftp.CMD_RMDIR:
                    self.log_event(sftp_cmd='rmdir', path=msg.get_text())
                    self.send_status(req_num, paramiko.SFTP_PERMISSION_DENIED)
                elif t == sftp.CMD_OPENDIR:
                    self.log_event(sftp_cmd='opendir', path=msg.get_text())
                    self.send_status(req_num, paramiko.SFTP_PERMISSION_DENIED)
                elif t == sftp.CMD_READDIR:
                    self.log_event(sftp_cmd='readdir')
                    self.send_status(req_num, paramiko.SFTP_BAD_MESSAGE)
                elif t == sftp.CMD_STAT:
                    self.log_event(sftp_cmd='stat', path=msg.get_text())
                    self.send_status(req_num, paramiko.SFTP_PERMISSION_DENIED)
                elif t == sftp.CMD_LSTAT:
                    self.log_event(sftp_cmd='lstat', path=msg.get_text())
                    self.send_status(req_num, paramiko.SFTP_PERMISSION_DENIED)
                elif t == sftp.CMD_FSTAT:
                    self.log_event(sftp_cmd='fstat')
                    self.send_status(req_num, paramiko.SFTP_BAD_MESSAGE)
                elif t == sftp.CMD_SETSTAT:
                    self.log_event(sftp_cmd='setstat', path=msg.get_text())
                    self.send_status(req_num, paramiko.SFTP_PERMISSION_DENIED)
                elif t == sftp.CMD_FSETSTAT:
                    self.log_event(sftp_cmd='fsetstat')
                    self.send_status(req_num, paramiko.SFTP_BAD_MESSAGE)
                elif t == sftp.CMD_READLINK:
                    self.log_event(sftp_cmd='readlink', path=msg.get_text())
                    self.send_status(req_num, paramiko.SFTP_PERMISSION_DENIED)
                elif t == sftp.CMD_SYMLINK:
                    self.log_event(
                        sftp_cmd='symlink',
                        target=msg.get_text(),
                        link_name=msg.get_text(),
                    )
                    self.send_status(req_num, paramiko.SFTP_PERMISSION_DENIED)
                elif t == sftp.CMD_EXTENDED:
                    tag = msg.get_text()
                    if tag == 'check-file':
                        self.send_status(req_num, paramiko.SFTP_BAD_HANDLE)
                    elif tag.endswith('@openssh.com'):
                        self.send_status(req_num, paramiko.SFTP_PERMISSION_DENIED)

                    self.log_event(sftp_cmd='extended', tag=tag)
                else:
                    self.log_event(sftp_cmd_raw=t)
                    self.send_status(req_num, paramiko.SFTP_OP_UNSUPPORTED)
            except EOFError:
                return
            except Exception:
                traceback.print_exc()
                return


class Server(paramiko.ServerInterface):
    def __init__(self, dport, transport, logger, config):
        self.dport = dport
        self.transport = transport
        self.logger = logger
        self.config = config
        self.transport.set_subsystem_handler('sftp', SFTPServer)

    def log_event(self, **kwargs):
        self.logger.log(ip=self.transport.getpeername()[0], dport=self.dport, **kwargs)

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_auth_password(self, username, password):
        allow = is_valid_username(username) and match_rules(
            self.config.get('protocols.ssh.auth_rules', []),
            username=username,
            password=password,
        )

        self.log_event(username=username, password=password, allow=allow)
        if allow:
            return paramiko.AUTH_SUCCESSFUL

        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.log_event(allow=False, username=username, key=str(key))
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password,publickey'

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True

    def check_channel_window_change_request(
        self, channel, width, height, pixelwidth, pixelheight
    ):
        return True

    def check_channel_shell_request(self, channel):
        run_thread(
            run_shell,
            (
                channel,
                self.dport,
                self.transport.get_username(),
                self.config,
                self.logger,
            ),
        )
        return True

    def check_channel_exec_request(self, channel, command):
        command = command.decode('latin-1')
        username = self.transport.get_username()
        self.log_event(username=username, exec_cmd=command)

        run_thread(
            run_cmdline, (channel, self.config, get_exec_command(username, command))
        )
        return True

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        def port_forwarder():
            channel = get_channel(self.transport, chanid)
            if not channel:
                return

            data = channel.recv(1024)
            if re.match(REQUEST_LINE_PATTERN, data, re.I):
                server_ip = get_original_dest(self.transport.sock)[0]
                Response(200, server_ip).send(channel, None)

            self.log_event(
                username=self.transport.get_username(),
                origin=list(origin),
                destination=list(destination),
                data=data.decode('latin-1'),
            )
            channel.close()

        run_thread(port_forwarder)
        return paramiko.OPEN_SUCCEEDED


def main(sock, dport, logger, config):
    transport = paramiko.Transport(sock)
    transport.local_version = 'SSH-2.0-%s' % config.get(
        'protocols.ssh.banner', 'OpenSSH-7.8p1'
    )

    key_types = {
        'dsa': paramiko.DSSKey,
        'rsa': paramiko.RSAKey,
        'ecdsa': paramiko.ECDSAKey,
        'ed25519': paramiko.Ed25519Key,
    }

    for name, _class in key_types.items():
        pref = 'protocols.ssh.key.%s' % name
        if pref in config:
            transport.add_server_key(_class(filename=config[pref]))

    server = Server(dport, transport, logger, config)
    transport.start_server(server=server)
    transport.join()
