import re
import socket
import ssl


def main(sock, dport, logger, config):
    ip = sock.getpeername()[0]
    data = sock.recv(2048, socket.MSG_PEEK)
    using_ssl = bool(re.match(b'\x16(\x02|\x03)', data))

    if using_ssl:
        try:
            ssl_sock = ssl.wrap_socket(
                sock, config['tls.keyfile'], config['tls.certfile'], True
            )
            data = ssl_sock.recv(2048)
        except ssl.SSLError:
            using_ssl = False

    logger.log(ip=ip, dport=dport, ssl=using_ssl, data=data.decode('latin-1'))
