import http_handler
import ssl

handled_ports = [443, 9200, 10443]


def main(sock, dport, logger, config):
    ip = sock.getpeername()[0]

    try:
        sock = ssl.wrap_socket(
            sock, config['tls.keyfile'], config['tls.certfile'], True
        )
    except ssl.SSLError:
        logger.log(ip=ip, dport=dport, data='', response=None)
        return

    http_handler.main(sock, dport, logger, config)
