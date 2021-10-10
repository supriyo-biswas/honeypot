import re
import ssl
import utils

handled_ports = [25, 587]


def parse_command(cmd):
    result = []
    for part in re.split(rb'\s+', cmd.strip()):
        result.append(re.sub(rb'^(\w+)', lambda p: p[1].upper(), part))

    return result


def main(sock, dport, logger, config):
    ip = sock.getpeername()[0]

    helo_done = False
    starttls_done = False
    receiving_data = False

    mail_from = None
    rcpt_to = []
    data = []

    server_ip, _ = utils.get_original_dest(sock)
    hostname = config.get('protocols.smtp.hostname', server_ip).encode()
    sock.send(b'220 %s ESMTP server ready\r\n' % hostname)

    while True:
        line = utils.readline(sock)
        if not line:
            break

        if not line.endswith(b'\r\n'):
            if len(line) == 2048:
                sock.send(b'500 Line too long\r\n')
                if receiving_data:
                    receiving_data = False
            elif not receiving_data:
                sock.send(b'500 Command unrecognized\r\n')
            continue

        if receiving_data:
            if line == b'.\r\n':
                receiving_data = False
                logger.log(
                    ip=ip, dport=dport, mail_from=mail_from, rcpt_to=rcpt_to, data=data
                )

                mail_from = None
                rcpt_to.clear()
                data.clear()
                sock.send(b'250 Message accepted\r\n')

            if line[0] == b'.':
                line = line[1:]

            data.append(line.decode())
            continue

        command = parse_command(line)

        if command[0] == b'HELO':
            if len(command) == 1:
                sock.send(b'501 Domain name required\r\n')
                continue

            helo_done = True
            sock.send(b'250 %s at your service\r\n' % hostname)

        elif command[0] == b'EHLO':
            if len(command) == 1:
                sock.send(b'501 Domain name required\r\n')
                continue

            helo_done = True
            sock.send(b'250-%s at your service\r\n' % hostname)
            sock.send(b'250-SMTPUTF8\r\n')
            sock.send(b'250-8BITMIME\r\n')
            sock.send(b'250 STARTTLS\r\n')

        elif command[0] == b'HELP':
            sock.send(b'214 Refer https://tools.ietf.org/html/rfc5321\r\n')

        elif command[0] == b'QUIT':
            sock.send(b'221 Closing connection\r\n')
            break

        elif command[0] == b'NOOP':
            sock.send(b'250 NOOP OK\r\n')

        elif command[0] == b'RSET':
            mail_from = None
            rcpt_to.clear()
            data.clear()
            sock.send(b'250 RSET OK\r\n')

        elif command[0] == b'MAIL':
            if not helo_done:
                sock.send(b'503 Must issue HELO/EHLO first\r\n')
                continue

            if len(command) == 1 or not re.match(b'FROM:<.*>$', command[1]):
                sock.send(b'501 Syntax error\r\n')
                continue

            mail_from = command[1][6:-1].decode()
            sock.send(b'250 Sender OK\r\n')

        elif command[0] == b'RCPT':
            if not helo_done:
                sock.send(b'503 Must issue HELO/EHLO first\r\n')
                continue

            if len(command) == 1 or not re.match(b'TO:<.*>$', command[1]):
                sock.send(b'501 Syntax error\r\n')
                continue

            rcpt_to.append(command[1][4:-1].decode())
            sock.send(b'250 Recipient OK\r\n')

        elif command[0] == b'DATA':
            if not (mail_from and rcpt_to):
                sock.send(b'250 Sender/recipient not specified\r\n')
                continue

            receiving_data = True
            sock.send(b'354 Start mail input\r\n')

        elif command[0] == b'VRFY':
            sock.send(b'252 Cannot VRFY user but will attempt delivery\r\n')

        elif command[0] == b'STARTTLS':
            if starttls_done:
                sock.send(b'454 TLS not available due to temporary reason\r\n')
                continue

            starttls_done = True
            helo_done = False
            mail_from = None
            rcpt_to.clear()
            data.clear()

            sock.send(b'220 Ready to start TLS\r\n')
            sock = ssl.wrap_socket(
                sock, config['tls.keyfile'], config['tls.certfile'], True
            )

        else:
            sock.send(b'502 Command not implemented\r\n')
