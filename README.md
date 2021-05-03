# honeypot

A medium-interaction network honeypot. It has the following features:

* Listens on all TCP ports (except the one where the real sshd listens)
* Supports SSH, telnet, SMTP, HTTP, HTTPS, and raw TCP and SSL dumps
* Shell emulation for SSH/telnet by executing commands in Docker containers
* Support for logging direct-tcpip and sftp subsystem requests
* HTTP/1.1 server with support for ranged-GET requests and templated responses

It detects SSH, SSL and HTTP based on the initial request bytes, and the rest
of the protocols are supported based on their default port numbers (for
example, SMTP is supported on port 25 and 587, telnet on port 23, and so on.)
Data sent through any other unknown protocol is logged as-is.

# Deployment

Although the honeypot can be run on any Linux system, the instructions
provided are only for Ubuntu 20.04. The steps below also take care of SSL
version issues by providing a packaged version of Python 3.8 that supports TLS
1.0 to 1.3. It also deploys a fake webpages for Wordpress, phpmyadmin and
Outlook web in order to lure attackers.

* Ensure that your honeypot nodes have sshd configured to listen on a high
port instead of port 22. You can do this by placing a file in
`/etc/ssh/sshd_config.d/port-change.conf`:

```
Port 34567
```

Then, restart sshd with `sudo systemctl restart ssh`

* If you're not using the root user, make sure that the user is allowed to
use passwordless `sudo`. This can be done by adding the file
`/etc/sudoers.d/nopasswd`:

```
myuser ALL=(ALL:ALL) NOPASSWD:ALL
```

* In the root of the project directory, create an Ansible inventory named
`hosts` with a list of hosts. Whenever possible, use DNS names associated
with these hosts, this will help with generating certificates from Let's
Encrypt. An example is shown below:

```ini
[honeypot_nodes]
node01 ansible_host=test1.example.com
node02 ansible_host=test2.example.com

[honeypot_nodes:vars]
ansible_port=34567
ansible_user=myuser

# Required only if you want certificates from Let's Encrypt. Otherwise,
# a self signed certificate is generated
letsencrypt_email_address=username@example.com
```

* Deploy the honeypot using the included Ansible playbook towards the
honeypot nodes:

```bash
ansible-playbook -i hosts -e target=honeypot_nodes scripts/deployment/playbook.yaml
```

## License

[GPLv3](https://opensource.org/licenses/gpl-3.0.html)
