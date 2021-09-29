#!/bin/bash
export LC_ALL=C.UTF-8
export DEBIAN_FRONTEND=noninteractive
apt-get autoremove --purge -y landscape-common snapd byobu

mkdir -p /etc/docker
echo '{"userns-remap":"default"}' > /etc/docker/daemon.json

apt-get update
apt-get upgrade -y
apt-get install -y build-essential curl gnutls-bin docker.io ripgrep ansible python3-venv

adduser vagrant docker
docker pull alpine:latest

cd /tmp || exit
wget -q https://github.com/supriyo-biswas/python-builds/releases/download/3.8.8/python-3.8.8-linux-x86_64.tar.bz2
mkdir -p /opt/python3
tar -C /opt/python3 -xf python-3.8.8-linux-x86_64.tar.bz2
rm -rf /opt/python3/etc/ssl/certs
ln -s /etc/ssl/certs/ /opt/python3/etc/ssl/certs
rm python-3.8.8-linux-x86_64.tar.bz2

# shellcheck disable=SC2016
echo 'export PATH="/opt/python3/bin:$PATH"' >> /home/vagrant/.bashrc
chown vagrant: /home/vagrant/.bashrc
