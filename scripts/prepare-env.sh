#!/bin/bash
cd "$(dirname "$0")/.." || exit

rm -rf venv
python3.8 -mvenv venv
./venv/bin/pip install -r requirements.txt

mkdir -p data/logs

if [[ ! -e data/html ]]; then
    ln -sr scripts/deployment/files/html data/html
fi

if [[ ! -d data/ssh ]]; then
    mkdir data/ssh
    for algo in dsa rsa ecdsa ed25519; do
        ssh-keygen -t "$algo" -f "data/ssh/host_$algo" -N ''
    done
fi

if [[ ! -e data/config.json ]]; then
    sed "s:/opt/honeypot/data:$PWD/data:g" \
        scripts/deployment/files/config.json > data/config.json
fi

if [[ ! -e data/certs ]]; then
    mkdir data/certs
    openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -subj '/CN=*' \
        -keyout data/certs/key.pem \
        -out data/certs/cert.pem
fi
