#!/bin/bash

set -euo pipefail

certbot renew --cert-name "$1"
cp "/etc/letsencrypt/live/$1/fullchain.pem" /opt/honeypot/data/certs/cert.pem
cp "/etc/letsencrypt/live/$1/privkey.pem" /opt/honeypot/data/certs/key.pem
