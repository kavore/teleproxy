#!/bin/sh
set -eu

CERT_DIR=/etc/nginx/certs
mkdir -p "$CERT_DIR" /var/run/nginx-mtproxy

if [ ! -f "$CERT_DIR/cert.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CERT_DIR/key.pem" \
    -out    "$CERT_DIR/cert.pem" \
    -days 7 \
    -subj "/CN=test-backend-unix" \
    -addext "subjectAltName=DNS:test-backend-unix,IP:127.0.0.1" \
    >/dev/null 2>&1
fi

# Make sure the directory that will hold the socket is writable by nginx
chown -R nginx:nginx /var/run/nginx-mtproxy 2>/dev/null || true
chmod 0775 /var/run/nginx-mtproxy || true

exec nginx -g 'daemon off;'
