#!/bin/sh
set -e

CERT_DIR="${CERT_DIR:-/certs}"
mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_DIR/cert.pem" ] || [ ! -f "$CERT_DIR/key.pem" ]; then
    echo "No TLS cert found in $CERT_DIR, generating a self-signed one..."
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$CERT_DIR/key.pem" \
        -out "$CERT_DIR/cert.pem" \
        -days 3650 \
        -subj "/CN=${CERT_CN:-unifi-controller}"
fi

exec python3 -u /app/ws_dump_server.py
