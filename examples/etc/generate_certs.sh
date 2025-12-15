#!/usr/bin/env bash
# Generate a self-signed certificate and private key for examples
# Produces: examples/etc/certs/cert.pem and examples/etc/certs/key.pem
set -euo pipefail

OUT_DIR="$(dirname "$0")/certs"
mkdir -p "$OUT_DIR"

CERT_PATH="$OUT_DIR/cert.pem"
KEY_PATH="$OUT_DIR/key.pem"

echo "Generating self-signed certificate at $CERT_PATH and key at $KEY_PATH"

# Create a 2048-bit RSA key and a self-signed certificate valid for 10 years
openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
  -subj "/CN=localhost" \
  -keyout "$KEY_PATH" -out "$CERT_PATH"

chmod 644 "$CERT_PATH" "$KEY_PATH"

echo "Done. Use cert_file=$CERT_PATH and key_file=$KEY_PATH in your config."