#!/bin/sh
# Generates throwaway self-signed certificates for the lab targets.
#
# The private keys exist only inside the "certs" Docker volume. They are never
# written to the repository and are deleted by "docker compose down -v".
set -eu

OUT="${OUT:-/certs}"

if [ -f "$OUT/.done" ]; then
    echo "lab certificates already present in $OUT"
    exit 0
fi

mkdir -p "$OUT"

# tls-good: ECDSA key on NIST P-256.
openssl req -x509 -noenc -days 30 \
    -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$OUT/tls-good.key" -out "$OUT/tls-good.crt" \
    -subj "/CN=tls-good.lab.test" \
    -addext "subjectAltName=DNS:tls-good,DNS:localhost,IP:127.0.0.1"

# tls-weak: 2048-bit RSA key, deliberately below the recommended length.
openssl req -x509 -noenc -days 30 \
    -newkey rsa:2048 \
    -keyout "$OUT/tls-weak.key" -out "$OUT/tls-weak.crt" \
    -subj "/CN=tls-weak.lab.test" \
    -addext "subjectAltName=DNS:tls-weak,DNS:localhost,IP:127.0.0.1"

touch "$OUT/.done"
echo "lab certificates written to $OUT"
