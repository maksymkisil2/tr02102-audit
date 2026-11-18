#!/bin/sh
# Generates a throwaway certificate authority and server certificates for the
# lab targets.
#
# The lab has its own CA so that a scan can tell "the certificate does not
# verify" apart from "the configuration is weak". Pass the CA to the scanner
# with --ca-file; nothing outside the lab trusts it.
#
# The private keys exist only inside the "certs" Docker volume. They are never
# written to the repository and are deleted by "docker compose down -v".
set -eu

OUT="${OUT:-/certs}"
DAYS="${DAYS:-30}"

mkdir -p "$OUT"

# Each file is created only if it is missing, so a lab that was started
# before a new target existed gets that target's certificate on the next run.
if [ ! -f "$OUT/lab-ca.crt" ]; then
openssl req -x509 -noenc -days "$DAYS" \
    -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$OUT/lab-ca.key" -out "$OUT/lab-ca.crt" \
    -subj "/O=tr02102-audit test lab/CN=Lab Root CA (not for production)" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
fi

# issue <name> <openssl key options...>
issue() {
    name="$1"
    shift
    if [ -f "$OUT/$name.crt" ]; then
        return 0
    fi
    openssl req -x509 -noenc -days "$DAYS" "$@" \
        -CA "$OUT/lab-ca.crt" -CAkey "$OUT/lab-ca.key" \
        -keyout "$OUT/$name.key" -out "$OUT/$name.crt" \
        -subj "/CN=$name.lab.test" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth" \
        -addext "subjectAltName=DNS:$name.lab.test,DNS:$name,DNS:localhost,IP:127.0.0.1"
}

# tls-good: ECDSA key on NIST P-256.
issue tls-good -newkey ec -pkeyopt ec_paramgen_curve:prime256v1
# tls-typical: the 2048-bit RSA key most public websites use.
issue tls-typical -newkey rsa:2048
# tls-weak: 2048-bit RSA as well; its weaknesses are in the protocol settings.
issue tls-weak -newkey rsa:2048
# my-site: your own server to practise on; RSA 2048 like most websites.
issue my-site -newkey rsa:2048

# Certificates are public; the web service reads the CA as an unprivileged user.
chmod 644 "$OUT"/*.crt
echo "lab certificates ready in $OUT"
