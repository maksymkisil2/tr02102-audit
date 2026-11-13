#!/bin/sh
# Verifies that the lab targets behave as documented in lab/README.md.
#
# The integration tests of the scanner rely on these two servers having a
# known configuration. If an image update silently changes what a target
# accepts, this script fails before any scanner test can give a wrong answer.
set -eu

GOOD="${GOOD:-tls-good:443}"
WEAK="${WEAK:-tls-weak:443}"

# Client-side switch that lets OpenSSL offer legacy protocol versions and
# cipher suites at all. It does not make the server accept them.
LEGACY="ALL:@SECLEVEL=0"

failures=0

# handshake <host:port> [openssl s_client options...]
# Exit status 0 means the TLS handshake completed.
handshake() {
    target="$1"
    shift
    timeout 10 openssl s_client -connect "$target" "$@" </dev/null >/dev/null 2>&1
}

expect_accept() {
    description="$1"
    shift
    if handshake "$@"; then
        echo "ok    $description"
    else
        echo "FAIL  $description (expected the handshake to succeed)"
        failures=$((failures + 1))
    fi
}

expect_reject() {
    description="$1"
    shift
    if handshake "$@"; then
        echo "FAIL  $description (expected the handshake to be refused)"
        failures=$((failures + 1))
    else
        echo "ok    $description"
    fi
}

# public_key_line <host:port>
# Prints the "Public-Key: (N bit)" line of the server certificate.
public_key_line() {
    timeout 10 openssl s_client -connect "$1" -cipher "$LEGACY" </dev/null 2>/dev/null \
        | openssl x509 -noout -text 2>/dev/null \
        | grep "Public-Key:" || true
}

expect_key() {
    description="$1"
    target="$2"
    wanted="$3"
    actual="$(public_key_line "$target")"
    case "$actual" in
        *"($wanted bit)"*)
            echo "ok    $description"
            ;;
        *)
            echo "FAIL  $description (certificate reports: ${actual:-nothing})"
            failures=$((failures + 1))
            ;;
    esac
}

echo "== tls-good ($GOOD)"
expect_accept "accepts TLS 1.3" "$GOOD" -tls1_3
expect_accept "accepts TLS 1.2 with forward secrecy" "$GOOD" -tls1_2
expect_reject "refuses TLS 1.1" "$GOOD" -tls1_1 -cipher "$LEGACY"
expect_reject "refuses TLS 1.0" "$GOOD" -tls1 -cipher "$LEGACY"
expect_reject "refuses RSA key exchange (no forward secrecy)" "$GOOD" -tls1_2 -cipher AES128-SHA
expect_reject "refuses CBC cipher suites" "$GOOD" -tls1_2 -cipher ECDHE-ECDSA-AES128-SHA256
expect_reject "refuses ChaCha20-Poly1305 in TLS 1.3" "$GOOD" -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256
expect_key "certificate uses a 256-bit EC key" "$GOOD" 256

echo "== tls-weak ($WEAK)"
expect_accept "accepts TLS 1.0" "$WEAK" -tls1 -cipher "$LEGACY"
expect_accept "accepts TLS 1.1" "$WEAK" -tls1_1 -cipher "$LEGACY"
expect_accept "accepts TLS 1.2" "$WEAK" -tls1_2
expect_accept "accepts RSA key exchange (no forward secrecy)" "$WEAK" -tls1_2 -cipher AES128-SHA
expect_reject "does not offer TLS 1.3" "$WEAK" -tls1_3
expect_key "certificate uses a 2048-bit RSA key" "$WEAK" 2048

if [ "$failures" -gt 0 ]; then
    echo "$failures check(s) failed: the lab does not match its documentation"
    exit 1
fi
echo "all lab checks passed"
