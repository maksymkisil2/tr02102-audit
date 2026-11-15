# Test lab

Three TLS servers with known configurations. The scanner's integration tests run against them, and each server stands for one situation a real audit meets.

| Target | Address | Configuration | Expected result |
|---|---|---|---|
| `tls-good` | `127.0.0.1:8443` | TLS 1.2 and 1.3, ECDHE, AES-GCM only, NIST curves, EC P-256 certificate | Conforms to every formal standard, rating A |
| `tls-typical` | `127.0.0.1:8445` | TLS 1.2 and 1.3, ECDHE, AES-GCM and ChaCha20, Curve25519, RSA-2048 certificate | Rating A, conforms to IETF RFC 9325 and PCI DSS, but not to BSI TR-02102-2 or NIST SP 800-52 |
| `tls-weak` | `127.0.0.1:8444` | See below | Fails everywhere, rating F |

`tls-typical` is the important one. It is configured the way most well-run public websites are, and it shows why "does not conform to BSI" is not the same as "insecure": the government standards accept only the algorithms on their approved lists.

## What is deliberately wrong with `tls-weak`

| Weakness | How it is configured |
|---|---|
| Legacy protocol versions | TLS 1.0 and TLS 1.1 are enabled |
| No TLS 1.3 | Only TLS 1.0–1.2 are offered |
| No forward secrecy | RSA key-exchange cipher suites are accepted |
| Anonymous key exchange | The full legacy cipher list is enabled, including suites without server authentication |
| CBC cipher suites | Part of the same legacy list |

## Certificates

The lab has its own throwaway certificate authority. All three server certificates are signed by it, so a scan can tell "the certificate does not verify" apart from "the configuration is weak". Nothing outside the lab trusts this CA; the scanner is told about it explicitly:

```bash
docker compose -f lab/docker-compose.yml cp tls-good:/etc/nginx/certs/lab-ca.crt lab-ca.crt
tr02102-audit scan 127.0.0.1:8443 --ca-file lab-ca.crt
```

The same option is what you use for servers behind a company's internal PKI.

## Usage

Requires Docker with Compose v2.

```bash
# start all targets
docker compose -f lab/docker-compose.yml up -d

# check that they behave as documented above
docker compose -f lab/docker-compose.yml run --rm smoke

# stop and delete the generated certificates
docker compose -f lab/docker-compose.yml down -v
```

The smoke test runs in CI on every push. If an image update changes what a target accepts, it fails there first, before a scanner test can report a wrong result.

## Safety

- All ports are bound to `127.0.0.1`. `tls-weak` is insecure on purpose; do not publish it on another interface.
- Certificates and private keys are generated at start-up inside a Docker volume. Nothing secret is stored in the repository.
