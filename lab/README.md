# Test lab

Two TLS servers with known configurations. The scanner's integration tests run against them: one server must pass, the other must fail in specific, documented ways.

| Target | Address | Configuration | Role |
|---|---|---|---|
| `tls-good` | `127.0.0.1:8443` | TLS 1.2 and 1.3, ECDHE key exchange, AES-GCM, NIST curves, EC P-256 certificate | Expected to pass |
| `tls-weak` | `127.0.0.1:8444` | See below | Expected to fail |

## What is deliberately wrong with `tls-weak`

| Weakness | How it is configured |
|---|---|
| Legacy protocol versions | TLS 1.0 and TLS 1.1 are enabled |
| No TLS 1.3 | Only TLS 1.0–1.2 are offered |
| No forward secrecy | RSA key-exchange cipher suites are accepted |
| CBC cipher suites | The full legacy cipher list is enabled |
| Short RSA key | The certificate uses a 2048-bit RSA key |

Whether each of these is a finding, and under which section of TR-02102, is decided by the policy files in milestone M1. The lab only guarantees that the weaknesses are really there.

## Usage

Requires Docker with Compose v2.

```bash
# start both targets
docker compose -f lab/docker-compose.yml up -d

# check that they behave as documented above
docker compose -f lab/docker-compose.yml run --rm smoke

# stop and delete the generated certificates
docker compose -f lab/docker-compose.yml down -v
```

The smoke test runs in CI on every push. If an image update changes what a target accepts, it fails there first, before a scanner test can report a wrong result.

## Safety

- Both ports are bound to `127.0.0.1`. `tls-weak` is insecure on purpose; do not publish it on another interface.
- Certificates and private keys are generated at start-up inside a Docker volume. Nothing secret is stored in the repository.
