# Test lab

Three TLS servers with known configurations, one server that is yours to configure, and the web interface to check them, all on your own computer. The scanner's integration tests run against the lab, and each server stands for one situation a real audit meets.

## Quick start (Windows, macOS, Linux)

1. Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) (on Linux: Docker Engine with the Compose plugin) and Git.
2. In a terminal (PowerShell on Windows):

   ```bash
   git clone https://github.com/maksymkisil2/tr02102-audit
   cd tr02102-audit
   docker compose -f lab/docker-compose.yml up -d --build
   ```

   The first start builds the web image and takes a few minutes.
3. Open <http://127.0.0.1:8080> and sign in as `admin` with the password `lab-admin-password`.
4. Check `my-site`, `tls-typical`, `tls-good` or `tls-weak` (port 443 is the default inside the lab). Tick "Keep this server in my list".

To change the lab password, set `LAB_ADMIN_PASSWORD` before the first start, or put it in a file `lab/.env`. The password and the data stay on your computer; the web interface is bound to `127.0.0.1`.

## Practise on `my-site`

`my-site` starts with nginx's default TLS settings, the way many servers run after installation.

1. Check it in the web interface and read the action plan at the top of the report.
2. Edit [`targets/my-site/nginx.conf`](targets/my-site/nginx.conf). The file lists exercises, from rating A to full BSI conformity.
3. Apply the change:

   ```bash
   docker compose -f lab/docker-compose.yml restart my-site
   ```

   If nginx does not come back, the configuration has an error: `docker compose -f lab/docker-compose.yml logs my-site` shows it.
4. Under "My servers", press "Check again", then "Compare the two checks": the comparison shows what the server accepts now, which findings are fixed and which are new.

To add another server of your own, copy the `my-site` block in `docker-compose.yml` with a new name and port, give it a configuration file, and add its name to the `issue` lines in `scripts/gen-certs.sh`. Inside the lab it is reachable by its service name.

A server that runs directly on your computer rather than in Docker is reachable from the web interface as `host.docker.internal` (Docker Desktop). Its address is private, so allow it first. Find the address:

```bash
docker compose -f lab/docker-compose.yml exec web python -c "import socket; print(socket.gethostbyname('host.docker.internal'))"
```

then set `LAB_PRIVATE_NETWORKS` to the lab network plus that address, for example `172.30.80.0/24, 192.168.65.254`, and start the lab again.

## The servers

| Target | Address | Configuration | Expected result |
|---|---|---|---|
| `tls-good` | `127.0.0.1:8443` | TLS 1.2 and 1.3, ECDHE, AES-GCM only, NIST curves, EC P-256 certificate | Conforms to every formal standard, rating A |
| `tls-typical` | `127.0.0.1:8445` | TLS 1.2 and 1.3, ECDHE, AES-GCM and ChaCha20, Curve25519, RSA-2048 certificate | Rating A, conforms to IETF RFC 9325 and PCI DSS, but not to BSI TR-02102-2 or NIST SP 800-52 |
| `tls-weak` | `127.0.0.1:8444` | See below | Fails everywhere, rating F |
| `my-site` | `127.0.0.1:8446` | nginx defaults: TLS 1.2 and 1.3, `HIGH:!aNULL:!MD5`, RSA-2048 certificate | Yours to improve |

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

## How the web interface is set up in the lab

The `web` service is built from this repository. Two settings make it fit the lab and would be wrong on the internet:

| Setting | Lab value | Why |
|---|---|---|
| `PRIVATE_NETWORKS` | `172.30.80.0/24`, the lab's Docker network | The hosted service refuses private addresses (server-side request forgery, threat T-14). In the lab, exactly this one network is allowed; every other private address is still refused. |
| `CA_FILE` | the lab CA | The lab's certificates are trusted, so a check can tell a weak configuration from an untrusted certificate. |

`lab/scripts/web-e2e.py` uses the web interface the way a person would: it signs in, checks two servers, downloads a PDF, checks a server again, compares, and makes sure a private address outside the lab is refused. CI runs it on every push.

## Usage

Requires Docker with Compose v2.

```bash
# start everything: targets, my-site and the web interface
docker compose -f lab/docker-compose.yml up -d --build

# check that they behave as documented above
docker compose -f lab/docker-compose.yml run --rm smoke

# stop and delete the generated certificates
docker compose -f lab/docker-compose.yml down -v
```

The smoke test runs in CI on every push. If an image update changes what a target accepts, it fails there first, before a scanner test can report a wrong result.

## Safety

- All ports are bound to `127.0.0.1`. `tls-weak` is insecure on purpose; do not publish it on another interface.
- Certificates and private keys are generated at start-up inside a Docker volume. Nothing secret is stored in the repository.
