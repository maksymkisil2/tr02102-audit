# Examples

| File | What it does |
|---|---|
| [`github-actions-tls-audit.yml`](github-actions-tls-audit.yml) | Audits your own endpoint once a week in GitHub Actions and sends the result to code scanning, so a weakened TLS configuration shows up as an alert and closes itself when fixed. |

## Other ways to run it regularly

**A pipeline gate.** The exit code is the contract: `0` nothing at or above `--fail-on`, `1` findings, `2` the scan could not be completed. A deployment step can simply depend on the scan.

```bash
tr02102-audit scan "$HOST" --standard bsi-tr-02102-2 --fail-on high
```

**A cron job that keeps evidence.** Observations are re-evaluated offline, so keeping the JSON means that when a new edition of a standard appears, you can judge last quarter's scans against it without touching the servers again.

```bash
tr02102-audit scan "$HOST" --format json --output "scans/$(date -I)-$HOST.json"
tr02102-audit evaluate "scans/2026-11-13-$HOST.json" --standard ncsc-nl-tls-2025
```

**Docker, without installing Python.**

```bash
docker build -t tr02102-audit .
docker run --rm tr02102-audit tr02102-audit scan example.org
```

Only audit systems you own or are permitted to test.
