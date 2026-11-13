# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Planned: SSH (BSI TR-02102-4) and IPsec (BSI TR-02102-3) collectors, a
cryptographic bill of materials, and a line-by-line review of the BSI,
NCSC-NL and Mozilla transcriptions.

## [0.1.0] - 2026-11-13

First working release: a TLS endpoint can be scanned and judged against six
standards, from a terminal, a web interface or a CI pipeline.

### Added

**Scanner**

- TLS prober built on hand-written ClientHello messages and bounds-checked
  parsers, so the tool reports what a server accepts rather than what a TLS
  library is willing to negotiate. Enumeration by elimination covers protocol
  versions, cipher suites and key-exchange groups; TLS 1.3 groups are read from
  a HelloRetryRequest triggered by an empty key share.
- Certificate analysis (key type and size, signature hash, validity, lifetime,
  subject alternative names) and a trust check against the system store.
- Finite-field DH parameter size, Encrypt-then-MAC and extended master secret.
- Three-state probe results: accepted, refused, inconclusive. An inconclusive
  probe is never reported as a pass, and it sets exit code 2.
- Connection, time and message-size budgets, so a scan stays polite to the
  target and a hostile server cannot stall or flood the scanner.

**Standards**

- Rules as validated YAML data, each citing the section it was transcribed
  from. Shared controls make different standards comparable side by side.
- BSI TR-02102-2 (2026-01, Germany), NIST SP 800-52 Rev. 2 (USA),
  IETF RFC 9325 / BCP 195, NCSC-NL TLS Security Guidelines (2025-05),
  Mozilla Server Side TLS 5.7 Intermediate and Modern.
- "Use up to" years from the BSI tables, and phase-out levels for scales such
  as NCSC-NL's Good / Sufficient / To be phased out / Insufficient.

**Interfaces**

- `scan`, `evaluate` (re-judge a stored observation without touching the
  network), `standards` and `serve` commands.
- Report formats: text, JSON, and SARIF 2.1.0 validated against the official
  schema in CI, for GitHub code scanning and other dashboards.
- Web interface with password login, CSRF protection, rate limits, background
  scan jobs and no JavaScript at all.
- Container image that runs as a non-root user, and a Render blueprint for
  one-click hosting.

**Engineering**

- 85 tests, including end-to-end scans of real OpenSSL servers and tests for
  SSRF, CSRF, login rate limiting and open redirects.
- CI: Ruff with security rules, mypy in strict mode, pytest, a Docker Compose
  lab scanned by the CLI, a container build that is started and probed, and a
  weekly dependency audit.
- Architecture document, STRIDE threat model with 19 threats, standards guide
  and an architecture decision record.

### Known limitations

- The BSI, NCSC-NL and Mozilla rule sets are marked as draft transcriptions;
  what has and has not been verified is listed in `docs/STANDARDS.md`.
- A scan describes one endpoint at one moment. Servers behind a load balancer
  may differ, and the absence of a weak option cannot be proven.
- The hosted web service keeps jobs, reports and rate limits in process
  memory, which suits a single instance.

[Unreleased]: https://github.com/maksymkisil2/tr02102-audit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/maksymkisil2/tr02102-audit/releases/tag/v0.1.0
