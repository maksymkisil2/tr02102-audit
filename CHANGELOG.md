# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Planned: SSH (BSI TR-02102-4) and IPsec (BSI TR-02102-3) collectors, a
cryptographic bill of materials, and a line-by-line review of the BSI,
NCSC-NL and Mozilla transcriptions.

## [0.2.0] - 2026-11-16

The verdicts now say what the standards say, a rating says how good a
configuration is in practice, and the web interface became a small
multi-user service with an audit log.

### Changed

- **Verdicts follow the wording of each standard.** What a document requires
  (MUST, shall) is a failure when missing; what it recommends (SHOULD) is a
  warning. Until now every violated rule was a failure, which made RFC 9325
  reject servers it only advises, and NIST SP 800-52r2 reject the RSA
  key-transport suites its Appendix D tolerates. A validation run against
  OpenSSL on public servers showed that the measured facts were right and the
  verdicts were harsher than the documents.
- 3DES is kept apart from broken ciphers (RC4, NULL, export, anonymous),
  because the standards rate the two differently.
- The Mozilla profiles are community baselines, not formal standards. They
  are no longer evaluated unless asked for (`-s all` or by name).
- **Web interface: accounts instead of one shared password.** Sign in with
  the login name `admin` and the password from `APP_PASSWORD`. Reports are
  stored in a database instead of process memory.
- Observation and report format 2 (`complete`, `incomplete`, `rating`,
  requirement `level`, new facts).

### Added

**Scanner**

- A probe without an answer is repeated before it counts. After each
  enumeration the server is asked again for a value it accepted, so a rate
  limiter that drops connections no longer looks like a short list.
- A scan that left something unmeasured is marked incomplete; it cannot
  produce a passing verdict or a rating.
- Facts for secure renegotiation and TLS compression; ClientHello padding
  (RFC 7685) and a key-share fallback for TLS 1.3; servers without any ECDHE
  cipher suite are handled.
- `--ca-file` for servers behind an internal PKI.

**Standards and reports**

- PCI DSS v4.0.1, requirement 4.2.1, as a profile.
- An overall rating from A+ to F (`rating.yaml`), evaluated by the same
  engine from points on which the standards agree.
- Findings and verdicts that fail only because a sound algorithm is missing
  from an approved list (ChaCha20, X25519 under BSI and NIST) are marked.
- Standards carry a category: government, international, community.
- A mapping from a report to the clauses that ask for such evidence:
  ISO/IEC 27001, PCI DSS, SOC 2, BSI C5, NIS2, GDPR, DORA, HIPAA,
  IT-Grundschutz, CIS Controls, NIST CSF.

**Web interface**

- Accounts with two roles. Registration is closed until an administrator
  opens it. Password change, account deletion, sign-out of other devices.
- A monthly limit of checks per account (default 50, adjustable per
  account) and an hourly limit.
- Report history per account, with JSON and SARIF download and a print
  layout.
- Administration: an audit log of sign-ins, failed sign-ins, checks and
  changes with time, IP address, country and browser; activity per day;
  accounts can be limited, blocked and deleted.
- English, German and Ukrainian.
- SQLite by default, PostgreSQL through `DATABASE_URL` for hosting without a
  persistent disk.
- Imprint, privacy notice and terms of use, filled from `OPERATOR_*`.
- A new design, with a dark mode.

**Engineering**

- Differential validation: the scanner's facts are compared with what
  OpenSSL negotiates with 18 public servers (`validation/`).
- The lab has its own CA and a third server, `tls-typical`: a well-run
  website that rates A and still fails the approved lists of BSI and NIST.
- 187 tests. The storage and web tests run on SQLite and on PostgreSQL in CI;
  the container image is started and signed in to.

### Security

- Passwords are stored as scrypt hashes; unknown logins take as long as wrong
  passwords and get the same answer.
- A session ends when its password changes or its account is blocked.
- The CSRF token is checked in one place for every POST.
- Refused targets (private, loopback, reserved addresses) are written to the
  audit log.
- Proxy headers with the visitor's address are read only when configured.
- Failed sign-ins are limited per address (10) and per login name (100) in
  15 minutes, so one address cannot lock an account for everybody else.
- The address to return to after signing in must consist of plain path
  characters; tabs and newlines, which browsers drop, are refused.
- The threat model grew from 19 to 26 threats (accounts, storage, audit log).

### Known limitations

- The BSI, NCSC-NL and Mozilla transcriptions are still drafts.
- Rate limits for sign-in, registration and hourly checks are counted in
  process memory; the service is meant to run as one process.
- An account is protected by its password alone; there is no second factor
  and no password reset by e-mail. An administrator replaces a lost password.

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

[Unreleased]: https://github.com/maksymkisil2/tr02102-audit/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/maksymkisil2/tr02102-audit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/maksymkisil2/tr02102-audit/releases/tag/v0.1.0
