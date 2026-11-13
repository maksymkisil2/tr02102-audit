# ADR-0001: Python as the implementation language

- Status: accepted
- Date: 2026-11-13

## Context

The tool needs to craft and parse TLS and SSH handshake messages, parse X.509 certificates, evaluate declarative rules and render reports. The two realistic candidates were Python and Go.

## Decision

Use Python 3.13. Keep runtime dependencies few and add each one only together with the component that needs it; the command-line interface uses `argparse` from the standard library.

## Reasons

- Handshake probing works on cleartext messages (see ARCHITECTURE.md, section 6), so the prober needs sockets and byte parsing, not a cryptographic library. The standard library covers that.
- Python is memory-safe, which removes the most severe class of parser bugs (threat T-11).
- Type hints with `mypy --strict` give most of the safety net a compiled language would.
- A scan is bounded by network round-trips, not by CPU, so interpreter speed is irrelevant.
- Fewer dependencies mean a smaller supply-chain surface (threat T-04).

## Consequences

- Distribution needs an interpreter. A container image will cover users who do not want to install Python (planned).
- Go's single static binary is given up. If distribution becomes a real obstacle, the collectors are isolated behind the observation format and could be reimplemented without touching policy or reports.
