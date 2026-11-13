# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub: open the **Security** tab of this repository and choose **Report a vulnerability**. Do not open a public issue for a security problem.

Useful details: affected version or commit, how to reproduce, and what an attacker gains.

## What counts as a vulnerability here

This tool parses data sent by servers it does not control, and people act on its reports. The threat model in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) lists what it defends against. Reports in these areas are especially welcome:

- a hostile server makes the tool crash, hang or execute code;
- data from a server ends up unescaped in a report or in terminal output;
- a weak configuration is reported as `pass`;
- a secret from an analysed configuration file appears in any output.

## Authorised use

`tr02102-audit` is for auditing systems you own or have permission to test. It has no discovery features and sends a small, bounded number of ordinary handshakes to the endpoints you name.

## The lab

`lab/` contains a server that is insecure on purpose. It is bound to `127.0.0.1` and is not a vulnerability.
