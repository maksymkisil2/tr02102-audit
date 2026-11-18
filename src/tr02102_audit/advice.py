"""From findings to an action plan: what to change first, and how.

A report lists dozens of findings, many of them the same problem seen by
several standards. The action plan groups them by control (one action per
topic), ranks the actions by how much they matter, and attaches the lines of
server configuration that fix them.

Ranking, most important first:

* critical: the problem caps the rating at F (the connection is not secure
  or cannot be trusted);
* high: it caps the rating at C (an obsolete option every standard rejects);
* medium: it caps the rating at B, or at least one standard requires the
  change;
* low: only recommendations are affected, or the only objection is that a
  sound algorithm is missing from an approved list.

Only the rating can make an action critical or high, because the rating is
built from points on which all standards agree. A requirement of one
standard alone, such as BSI's 3000-bit minimum for RSA keys, is medium.

The configuration comes in two profiles. Both are taken from the project's
test lab, where CI checks the result on every push:

* compatible (``lab/targets/tls-typical``): rating A, conforms to RFC 9325,
  PCI DSS and NCSC-NL;
* strict (``lab/targets/tls-good``): conforms to every formal standard here,
  BSI TR-02102-2 and NIST SP 800-52r2 included.

Texts are English; the web interface translates them. Configuration lines
are never translated.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

PRIORITIES: tuple[str, ...] = ("critical", "high", "medium", "low")

# Which control each rating criterion belongs to (rating.yaml ids).
RATING_CONTROL: dict[str, str] = {
    "RATE-F1": "protocol-versions",
    "RATE-F2": "broken-ciphers",
    "RATE-F3": "certificate-validity",
    "RATE-F4": "certificate-trust",
    "RATE-F5": "certificate-key",
    "RATE-F6": "certificate-signature",
    "RATE-F7": "dh-parameters",
    "RATE-C1": "protocol-versions",
    "RATE-C2": "tls12-cipher-suites",
    "RATE-C3": "dh-parameters",
    "RATE-C4": "forward-secrecy",
    "RATE-C5": "tls-compression",
    "RATE-B1": "forward-secrecy",
    "RATE-B2": "tls13-support",
    "RATE-B3": "cbc-encrypt-then-mac",
    "RATE-B4": "extended-master-secret",
    "RATE-B5": "secure-renegotiation",
    "RATE-P1": "post-quantum",
}

_CAP_PRIORITY = {"F": "critical", "C": "high", "B": "medium"}

# What to do, and why it matters: (title, reason). English message ids.
ACTION_TEXT: dict[str, tuple[str, str]] = {
    "protocol-versions": (
        "Switch off old protocol versions",
        "SSL 3.0, TLS 1.0 and TLS 1.1 have known weaknesses and are rejected by every "
        "standard here. Clients from the last ten years speak TLS 1.2.",
    ),
    "tls13-support": (
        "Offer TLS 1.3",
        "TLS 1.3 removes old options and makes the handshake faster. It needs OpenSSL "
        "1.1.1 or newer.",
    ),
    "broken-ciphers": (
        "Remove broken cipher suites",
        "NULL, anonymous, export, RC4 and DES suites offer little or no protection.",
    ),
    "tls12-cipher-suites": (
        "Limit the TLS 1.2 cipher suites",
        "Keep only ECDHE key exchange with AES-GCM, and ChaCha20-Poly1305 where the "
        "standard allows it.",
    ),
    "tls13-cipher-suites": (
        "Limit the TLS 1.3 cipher suites",
        "BSI and NIST approve only the AES-GCM suites. ChaCha20-Poly1305 is sound, but "
        "not on their lists.",
    ),
    "forward-secrecy": (
        "Use only key exchange with forward secrecy",
        "With static RSA key exchange, whoever obtains the server key later can decrypt "
        "recorded traffic.",
    ),
    "key-exchange-groups": (
        "Adjust the key-exchange groups",
        "Offer the groups the standard approves. Their order sets the server's preference.",
    ),
    "dh-parameters": (
        "Strengthen or drop finite-field Diffie-Hellman",
        "DHE with short parameters can be broken. ECDHE is faster and needs no parameter file.",
    ),
    "cbc-encrypt-then-mac": (
        "Drop CBC cipher suites",
        "CBC suites without Encrypt-then-MAC are open to padding-oracle attacks. AES-GCM "
        "avoids the problem.",
    ),
    "extended-master-secret": (
        "Update the TLS library",
        "Current OpenSSL versions support the extended master secret (RFC 7627) by "
        "default. If it is missing, the library or the appliance is outdated.",
    ),
    "secure-renegotiation": (
        "Update the TLS library",
        "Current TLS libraries signal secure renegotiation (RFC 5746) by default. If it "
        "is missing, the library or the appliance is outdated.",
    ),
    "tls-compression": (
        "Switch off TLS compression",
        "Compression leaks secrets through the length of encrypted messages (CRIME).",
    ),
    "certificate-key": (
        "Use a stronger certificate key",
        "BSI asks for RSA with at least 3000 bit or an elliptic-curve key. An ECDSA key on "
        "P-256 or P-384 meets every standard here.",
    ),
    "certificate-signature": (
        "Replace a certificate signed with a weak hash",
        "Signatures with SHA-1 or MD5 can be forged.",
    ),
    "certificate-validity": (
        "Renew the certificate",
        "An expired or not yet valid certificate breaks every connection.",
    ),
    "certificate-trust": (
        "Fix the certificate chain",
        "Clients reject the connection: the certificate does not match the name, comes "
        "from an untrusted issuer, or the intermediate certificates are missing.",
    ),
    "certificate-lifetime": (
        "Use shorter-lived certificates",
        "Short lifetimes limit the damage of a lost key. Automatic renewal with ACME "
        "makes them practical.",
    ),
    "post-quantum": (
        "Add hybrid post-quantum key exchange",
        "X25519MLKEM768 protects recorded traffic against future quantum computers. It "
        "needs OpenSSL 3.5 or newer, and it turns an A into an A+.",
    ),
}

PRIORITY_TEXT: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}

PROFILE_TEXT: dict[str, tuple[str, str]] = {
    "compatible": (
        "Compatible",
        "Rating A; conforms to RFC 9325, PCI DSS and NCSC-NL. Keeps ChaCha20 and X25519, "
        "which most of the internet uses.",
    ),
    "strict": (
        "Strict",
        "Conforms to every formal standard here, BSI TR-02102-2 and NIST SP 800-52r2 "
        "included. Needs an ECDSA certificate or RSA with at least 3000 bit.",
    ),
}

# ---------------------------------------------------------------------------
# Configuration lines. Taken from lab/targets/*/nginx.conf, which CI starts and
# scans on every push; the Apache lines are the documented equivalents.
# ---------------------------------------------------------------------------

_TLS12 = {
    "compatible": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
    "strict": "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256",
}
_TLS13_STRICT = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"
_GROUPS = {"compatible": "X25519:prime256v1:secp384r1", "strict": "secp384r1:prime256v1"}
_GROUPS_PQ = "X25519MLKEM768:X25519:prime256v1:secp384r1"

_LINES: dict[str, dict[str, dict[str, list[str]]]] = {
    "nginx": {
        "protocols": {"*": ["ssl_protocols TLSv1.2 TLSv1.3;"]},
        "ciphers12": {
            "compatible": [
                f"ssl_ciphers {_TLS12['compatible']};",
                "ssl_prefer_server_ciphers off;",
            ],
            "strict": [f"ssl_ciphers {_TLS12['strict']};", "ssl_prefer_server_ciphers on;"],
        },
        "ciphers13": {
            "compatible": ["# OpenSSL's default TLS 1.3 suites are fine for this profile."],
            "strict": [f"ssl_conf_command Ciphersuites {_TLS13_STRICT};"],
        },
        "groups": {
            "compatible": [f"ssl_ecdh_curve {_GROUPS['compatible']};"],
            "strict": [f"ssl_ecdh_curve {_GROUPS['strict']};"],
        },
        "groups_pq": {"*": [f"ssl_ecdh_curve {_GROUPS_PQ};  # OpenSSL 3.5 or newer"]},
        "tickets": {"*": ["ssl_session_tickets off;"]},
        "compression": {
            "*": ["# nginx switches TLS compression off by itself; update nginx and OpenSSL."]
        },
    },
    "apache": {
        "protocols": {"*": ["SSLProtocol -all +TLSv1.2 +TLSv1.3"]},
        "ciphers12": {
            "compatible": [f"SSLCipherSuite {_TLS12['compatible']}", "SSLHonorCipherOrder off"],
            "strict": [f"SSLCipherSuite {_TLS12['strict']}", "SSLHonorCipherOrder on"],
        },
        "ciphers13": {
            "compatible": ["# OpenSSL's default TLS 1.3 suites are fine for this profile."],
            "strict": [f"SSLCipherSuite TLSv1.3 {_TLS13_STRICT}"],
        },
        "groups": {
            "compatible": [f"SSLOpenSSLConfCmd Curves {_GROUPS['compatible']}"],
            "strict": [f"SSLOpenSSLConfCmd Curves {_GROUPS['strict']}"],
        },
        "groups_pq": {"*": [f"SSLOpenSSLConfCmd Curves {_GROUPS_PQ}  # OpenSSL 3.5 or newer"]},
        "tickets": {"*": ["SSLSessionTickets off"]},
        "compression": {"*": ["SSLCompression off"]},
    },
}

_CERT_COMMANDS = {
    "compatible": [
        "# A new certificate with an ECDSA key (certbot 2.0 or newer):",
        "certbot certonly --key-type ecdsa --elliptic-curve secp256r1 -d example.org",
    ],
    "strict": [
        "# A new certificate with an ECDSA key (certbot 2.0 or newer):",
        "certbot certonly --key-type ecdsa --elliptic-curve secp384r1 -d example.org",
    ],
}
_CHAIN_LINES = [
    "# nginx: the file must hold the server certificate and the intermediates.",
    "ssl_certificate /etc/letsencrypt/live/example.org/fullchain.pem;",
    "# Apache 2.4.8 or newer:",
    "SSLCertificateFile /etc/letsencrypt/live/example.org/fullchain.pem",
]
_LIBRARY_LINES = [
    "# Check the version of the TLS library the server uses:",
    "openssl version",
    "nginx -V 2>&1 | grep -i openssl",
]

# Which configuration lines fix which control.
_CONTROL_LINES: dict[str, tuple[str, ...]] = {
    "protocol-versions": ("protocols",),
    "tls13-support": ("protocols",),
    "broken-ciphers": ("ciphers12",),
    "tls12-cipher-suites": ("ciphers12",),
    "forward-secrecy": ("ciphers12",),
    "cbc-encrypt-then-mac": ("ciphers12",),
    "dh-parameters": ("ciphers12",),
    "tls13-cipher-suites": ("ciphers13",),
    "key-exchange-groups": ("groups",),
    "post-quantum": ("groups_pq",),
    "tls-compression": ("compression",),
}


def _lines(server: str, keys: Sequence[str], profile: str) -> list[str]:
    out: list[str] = []
    for key in keys:
        variants = _LINES[server][key]
        out += variants.get(profile, variants.get("*", []))
    return out


def snippets(control: str, profile: str) -> dict[str, list[str]]:
    """Configuration that fixes one control, by server type or as shell commands."""
    if control in _CONTROL_LINES:
        keys = _CONTROL_LINES[control]
        return {server: _lines(server, keys, profile) for server in ("nginx", "apache")}
    if control in ("certificate-key", "certificate-signature", "certificate-validity"):
        return {"shell": _CERT_COMMANDS[profile]}
    if control == "certificate-trust":
        return {"shell": _CHAIN_LINES}
    if control == "certificate-lifetime":
        return {
            "shell": ["# Renew automatically, for example with certbot's timer:", "certbot renew"]
        }
    if control in ("extended-master-secret", "secure-renegotiation"):
        return {"shell": _LIBRARY_LINES}
    return {}


def configuration(profile: str) -> dict[str, list[str]]:
    """A complete TLS block for nginx and Apache in one profile."""
    keys = ("protocols", "ciphers12", "ciphers13", "groups", "tickets")
    out = {server: _lines(server, keys, profile) for server in ("nginx", "apache")}
    out["apache"] += _lines("apache", ("compression",), profile)
    return out


@dataclass(slots=True)
class Action:
    control: str
    priority: str
    title: str
    reason: str
    profile: str
    rating_cap: str | None = None
    off_list_only: bool = True  # no objection except "not on the approved list"
    evidence: list[str] = field(default_factory=list)
    affected: list[dict[str, str]] = field(default_factory=list)  # standard, status, rule ids
    snippets: dict[str, list[str]] = field(default_factory=dict)
    same_as: int | None = None  # number of an earlier action with the same configuration

    def to_dict(self) -> dict[str, Any]:
        return {
            "control": self.control,
            "priority": self.priority,
            "title": self.title,
            "reason": self.reason,
            "profile": self.profile,
            "rating_cap": self.rating_cap,
            "off_list_only": self.off_list_only,
            "evidence": self.evidence,
            "affected": self.affected,
            "snippets": self.snippets,
            "same_as": self.same_as,
        }


def _rank(priority: str) -> int:
    return PRIORITIES.index(priority)


def plan(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The action plan for a report built by ``report.build``, most important first."""
    actions: dict[str, Action] = {}

    def action(control: str) -> Action:
        if control not in actions:
            title, reason = ACTION_TEXT.get(control, (control, ""))
            actions[control] = Action(control, "low", title, reason, "compatible")
        return actions[control]

    def raise_to(item: Action, priority: str) -> None:
        if _rank(priority) < _rank(item.priority):
            item.priority = priority

    def add_evidence(item: Action, evidence: Sequence[Any]) -> None:
        for entry in evidence:
            text = str(entry)
            if text not in item.evidence:
                item.evidence.append(text)

    rate = report.get("rating") or {}
    for reason in rate.get("reasons", []):
        control = RATING_CONTROL.get(reason["id"])
        if control is None:
            continue
        item = action(control)
        if item.rating_cap is None or "FCB".index(reason["grade"]) < "FCB".index(item.rating_cap):
            item.rating_cap = reason["grade"]
        item.off_list_only = False
        raise_to(item, _CAP_PRIORITY[reason["grade"]])
        add_evidence(item, reason.get("evidence", []))
    # An A that misses only the bonus: offer the step to A+, at the lowest priority.
    if rate.get("grade") == "A":
        for missing in rate.get("bonus_missing", []):
            control = RATING_CONTROL.get(missing.get("id", ""))
            if control:
                action(control)

    for evaluation in report.get("evaluations", []):
        standard = evaluation["standard"]
        by_control: dict[str, list[dict[str, Any]]] = {}
        for finding in evaluation["findings"]:
            if finding["status"] in ("fail", "warn"):
                by_control.setdefault(finding["control"], []).append(finding)
        for control, findings in by_control.items():
            item = action(control)
            failed = [f for f in findings if f["status"] == "fail"]
            item.affected.append(
                {
                    "standard": standard["short_name"],
                    "standard_id": standard["id"],
                    "status": "fail" if failed else "warn",
                    "rules": ", ".join(f["rule_id"] for f in findings),
                }
            )
            for finding in findings:
                add_evidence(item, finding["evidence"])
            if not all(f.get("off_list_only") for f in findings):
                item.off_list_only = False
                if failed:
                    raise_to(item, "medium")

    for item in actions.values():
        if not item.affected and item.rating_cap is None:
            item.off_list_only = False  # only the A+ bonus asks for it
        if item.off_list_only and item.affected:
            # Only approved lists object: the strict profile is the fix.
            item.profile = "strict"
        item.snippets = snippets(item.control, item.profile)
    ordered = sorted(
        actions.values(),
        key=lambda a: (
            _rank(a.priority),
            "FCB".index(a.rating_cap) if a.rating_cap else 3,
            -sum(x["status"] == "fail" for x in a.affected),
        ),
    )
    # Several problems often share one fix (one cipher list removes broken,
    # CBC and non-forward-secret suites at once). Show it once.
    seen: dict[str, int] = {}
    for number, item in enumerate(ordered, 1):
        key = repr(sorted(item.snippets.items()))
        if item.snippets and key in seen:
            item.same_as = seen[key]
        elif item.snippets:
            seen[key] = number
    return [a.to_dict() for a in ordered]


def summary(report: Mapping[str, Any], actions: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Numbers for the first lines of a report."""
    evaluations = report.get("evaluations", [])
    conform = [e for e in evaluations if e["verdict"] in ("pass", "pass_with_warnings")]
    return {
        "grade": (report.get("rating") or {}).get("grade"),
        "standards": len(evaluations),
        "conform": len(conform),
        "off_list_only": sum(1 for e in evaluations if e.get("off_list_only")),
        "actions": {p: sum(1 for a in actions if a["priority"] == p) for p in PRIORITIES},
        "first": [a for a in actions if a["priority"] in ("critical", "high")][:3]
        or list(actions[:1]),
    }
