"""Standards as data: loading and validating the YAML rule sets.

Each ``*.yaml`` file in this package describes one standard (or one profile of
a standard). Adding a standard means adding a file; no code changes. Files are
loaded with ``yaml.safe_load`` and validated strictly, so a policy file can
never carry code (threat T-12), and a typo fails loudly instead of silently
weakening an audit (threat T-03).
"""

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from typing import Any

import yaml

# The shared vocabulary that makes standards comparable. Every rule belongs to
# exactly one control; the report shows one row per control and one column
# per standard, so gaps between standards become visible.
CONTROLS: dict[str, str] = {
    "protocol-versions": "Protocol versions",
    "tls13-support": "TLS 1.3 offered",
    "tls12-cipher-suites": "TLS 1.2 cipher suites",
    "tls13-cipher-suites": "TLS 1.3 cipher suites",
    "forward-secrecy": "Forward secrecy",
    "broken-ciphers": "Broken ciphers",
    "key-exchange-groups": "Key-exchange groups",
    "dh-parameters": "DH parameter size",
    "cbc-encrypt-then-mac": "CBC with Encrypt-then-MAC",
    "extended-master-secret": "Extended master secret",
    "certificate-key": "Certificate key",
    "certificate-signature": "Certificate signature",
    "certificate-validity": "Certificate validity",
    "certificate-trust": "Certificate trust",
    "certificate-lifetime": "Certificate lifetime",
    "post-quantum": "Post-quantum key exchange",
}

OPERATORS = frozenset(
    {
        "present",
        "subset_of",
        "none_of",
        "empty",
        "not_empty",
        "contains",
        "is",
        "one_of",
        "min",
        "max",
        "key_strength",
    }
)
SEVERITIES = ("high", "medium", "low", "info")


class StandardError(ValueError):
    """A standard file is malformed."""


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    control: str
    title: str
    severity: str
    reference: str
    check: Mapping[str, Any]
    when: Mapping[str, Any] | None = None
    on_violation: str = "fail"
    remediation: str = ""


@dataclass(frozen=True, slots=True)
class Standard:
    id: str
    title: str
    short_name: str
    publisher: str
    edition: str
    url: str
    description: str
    transcription: str  # "verified" or "draft"
    rules: tuple[Rule, ...]
    sha256: str

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "short_name": self.short_name,
            "publisher": self.publisher,
            "edition": self.edition,
            "url": self.url,
            "transcription": self.transcription,
            "sha256": self.sha256,
            "rules": len(self.rules),
        }


def _require(data: Mapping[str, Any], key: str, where: str, kind: type = str) -> Any:
    if key not in data:
        raise StandardError(f"{where}: missing '{key}'")
    value = data[key]
    if not isinstance(value, kind):
        raise StandardError(f"{where}: '{key}' must be {kind.__name__}")
    return value


def _check_spec(spec: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(spec, Mapping):
        raise StandardError(f"{where}: must be a mapping")
    _require(spec, "subject", where)
    op = _require(spec, "op", where)
    if op not in OPERATORS:
        raise StandardError(f"{where}: unknown operator '{op}'")
    if op in ("subset_of", "none_of", "one_of"):
        _require(spec, "values", where, list)
    if op in ("contains", "is", "min", "max") and "value" not in spec:
        raise StandardError(f"{where}: operator '{op}' needs 'value'")
    if op == "key_strength":
        _require(spec, "min_bits", where, dict)
    return spec


def parse(text: str) -> Standard:
    """Parse and validate one standard file."""
    data = yaml.safe_load(text)
    if not isinstance(data, Mapping):
        raise StandardError("standard file must contain a mapping")
    sid = _require(data, "id", "standard")
    rules_data = _require(data, "rules", sid, list)

    rules: list[Rule] = []
    seen: set[str] = set()
    for i, r in enumerate(rules_data):
        where = f"{sid} rule #{i + 1}"
        if not isinstance(r, Mapping):
            raise StandardError(f"{where}: must be a mapping")
        rid = _require(r, "id", where)
        where = f"{sid} {rid}"
        if rid in seen:
            raise StandardError(f"{where}: duplicate rule id")
        seen.add(rid)
        control = _require(r, "control", where)
        if control not in CONTROLS:
            raise StandardError(f"{where}: unknown control '{control}'")
        severity = _require(r, "severity", where)
        if severity not in SEVERITIES:
            raise StandardError(f"{where}: severity must be one of {SEVERITIES}")
        on_violation = r.get("on_violation", "fail")
        if on_violation not in ("fail", "warn"):
            raise StandardError(f"{where}: on_violation must be 'fail' or 'warn'")
        rules.append(
            Rule(
                id=rid,
                control=control,
                title=_require(r, "title", where),
                severity=severity,
                reference=_require(r, "reference", where),
                check=_check_spec(r.get("check"), f"{where} check"),
                when=_check_spec(r["when"], f"{where} when") if "when" in r else None,
                on_violation=on_violation,
                remediation=str(r.get("remediation", "")).strip(),
            )
        )

    transcription = _require(data, "transcription", sid)
    if transcription not in ("verified", "draft"):
        raise StandardError(f"{sid}: transcription must be 'verified' or 'draft'")
    return Standard(
        id=sid,
        title=_require(data, "title", sid),
        short_name=_require(data, "short_name", sid),
        publisher=_require(data, "publisher", sid),
        edition=str(_require(data, "edition", sid, (str, int))),  # type: ignore[arg-type]
        url=_require(data, "url", sid),
        description=str(_require(data, "description", sid)).strip(),
        transcription=transcription,
        rules=tuple(rules),
        sha256=hashlib.sha256(text.encode()).hexdigest(),
    )


def load_builtin() -> dict[str, Standard]:
    """Load every standard shipped with the package, keyed by id."""
    standards: dict[str, Standard] = {}
    for entry in sorted(resources.files(__name__).iterdir(), key=lambda e: e.name):
        if entry.name.endswith(".yaml"):
            std = parse(entry.read_text(encoding="utf-8"))
            if std.id in standards:
                raise StandardError(f"duplicate standard id {std.id}")
            standards[std.id] = std
    return standards
