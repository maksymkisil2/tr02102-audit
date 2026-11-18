"""What changed between two checks of the same server.

The point of checking a server again is to see the effect of a change: a
cipher suite removed, a new certificate, TLS 1.3 switched on. This module
compares two reports built by ``report.build`` and lists the differences in
the measured facts, the rating, the verdicts and the findings. It is a pure
function of the two reports, so the comparison can be repeated at any time.
"""

from collections.abc import Mapping, Sequence
from typing import Any

from tr02102_audit.rating import GRADES

# Measured lists whose members are compared one by one: (key, path in facts).
_LISTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Protocol versions", ("tls", "protocol_versions")),
    ("TLS 1.3 cipher suites", ("tls", "suites", "tls13")),
    ("TLS 1.2 cipher suites", ("tls", "suites", "tls12")),
    ("TLS 1.1 cipher suites", ("tls", "suites", "tls11")),
    ("TLS 1.0 cipher suites", ("tls", "suites", "tls10")),
    ("SSL 3.0 cipher suites", ("tls", "suites", "ssl3")),
    ("TLS 1.3 key-exchange groups", ("tls", "groups", "tls13")),
    ("TLS 1.2 key-exchange groups", ("tls", "groups", "tls12")),
)

# Single measured values: (label, path in facts).
_VALUES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Extended master secret", ("tls", "extended_master_secret")),
    ("Secure renegotiation", ("tls", "secure_renegotiation")),
    ("TLS compression", ("tls", "compression")),
    ("DH parameter size", ("tls", "dhe_prime_bits")),
    ("Certificate key", ("certificate", "key")),
    ("Certificate signature", ("certificate", "signature_hash")),
    ("Certificate issuer", ("certificate", "issuer_cn")),
    ("Certificate valid until", ("certificate", "not_after")),
    ("Certificate trusted", ("certificate", "trusted")),
)


def _get(facts: Mapping[str, Any], path: Sequence[str]) -> Any:
    value: Any = facts
    for key in path:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value


def _facts(report: Mapping[str, Any]) -> dict[str, Any]:
    facts = dict(report["observation"]["facts"])
    cert = facts.get("certificate")
    if isinstance(cert, Mapping) and cert:
        cert = dict(cert)
        key = f"{cert.get('key_type')} {cert.get('key_bits')}"
        if cert.get("curve"):
            key += f" {cert['curve']}"
        cert["key"] = key
        if isinstance(cert.get("not_after"), str):
            cert["not_after"] = cert["not_after"][:10]
        facts["certificate"] = cert
    return facts


def _findings(report: Mapping[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    out = {}
    for evaluation in report["evaluations"]:
        std = evaluation["standard"]
        for finding in evaluation["findings"]:
            out[(std["id"], finding["rule_id"])] = {
                "standard": std["short_name"],
                "rule_id": finding["rule_id"],
                "title": finding["title"],
                "status": finding["status"],
            }
    return out


def _grade_rank(grade: str | None) -> int | None:
    return GRADES.index(grade) if grade in GRADES else None


def compare(old: Mapping[str, Any], new: Mapping[str, Any]) -> dict[str, Any]:
    """Differences from ``old`` to ``new``."""
    old_facts, new_facts = _facts(old), _facts(new)

    lists = []
    for label, path in _LISTS:
        before = [str(x) for x in _get(old_facts, path) or []]
        after = [str(x) for x in _get(new_facts, path) or []]
        added = [x for x in after if x not in before]
        removed = [x for x in before if x not in after]
        if added or removed:
            lists.append({"label": label, "added": added, "removed": removed})

    values = []
    for label, path in _VALUES:
        before, after = _get(old_facts, path), _get(new_facts, path)
        if before != after:
            values.append({"label": label, "before": before, "after": after})

    verdicts = []
    old_verdicts = {e["standard"]["id"]: e for e in old["evaluations"]}
    for evaluation in new["evaluations"]:
        std_id = evaluation["standard"]["id"]
        if std_id in old_verdicts and old_verdicts[std_id]["verdict"] != evaluation["verdict"]:
            verdicts.append(
                {
                    "standard": evaluation["standard"]["short_name"],
                    "before": old_verdicts[std_id]["verdict"],
                    "after": evaluation["verdict"],
                }
            )

    old_findings, new_findings = _findings(old), _findings(new)
    fixed, appeared = [], []
    problem = ("fail", "warn")
    for key, now in new_findings.items():
        was = old_findings.get(key)
        if was is None:
            continue  # the standard was not evaluated before
        if was["status"] in problem and now["status"] not in problem:
            fixed.append({**now, "before": was["status"]})
        elif now["status"] in problem and was["status"] != now["status"]:
            appeared.append({**now, "before": was["status"]})

    old_grade = (old.get("rating") or {}).get("grade")
    new_grade = (new.get("rating") or {}).get("grade")
    a, b = _grade_rank(old_grade), _grade_rank(new_grade)
    if a is None or b is None or a == b:
        direction = "same" if old_grade == new_grade else "unknown"
    else:
        direction = "better" if b < a else "worse"

    return {
        "rating": {"before": old_grade, "after": new_grade, "direction": direction},
        "lists": lists,
        "values": values,
        "verdicts": verdicts,
        "fixed": fixed,
        "appeared": appeared,
        "changed": bool(lists or values or verdicts or fixed or appeared or old_grade != new_grade),
    }
