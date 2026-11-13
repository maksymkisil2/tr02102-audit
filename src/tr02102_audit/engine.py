"""Evaluation engine: observations + standard -> findings.

This module performs no I/O (principle P4). The same observation can be
re-evaluated against any standard, at any later time, with identical results
for an identical date.
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import date
from typing import Any, Literal

from tr02102_audit.standards import Rule, Standard

Status = Literal["pass", "fail", "warn", "inconclusive", "not_applicable"]

# Order used when several rules of one standard cover the same control.
STATUS_RANK: dict[str, int] = {
    "fail": 5,
    "warn": 4,
    "inconclusive": 3,
    "pass": 2,
    "not_applicable": 1,
}

_MISSING = object()


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    control: str
    title: str
    severity: str
    status: Status
    message: str
    evidence: list[str] = field(default_factory=list)
    reference: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Result:
    status: Status
    message: str
    evidence: list[str] = field(default_factory=list)


def lookup(facts: Mapping[str, Any], path: str) -> Any:
    """Follow a dotted path such as ``tls.suites.tls12`` through the fact tree."""
    node: Any = facts
    for part in path.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return _MISSING
        node = node[part]
    return node


def _allow_list(values: Iterable[Any]) -> dict[str, int | None]:
    """Normalise ``["a", {"value": "b", "until": 2029}]`` to ``{"a": None, "b": 2029}``."""
    out: dict[str, int | None] = {}
    for v in values:
        if isinstance(v, Mapping):
            out[str(v["value"])] = int(v["until"]) if v.get("until") is not None else None
        else:
            out[str(v)] = None
    return out


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list | tuple):
        return [str(v) for v in value]
    return [str(value)]


def check(spec: Mapping[str, Any], facts: Mapping[str, Any], today: date) -> Result:
    """Evaluate one check specification against the facts."""
    op = spec["op"]
    subject = lookup(facts, spec["subject"])
    if subject is _MISSING or (subject is None and op != "present"):
        return Result("inconclusive", "the scan did not determine this value")

    if op == "present":
        ok = subject is not None
        return Result("pass" if ok else "fail", "present" if ok else "not present")

    if op == "subset_of":
        allowed = _allow_list(spec["values"])
        items = _as_list(subject)
        offending = [i for i in items if i not in allowed]
        expired = [i for i in items if (u := allowed.get(i)) is not None and u < today.year]
        expiring = [i for i in items if allowed.get(i) == today.year]
        if offending or expired:
            bad = offending + [f"{i} (recommended only until {allowed[i]})" for i in expired]
            return Result("fail", "not covered by the recommendation", bad)
        if expiring:
            return Result(
                "warn",
                f"allowed only until the end of {today.year}",
                expiring,
            )
        return Result("pass", "all values are covered by the recommendation", items)

    if op == "none_of":
        banned = set(_allow_list(spec["values"]))
        offending = [i for i in _as_list(subject) if i in banned]
        if offending:
            return Result("fail", "values that must not be offered are accepted", offending)
        return Result("pass", "none of the excluded values is accepted")

    if op == "empty":
        items = _as_list(subject)
        if items:
            return Result("fail", f"{len(items)} offending value(s)", items)
        return Result("pass", "none found")

    if op == "not_empty":
        items = _as_list(subject)
        if items:
            return Result("pass", "present", items)
        return Result("fail", "none found")

    if op == "contains":
        items = _as_list(subject)
        wanted = str(spec["value"])
        if wanted in items:
            return Result("pass", f"{wanted} is accepted")
        return Result("fail", f"{wanted} is not accepted")

    if op == "is":
        expected = spec["value"]
        if subject == expected:
            return Result("pass", f"is {expected}")
        return Result("fail", f"expected {expected}, found {subject}")

    if op == "one_of":
        allowed_values = _allow_list(spec["values"])
        if str(subject) in allowed_values:
            return Result("pass", f"{subject}")
        return Result("fail", f"{subject} is not covered by the recommendation", [str(subject)])

    if op in ("min", "max"):
        limit = spec["value"]
        if not isinstance(subject, int | float):
            return Result("inconclusive", "value is not a number")
        ok = subject >= limit if op == "min" else subject <= limit
        word = "at least" if op == "min" else "at most"
        msg = f"{subject} (required: {word} {limit})"
        return Result("pass" if ok else "fail", msg, [] if ok else [str(subject)])

    if op == "key_strength":
        return _key_strength(spec, subject)

    raise ValueError(f"unknown operator {op!r}")


def _key_strength(spec: Mapping[str, Any], cert: Any) -> Result:
    if not isinstance(cert, Mapping):
        return Result("inconclusive", "no certificate was analysed")
    key_type = str(cert.get("key_type"))
    bits = cert.get("key_bits")
    allowed: Mapping[str, int] = spec["min_bits"]
    label = f"{key_type} {bits} bit" + (f" ({cert['curve']})" if cert.get("curve") else "")
    if key_type not in allowed:
        return Result("fail", f"key type {key_type} is not covered", [label])
    if not isinstance(bits, int) or bits < allowed[key_type]:
        return Result("fail", f"{label}; required: at least {allowed[key_type]} bit", [label])
    curves = spec.get("curves")
    if key_type == "EC" and curves and cert.get("curve") not in curves:
        return Result("fail", f"curve {cert.get('curve')} is not covered", [label])
    return Result("pass", label)


def evaluate_rule(rule: Rule, facts: Mapping[str, Any], today: date) -> Finding:
    if rule.when is not None:
        condition = check(rule.when, facts, today)
        if condition.status != "pass":
            return _finding(rule, Result("not_applicable", "does not apply to this server"))
    result = check(rule.check, facts, today)
    detail_path = rule.check.get("detail")
    if result.status == "fail" and isinstance(detail_path, str):
        detail = lookup(facts, detail_path)
        if detail not in (None, _MISSING, ""):
            result = Result(result.status, str(detail), result.evidence)
    if result.status == "fail" and rule.on_violation == "warn":
        result = Result("warn", result.message, result.evidence)
    return _finding(rule, result)


def _finding(rule: Rule, result: Result) -> Finding:
    return Finding(
        rule_id=rule.id,
        control=rule.control,
        title=rule.title,
        severity=rule.severity,
        status=result.status,
        message=result.message,
        evidence=result.evidence,
        reference=rule.reference,
        remediation=rule.remediation if result.status in ("fail", "warn") else "",
    )


@dataclass(frozen=True, slots=True)
class Evaluation:
    standard: Standard
    findings: list[Finding]

    def count(self, status: str) -> int:
        return sum(1 for f in self.findings if f.status == status)

    @property
    def verdict(self) -> str:
        serious = [
            f for f in self.findings if f.status == "fail" and f.severity in ("high", "medium")
        ]
        if serious:
            return "fail"
        if self.count("inconclusive"):
            return "incomplete"
        if self.count("fail") or self.count("warn"):
            return "pass_with_warnings"
        return "pass"

    def control_status(self, control: str) -> str | None:
        statuses = [f.status for f in self.findings if f.control == control]
        if not statuses:
            return None  # the standard says nothing about this control
        return max(statuses, key=lambda s: STATUS_RANK[s])

    def to_dict(self) -> dict[str, Any]:
        return {
            "standard": self.standard.summary(),
            "verdict": self.verdict,
            "counts": {s: self.count(s) for s in STATUS_RANK},
            "findings": [f.to_dict() for f in self.findings],
        }


def evaluate(standard: Standard, facts: Mapping[str, Any], today: date | None = None) -> Evaluation:
    today = today or date.today()
    return Evaluation(standard, [evaluate_rule(r, facts, today) for r in standard.rules])


def evaluate_all(
    standards: Sequence[Standard], facts: Mapping[str, Any], today: date | None = None
) -> list[Evaluation]:
    return [evaluate(s, facts, today) for s in standards]
