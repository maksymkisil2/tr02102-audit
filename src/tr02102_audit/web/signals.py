"""Patterns in the audit log that an administrator should look at.

Each rule counts events of a kind per address or per account in a time
window and reports whoever crosses a threshold. The rules are deliberately
simple, so an administrator can tell why something was flagged, and new ones
are a few lines: add an entry to ``RULES``.

A signal is a reason to look, not proof of an attack: a user who forgot a
password also fails to sign in five times.
"""

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

HOUR = 3600
DAY = 24 * HOUR


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str  # English message id
    explanation: str  # English message id
    kinds: tuple[str, ...]
    by: str  # "ip" or "login": what is counted
    window: int  # seconds
    threshold: int
    severity: str  # "high" or "medium"
    distinct: str = ""  # count distinct values of this field instead of events


RULES: tuple[Rule, ...] = (
    Rule(
        "password-guessing",
        "Many failed sign-ins from one address",
        "Someone may be guessing passwords. A blocked address waits 15 minutes.",
        ("login.failed", "login.blocked"),
        by="ip",
        window=DAY,
        threshold=5,
        severity="high",
    ),
    Rule(
        "password-spraying",
        "One address tries many login names",
        "Typical of password spraying: one common password against many accounts.",
        ("login.failed",),
        by="ip",
        window=DAY,
        threshold=4,
        severity="high",
        distinct="login",
    ),
    Rule(
        "account-targeted",
        "Many failed sign-ins for one account",
        "Someone may be trying to get into this account from several addresses.",
        ("login.failed", "login.blocked"),
        by="login",
        window=DAY,
        threshold=8,
        severity="high",
    ),
    Rule(
        "internal-probing",
        "Repeated attempts to check private addresses",
        "Checking private or loopback addresses is how someone would try to reach the network behind this service.",  # noqa: E501
        ("scan.rejected",),
        by="login",
        window=7 * DAY,
        threshold=3,
        severity="high",
    ),
    Rule(
        "scan-burst",
        "Unusually many checks from one account",
        "Many checks in a short time may mean the service is used to scan third parties.",
        ("scan.started",),
        by="login",
        window=DAY,
        threshold=20,
        severity="medium",
    ),
    Rule(
        "many-targets",
        "One account checks many different hosts",
        "Checking many unrelated servers can point to scanning without permission.",
        ("scan.started",),
        by="login",
        window=7 * DAY,
        threshold=10,
        severity="medium",
        distinct="host",
    ),
    Rule(
        "registration-burst",
        "Many registrations from one address",
        "Someone may be creating accounts to get around the limits.",
        ("register", "register.blocked"),
        by="ip",
        window=DAY,
        threshold=4,
        severity="medium",
    ),
)

KINDS: tuple[str, ...] = tuple(sorted({k for rule in RULES for k in rule.kinds}))
LONGEST = max(rule.window for rule in RULES)


def _value(event: Mapping[str, Any], field: str) -> str:
    if field == "host":
        # "example.org:443 (93.184.216.34); bsi-..." -> "example.org"
        return str(event.get("detail") or "").split(" ", 1)[0].rsplit(":", 1)[0]
    return str(event.get(field) or "")


def evaluate(events: Iterable[Mapping[str, Any]], now: int) -> list[dict[str, Any]]:
    """Signals for ``events`` (any order), most severe and most frequent first."""
    events = list(events)
    found: list[dict[str, Any]] = []
    for rule in RULES:
        counts: Counter[str] = Counter()
        seen: defaultdict[str, set[str]] = defaultdict(set)
        last: dict[str, int] = {}
        for event in events:
            if event["kind"] not in rule.kinds or int(event["ts"]) < now - rule.window:
                continue
            who = _value(event, rule.by)
            if not who:
                continue
            counts[who] += 1
            last[who] = max(last.get(who, 0), int(event["ts"]))
            if rule.distinct:
                seen[who].add(_value(event, rule.distinct))
        for who, count in counts.items():
            measure = len(seen[who]) if rule.distinct else count
            if measure >= rule.threshold:
                found.append(
                    {
                        "rule": rule.id,
                        "title": rule.title,
                        "explanation": rule.explanation,
                        "severity": rule.severity,
                        "by": rule.by,
                        "who": who,
                        "count": measure,
                        "events": count,
                        "last": last[who],
                        "window_hours": rule.window // HOUR,
                        "kind": rule.kinds[0].split(".")[0],
                    }
                )
    found.sort(key=lambda s: (s["severity"] != "high", -int(s["count"]), -int(s["last"])))
    return found


def flagged(event: Mapping[str, Any]) -> bool:
    """Whether an event by itself is worth a second look (shown in red in the log)."""
    kind = str(event.get("kind", ""))
    return kind.endswith(("failed", "blocked", "rejected", "denied", "quota"))
