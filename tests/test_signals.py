"""Patterns in the audit log that an administrator should look at."""

from typing import Any

from tr02102_audit.web import signals

NOW = 1_800_000_000


def event(kind: str, *, ago: int = 60, **fields: object) -> dict[str, Any]:
    return {"ts": NOW - ago, "kind": kind, "login": "", "ip": "", "detail": "", **fields}


def rules(found: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {s["rule"]: s for s in found}


def test_quiet_log_has_no_signals() -> None:
    events = [
        event("login.ok", login="anna", ip="198.51.100.1"),
        event("scan.started", login="anna"),
    ]
    assert signals.evaluate(events, NOW) == []


def test_password_guessing_and_spraying() -> None:
    events = [event("login.failed", ip="203.0.113.9", login=f"name{n}") for n in range(5)] + [
        event("login.failed", ip="198.51.100.1", login="anna") for _ in range(3)
    ]
    found = rules(signals.evaluate(events, NOW))
    assert found["password-guessing"]["who"] == "203.0.113.9"
    assert found["password-guessing"]["count"] == 5
    assert found["password-spraying"]["count"] == 5
    assert "198.51.100.1" not in {s["who"] for s in signals.evaluate(events, NOW)}


def test_old_events_do_not_count() -> None:
    events = [event("login.failed", ip="203.0.113.9", ago=2 * signals.DAY) for _ in range(9)]
    assert signals.evaluate(events, NOW) == []


def test_probing_private_addresses_and_many_hosts() -> None:
    events = [event("scan.rejected", login="eve", detail="10.0.0.1: private") for _ in range(3)]
    events += [
        event("scan.started", login="eve", detail=f"host{n}.example:443 (192.0.2.{n}); ietf")
        for n in range(10)
    ]
    found = rules(signals.evaluate(events, NOW))
    assert found["internal-probing"]["who"] == "eve"
    assert found["many-targets"]["count"] == 10
    assert signals.evaluate(events, NOW)[0]["severity"] == "high", "high first"


def test_flagged_events() -> None:
    assert signals.flagged({"kind": "login.failed"})
    assert signals.flagged({"kind": "scan.rejected"})
    assert not signals.flagged({"kind": "login.ok"})
    assert not signals.flagged({"kind": "scan.started"})
