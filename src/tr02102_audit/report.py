"""Combine an observation with evaluations into a report, and render it as text."""

import hashlib
import json
from collections.abc import Sequence
from datetime import date
from typing import Any

from tr02102_audit import __version__, rating
from tr02102_audit.engine import Evaluation, evaluate_all
from tr02102_audit.standards import CONTROLS, Standard
from tr02102_audit.tls.registry import GROUPS, suite_info

REPORT_FORMAT = 2

# Controls that are judged against an approved list. A failure here can mean
# "weak", or merely "secure, but not on this standard's list".
_LIST_CONTROLS = frozenset({"tls12-cipher-suites", "tls13-cipher-suites", "key-exchange-groups"})
_SOUND_GROUPS = frozenset(GROUPS.values()) - {"secp224r1"}


def observation_digest(observation: dict[str, Any]) -> str:
    """SHA-256 over the canonical JSON of the observation (threat T-05)."""
    canonical = json.dumps(observation, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def comparison(evaluations: Sequence[Evaluation]) -> list[dict[str, Any]]:
    """One row per control, one cell per standard. ``None`` means not covered."""
    rows = []
    for control, label in CONTROLS.items():
        cells = [e.control_status(control) for e in evaluations]
        if any(c is not None for c in cells):
            rows.append({"control": control, "label": label, "cells": cells})
    return rows


def _only_off_list(finding: dict[str, Any]) -> bool:
    """True when a rule objects only to values that are sound, but not on its list.

    ChaCha20 or x25519 fail the approved lists of BSI and NIST although no
    standard calls them weak. Telling the two cases apart is what makes a
    "does not conform" verdict readable.
    """
    if finding["control"] not in _LIST_CONTROLS or not finding["evidence"]:
        return False
    for item in finding["evidence"]:
        name = str(item).split(" ", 1)[0]
        if name in _SOUND_GROUPS:
            continue
        if not name.startswith("TLS_"):
            return False
        info = suite_info(name)
        if info.weak or not info.forward_secrecy or not info.aead:
            return False
    return True


def _evaluation(evaluation: Evaluation, complete: bool) -> dict[str, Any]:
    data = evaluation.to_dict()
    blocking = []
    for finding in data["findings"]:
        finding["off_list_only"] = finding["status"] in ("fail", "warn") and _only_off_list(finding)
        if finding["status"] == "fail" and finding["severity"] in ("high", "medium"):
            blocking.append(finding)
    # A scan that left something unmeasured can prove a failure, never a pass.
    if not complete and data["verdict"] in ("pass", "pass_with_warnings"):
        data["verdict"] = "incomplete"
    # "Fails only because of the approved list": no weakness was found.
    data["off_list_only"] = bool(blocking) and all(f["off_list_only"] for f in blocking)
    return data


def build(
    observation: dict[str, Any], standards: Sequence[Standard], today: date | None = None
) -> dict[str, Any]:
    evaluations = evaluate_all(standards, observation["facts"], today)
    complete = bool(observation.get("complete", True))
    return {
        "format": REPORT_FORMAT,
        "tool_version": __version__,
        "evaluated_on": (today or date.today()).isoformat(),
        "observation_sha256": observation_digest(observation),
        "observation": observation,
        "rating": rating.rate(observation, today),
        "evaluations": [_evaluation(e, complete) for e in evaluations],
        "comparison": {
            "standards": [e.standard.short_name for e in evaluations],
            "rows": comparison(evaluations),
        },
    }


def worst_failure_severity(report: dict[str, Any]) -> str | None:
    order = ["info", "low", "medium", "high"]
    worst: str | None = None
    for ev in report["evaluations"]:
        for f in ev["findings"]:
            if f["status"] == "fail" and (
                worst is None or order.index(f["severity"]) > order.index(worst)
            ):
                worst = f["severity"]
    return worst


# ---------------------------------------------------------------------------
# Plain-text rendering for the terminal
# ---------------------------------------------------------------------------

_SYMBOL = {
    "pass": "PASS",
    "fail": "FAIL",
    "warn": "WARN",
    "inconclusive": "????",
    "not_applicable": " n/a",
    None: "   -",
}


def _clean(text: object) -> str:
    """Neutralise control characters from target-derived strings (threat T-13)."""
    return "".join(ch if ch.isprintable() else "?" for ch in str(text))


def render_text(report: dict[str, Any]) -> str:
    obs = report["observation"]
    t = obs["target"]
    tls = obs["facts"]["tls"]
    cert = obs["facts"]["certificate"]
    lines = [
        f"Target      {_clean(t['host'])}:{t['port']} ({t['ip']})",
        f"Scanned     {obs['collected_at']}  ·  {obs['connections']} connections"
        f"  ·  {obs['duration_s']} s",
        f"Versions    {', '.join(tls['protocol_versions']) or 'none'}",
    ]
    if cert:
        key = f"{cert['key_type']} {cert['key_bits']}" + (
            f" {cert['curve']}" if cert.get("curve") else ""
        )
        lines.append(
            f"Certificate {_clean(cert.get('subject_cn'))} · {key} · "
            f"{cert.get('signature_hash')} · expires {cert['not_after'][:10]}"
        )
    for note in obs["notes"]:
        lines.append(f"Note        {_clean(note)}")
    for reason in obs.get("incomplete", []):
        lines.append(f"Incomplete  {_clean(reason)}")

    rate = report["rating"]
    grade = rate["grade"] or f"not rated (at best {rate['at_best']})"
    lines += ["", f"Rating      {grade}   (the tool's own summary, not part of a standard)"]
    for reason in rate["reasons"]:
        lines.append(f"            {reason['grade']}: {reason['title']}")
    for item in rate["unknown"]:
        lines.append(f"            ?: could not be checked: {item['title']}")

    comp = report["comparison"]
    width = max(len(r["label"]) for r in comp["rows"]) if comp["rows"] else 10
    lines += [
        "",
        "Comparison".ljust(width + 2) + "  ".join(s[:14].ljust(14) for s in comp["standards"]),
    ]
    for row in comp["rows"]:
        cells = "  ".join(_SYMBOL[c].ljust(14) for c in row["cells"])
        lines.append(row["label"].ljust(width + 2) + cells)

    for ev in report["evaluations"]:
        std = ev["standard"]
        c = ev["counts"]
        lines += [
            "",
            f"== {std['title']} ({std['edition']})  verdict: {ev['verdict'].upper()}",
            f"   {c['pass']} pass · {c['fail']} fail · {c['warn']} warn · "
            f"{c['inconclusive']} inconclusive · {c['not_applicable']} n/a",
        ]
        if ev.get("off_list_only"):
            lines.append(
                "   Fails only because of the standard's approved list; "
                "no weak algorithm was found."
            )
        for f in ev["findings"]:
            if f["status"] in ("pass", "not_applicable"):
                continue
            lines.append(f"   {_SYMBOL[f['status']]} [{f['severity']}] {f['rule_id']} {f['title']}")
            lines.append(f"        {_clean(f['message'])}")
            if f.get("off_list_only"):
                lines.append("        (sound elsewhere, but not on this standard's approved list)")
            for item in f["evidence"][:8]:
                lines.append(f"        - {_clean(item)}")
            if len(f["evidence"]) > 8:
                lines.append(f"        ... and {len(f['evidence']) - 8} more")
            lines.append(f"        ref: {f['reference']}")
    return "\n".join(lines) + "\n"
