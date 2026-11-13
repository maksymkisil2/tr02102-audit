"""Combine an observation with evaluations into a report, and render it as text."""

import hashlib
import json
from collections.abc import Sequence
from datetime import date
from typing import Any

from tr02102_audit import __version__
from tr02102_audit.engine import Evaluation, evaluate_all
from tr02102_audit.standards import CONTROLS, Standard

REPORT_FORMAT = 1


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


def build(
    observation: dict[str, Any], standards: Sequence[Standard], today: date | None = None
) -> dict[str, Any]:
    evaluations = evaluate_all(standards, observation["facts"], today)
    return {
        "format": REPORT_FORMAT,
        "tool_version": __version__,
        "evaluated_on": (today or date.today()).isoformat(),
        "observation_sha256": observation_digest(observation),
        "observation": observation,
        "evaluations": [e.to_dict() for e in evaluations],
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
        for f in ev["findings"]:
            if f["status"] in ("pass", "not_applicable"):
                continue
            lines.append(f"   {_SYMBOL[f['status']]} [{f['severity']}] {f['rule_id']} {f['title']}")
            lines.append(f"        {_clean(f['message'])}")
            for item in f["evidence"][:8]:
                lines.append(f"        - {_clean(item)}")
            if len(f["evidence"]) > 8:
                lines.append(f"        ... and {len(f['evidence']) - 8} more")
            lines.append(f"        ref: {f['reference']}")
    return "\n".join(lines) + "\n"
