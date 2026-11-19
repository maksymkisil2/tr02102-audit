"""Overall rating from A+ to F: the tool's own summary of an observation.

The rating is not part of any standard (see ``rating.yaml`` for the reasons
it exists). It is computed by the same pure engine as the standards, from the
same facts, so it is reproducible and explains itself: every grade below A
comes with the list of facts that caused it.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from functools import cache
from importlib import resources
from typing import Any

import yaml

from tr02102_audit import engine
from tr02102_audit.standards import StandardError, _check_spec

GRADES: tuple[str, ...] = ("A+", "A", "B", "C", "F")  # best first


@dataclass(frozen=True, slots=True)
class Criterion:
    id: str
    title: str
    check: Mapping[str, Any]
    when: Mapping[str, Any] | None = None
    grade: str = "A+"


@dataclass(frozen=True, slots=True)
class Scale:
    caps: tuple[Criterion, ...]
    bonus: tuple[Criterion, ...]


def parse(text: str) -> Scale:
    data = yaml.safe_load(text)
    if not isinstance(data, Mapping):
        raise StandardError("rating file must contain a mapping")

    def criteria(key: str, *, graded: bool) -> tuple[Criterion, ...]:
        out = []
        for item in data.get(key, []):
            where = f"rating {item.get('id', '?')}"
            grade = str(item.get("grade", "A+"))
            if graded and grade not in GRADES[2:]:
                raise StandardError(f"{where}: grade must be one of {GRADES[2:]}")
            out.append(
                Criterion(
                    id=str(item["id"]),
                    title=str(item["title"]),
                    check=_check_spec(item.get("check"), f"{where} check"),
                    when=_check_spec(item["when"], f"{where} when") if "when" in item else None,
                    grade=grade,
                )
            )
        return tuple(out)

    return Scale(caps=criteria("caps", graded=True), bonus=criteria("bonus", graded=False))


@cache
def load() -> Scale:
    text = resources.files("tr02102_audit").joinpath("rating.yaml").read_text(encoding="utf-8")
    return parse(text)


def _status(criterion: Criterion, facts: Mapping[str, Any], today: date) -> engine.Result:
    if criterion.when is not None and engine.check(criterion.when, facts, today).status != "pass":
        return engine.Result("not_applicable", "")
    return engine.check(criterion.check, facts, today)


def rate(observation: Mapping[str, Any], today: date | None = None) -> dict[str, Any]:
    """Grade an observation.

    ``grade`` is None when the scan left something open that could lower the
    grade: an unknown is never rounded up. ``at_best`` then says how good the
    grade can still be, or is None when not a single criterion could be
    checked (an aborted scan). A definite F is reported even for an incomplete
    scan, because more data cannot repair it.
    """
    today = today or date.today()
    facts = observation["facts"]
    scale = load()
    reasons: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    checked = 0  # criteria that could be decided either way
    for cap in scale.caps:
        result = _status(cap, facts, today)
        entry = {"id": cap.id, "grade": cap.grade, "title": cap.title}
        if result.status in ("pass", "fail"):
            checked += 1
        if result.status == "fail":
            detail = cap.check.get("detail")
            found = engine.lookup(facts, detail) if isinstance(detail, str) else None
            note = found if isinstance(found, str) and found else ""
            reasons.append({**entry, "evidence": result.evidence, "detail": note})
        elif result.status == "inconclusive":
            unknown.append(entry)

    rank = {g: i for i, g in enumerate(GRADES)}
    at_best = max((r["grade"] for r in reasons), key=lambda g: rank[g], default="A")
    bonus_missing = [
        {"id": b.id, "title": b.title}
        for b in scale.bonus
        if _status(b, facts, today).status != "pass"
    ]
    if at_best == "A" and not bonus_missing:
        at_best = "A+"

    if not checked:
        # Nothing was measured: "at best A+" would be true but meaningless.
        return {
            "grade": None,
            "at_best": None,
            "reasons": [],
            "unknown": unknown,
            "bonus_missing": [],
        }

    open_questions = [u for u in unknown if rank[u["grade"]] > rank[at_best]]
    complete = bool(observation.get("complete", True))
    rated = at_best == "F" or (complete and not open_questions)
    return {
        "grade": at_best if rated else None,
        "at_best": at_best,
        # The reasons that decide the grade come first.
        "reasons": sorted(reasons, key=lambda r: -rank[r["grade"]]),
        "unknown": unknown,
        "bonus_missing": bonus_missing if at_best == "A" else [],
    }
