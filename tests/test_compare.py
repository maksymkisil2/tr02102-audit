"""What changed between two checks."""

import copy
import json
from importlib import resources
from typing import Any

from tr02102_audit import compare, report
from tr02102_audit.standards import defaults, load_builtin

STANDARDS = defaults(load_builtin())


def observation(name: str) -> dict[str, Any]:
    text = resources.files("tr02102_audit.web").joinpath("demo", f"{name}.json").read_text()
    data: dict[str, Any] = json.loads(text)
    return data


def test_same_check_has_no_changes() -> None:
    rep = report.build(observation("tls-typical"), STANDARDS)
    diff = compare.compare(rep, rep)
    assert diff["changed"] is False
    assert diff["rating"] == {"before": "A", "after": "A", "direction": "same"}
    assert diff["lists"] == diff["values"] == diff["fixed"] == diff["appeared"] == []


def test_hardening_a_server_shows_what_it_did() -> None:
    before = report.build(observation("tls-weak"), STANDARDS)
    after = report.build(observation("tls-typical"), STANDARDS)
    diff = compare.compare(before, after)
    assert diff["rating"]["direction"] == "better"
    versions = next(x for x in diff["lists"] if x["label"] == "Protocol versions")
    assert "TLS1.0" in versions["removed"] and "TLS1.3" in versions["added"]
    assert diff["fixed"], "removing TLS 1.0 fixes findings"
    assert all(f["before"] in ("fail", "warn") for f in diff["fixed"])
    assert compare.compare(after, before)["rating"]["direction"] == "worse"


def test_one_changed_setting_is_reported_alone() -> None:
    old = observation("tls-typical")
    new = copy.deepcopy(old)
    new["facts"]["tls"]["suites"]["tls12"] = [
        s for s in new["facts"]["tls"]["suites"]["tls12"] if "CHACHA20" not in s
    ]
    diff = compare.compare(report.build(old, STANDARDS), report.build(new, STANDARDS))
    assert [x["label"] for x in diff["lists"]] == ["TLS 1.2 cipher suites"]
    assert diff["lists"][0]["added"] == []
    assert all("CHACHA20" in s for s in diff["lists"][0]["removed"])
    assert diff["values"] == []
