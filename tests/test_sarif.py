"""SARIF output: structure, level mapping and schema conformance.

The schema check runs when the environment variable ``SARIF_SCHEMA`` points at a
copy of the official SARIF 2.1.0 schema. CI downloads it and sets the variable,
so the format is validated against the specification on every push.
"""

import json
import os
from pathlib import Path
from typing import Any

import pytest

from tests.test_engine import D2026, facts
from tr02102_audit import report, sarif
from tr02102_audit.standards import load_builtin


def _report(**observation: Any) -> dict[str, Any]:
    obs: dict[str, Any] = {
        "facts": facts(protocol_versions=["TLS1.0", "TLS1.2"]),
        "target": {"host": "example.org", "port": 443, "ip": "192.0.2.1", "sni": "example.org"},
        "collected_at": "2026-11-13T13:02:14+00:00",
        "notes": [],
        "complete": True,
    }
    obs.update(observation)
    return report.build(obs, list(load_builtin().values()), D2026)


@pytest.fixture(scope="module")
def log() -> dict[str, Any]:
    return sarif.build(_report())


def test_envelope(log: dict[str, Any]) -> None:
    assert log["version"] == "2.1.0"
    assert len(log["runs"]) == 1
    driver = log["runs"][0]["tool"]["driver"]
    assert driver["name"] == "tr02102-audit"
    assert driver["informationUri"].startswith("https://")


def test_every_result_points_at_an_existing_rule(log: dict[str, Any]) -> None:
    run = log["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids)), "rule ids must be unique across standards"
    assert run["results"], "the sample configuration must produce findings"
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_level_mapping_and_no_results_for_passing_checks(log: dict[str, Any]) -> None:
    rep = _report()
    expected = {
        status: sum(1 for ev in rep["evaluations"] for f in ev["findings"] if f["status"] == status)
        for status in ("fail", "warn", "inconclusive")
    }
    levels = [r["level"] for r in log["runs"][0]["results"]]
    assert levels.count("error") == expected["fail"]
    assert levels.count("warning") == expected["warn"]
    assert levels.count("note") == expected["inconclusive"]
    assert len(levels) == sum(expected.values())
    assert {r["properties"]["status"] for r in log["runs"][0]["results"]} <= set(expected)


def test_rules_carry_severity_and_help(log: dict[str, Any]) -> None:
    for rule in log["runs"][0]["tool"]["driver"]["rules"]:
        severity = float(rule["properties"]["security-severity"])
        assert 0.0 <= severity <= 10.0
        assert rule["help"]["text"] and rule["helpUri"].startswith("https://")
        assert "security" in rule["properties"]["tags"]


def test_same_finding_keeps_its_fingerprint_but_differs_per_standard(log: dict[str, Any]) -> None:
    again = sarif.build(_report())
    assert [r["partialFingerprints"] for r in log["runs"][0]["results"]] == [
        r["partialFingerprints"] for r in again["runs"][0]["results"]
    ]
    fingerprints = {
        r["partialFingerprints"]["tr02102AuditFindingV1"] for r in log["runs"][0]["results"]
    }
    assert len(fingerprints) == len(log["runs"][0]["results"])


def test_location_is_the_endpoint(log: dict[str, Any]) -> None:
    location = log["runs"][0]["results"][0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == "tls://example.org:443"
    assert location["logicalLocations"][0]["fullyQualifiedName"] == "example.org:443"


def test_incomplete_scan_is_marked_unsuccessful() -> None:
    log = sarif.build(_report(complete=False, notes=["timeout"]))
    invocation = log["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert invocation["startTimeUtc"] == "2026-11-13T13:02:14.000Z"
    texts = [n["message"]["text"] for n in invocation["toolExecutionNotifications"]]
    assert "timeout" in texts
    assert any("never as passes" in t for t in texts)


@pytest.mark.skipif(not os.environ.get("SARIF_SCHEMA"), reason="SARIF_SCHEMA not set")
def test_matches_the_official_schema(log: dict[str, Any]) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(Path(os.environ["SARIF_SCHEMA"]).read_text(encoding="utf-8"))
    jsonschema.validate(instance=log, schema=schema)
