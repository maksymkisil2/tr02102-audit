"""Evaluation engine and standard files."""

from datetime import date
from typing import Any

import pytest

from tr02102_audit import engine, report
from tr02102_audit.standards import StandardError, load_builtin, parse

D2026 = date(2026, 11, 13)


def facts(**tls: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "protocol_versions": ["TLS1.2", "TLS1.3"],
        "suites": {
            "tls13": ["TLS_AES_128_GCM_SHA256"],
            "tls12": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
        },
        "suites_without_forward_secrecy": [],
        "suites_broken": [],
        "cbc_without_encrypt_then_mac": [],
        "extended_master_secret": True,
        "groups": {"tls12": ["secp256r1"], "tls13": ["secp256r1"]},
        "hybrid_pq_groups": [],
        "dhe_prime_bits": None,
    }
    base.update(tls)
    cert = {
        "key_type": "EC",
        "key_bits": 256,
        "curve": "secp256r1",
        "signature_hash": "sha256",
        "expired": False,
        "trusted": True,
        "trust_error": None,
        "lifetime_days": 90,
    }
    return {"tls": base, "certificate": cert}


def test_all_builtin_standards_load() -> None:
    standards = load_builtin()
    assert {"bsi-tr-02102-2", "mozilla-intermediate", "mozilla-modern"} <= set(standards)
    for s in standards.values():
        assert len(s.sha256) == 64 and s.rules


def test_until_year_turns_into_warning_then_failure() -> None:
    spec = {"subject": "x", "op": "subset_of", "values": [{"value": "a", "until": 2026}, "b"]}
    assert engine.check(spec, {"x": ["a", "b"]}, date(2025, 6, 1)).status == "pass"
    assert engine.check(spec, {"x": ["a", "b"]}, date(2026, 6, 1)).status == "warn"
    assert engine.check(spec, {"x": ["a"]}, date(2027, 1, 1)).status == "fail"


def test_unknown_value_is_inconclusive_never_pass() -> None:
    result = engine.check(
        {"subject": "tls.groups.tls13", "op": "subset_of", "values": ["x"]},
        {"tls": {"groups": {"tls13": None}}},
        D2026,
    )
    assert result.status == "inconclusive"


def test_good_configuration_conforms_to_bsi() -> None:
    bsi = load_builtin()["bsi-tr-02102-2"]
    ev = engine.evaluate(bsi, facts(), D2026)
    assert ev.count("fail") == 0, [f for f in ev.findings if f.status == "fail"]


def test_legacy_protocol_fails_every_standard() -> None:
    f = facts(protocol_versions=["TLS1.0", "TLS1.2"])
    for std in load_builtin().values():
        assert engine.evaluate(std, f, D2026).verdict == "fail"


def test_standards_disagree_where_they_really_differ() -> None:
    # TLS 1.2 is fine for BSI and Mozilla Intermediate, not for Mozilla Modern.
    rep = report.build(
        {"facts": facts(), "target": {}, "notes": [], "complete": True},
        list(load_builtin().values()),
        D2026,
    )
    row = next(r for r in rep["comparison"]["rows"] if r["control"] == "protocol-versions")
    assert sorted(row["cells"]) == ["fail", "pass", "pass"]


def test_x25519_is_a_warning_under_bsi_and_fine_under_mozilla() -> None:
    f = facts(groups={"tls12": ["x25519"], "tls13": ["x25519"]})
    std = load_builtin()
    bsi = {x.rule_id: x.status for x in engine.evaluate(std["bsi-tr-02102-2"], f, D2026).findings}
    moz = {
        x.rule_id: x.status for x in engine.evaluate(std["mozilla-intermediate"], f, D2026).findings
    }
    assert bsi["BSI-TLS-08"] == "warn" and moz["MOZ-I-06"] == "pass"


@pytest.mark.parametrize(
    "text",
    [
        "!!python/object/apply:os.system ['echo pwned']",  # code execution attempt (T-12)
        "id: x\ntitle: t\nrules: []",  # missing fields
        "id: x\nrules:\n - {id: R, control: nope, title: t, severity: high, reference: r, check: {subject: a, op: empty}}",
        "id: x\nrules:\n - {id: R, control: protocol-versions, title: t, severity: high, reference: r, check: {subject: a, op: eval}}",
    ],
)
def test_malformed_or_hostile_standard_files_are_rejected(text: str) -> None:
    with pytest.raises((StandardError, Exception)):
        parse(text)


def test_reevaluation_is_deterministic() -> None:
    obs = {"facts": facts(), "target": {}, "notes": [], "complete": True}
    stds = list(load_builtin().values())
    a, b = report.build(obs, stds, D2026), report.build(obs, stds, D2026)
    assert (
        a["evaluations"] == b["evaluations"] and a["observation_sha256"] == b["observation_sha256"]
    )
