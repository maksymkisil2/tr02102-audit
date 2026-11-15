"""Evaluation engine and standard files."""

from datetime import date
from typing import Any

import pytest

from tr02102_audit import engine, rating, report
from tr02102_audit.standards import StandardError, defaults, load_builtin, parse

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
        "suites_3des": [],
        "suites_weak": [],
        "forward_secrecy_supported": True,
        "cbc_without_encrypt_then_mac": [],
        "extended_master_secret": True,
        "secure_renegotiation": True,
        "compression": False,
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
    assert {
        "bsi-tr-02102-2",
        "nist-sp-800-52r2",
        "ietf-rfc9325",
        "ncsc-nl-tls-2025",
        "pci-dss-4.0.1",
        "mozilla-intermediate",
        "mozilla-modern",
    } <= set(standards)
    assert next(iter(standards)) == "bsi-tr-02102-2"  # German reference first
    for s in standards.values():
        assert len(s.sha256) == 64 and s.rules


def test_community_baselines_are_optional_not_default() -> None:
    # Mozilla's advice is a useful baseline, but nobody certifies against it.
    standards = load_builtin()
    chosen = {s.id for s in defaults(standards)}
    assert chosen == {
        "bsi-tr-02102-2",
        "nist-sp-800-52r2",
        "ietf-rfc9325",
        "ncsc-nl-tls-2025",
        "pci-dss-4.0.1",
    }
    assert {s.category for s in standards.values() if not s.default} == {"community"}


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
    by_std = dict(zip(rep["comparison"]["standards"], row["cells"], strict=True))
    assert by_std["Mozilla Modern"] == "fail"
    assert all(v == "pass" for k, v in by_std.items() if k != "Mozilla Modern")


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


def _status(std_id: str, rule_id: str, f: dict[str, Any]) -> str:
    std = load_builtin()[std_id]
    return next(x.status for x in engine.evaluate(std, f, D2026).findings if x.rule_id == rule_id)


def test_chacha20_is_not_fips_approved() -> None:
    f = facts(suites={"tls13": ["TLS_CHACHA20_POLY1305_SHA256"], "tls12": []})
    assert _status("nist-sp-800-52r2", "NIST-05", f) == "fail"
    assert _status("ncsc-nl-tls-2025", "NL-03", f) == "pass"
    assert _status("mozilla-intermediate", "MOZ-I-03", f) == "pass"


def test_rsa_2048_certificate_divides_the_standards() -> None:
    f = facts()
    f["certificate"].update(key_type="RSA", key_bits=2048, curve=None)
    assert _status("bsi-tr-02102-2", "BSI-TLS-12", f) == "fail"  # 3000 bit minimum
    assert _status("ncsc-nl-tls-2025", "NL-10", f) == "warn"  # to be phased out
    assert _status("nist-sp-800-52r2", "NIST-10", f) == "pass"
    assert _status("ietf-rfc9325", "IETF-09", f) == "pass"


def test_static_ecdh_is_judged_by_each_standards_own_wording() -> None:
    suite = "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"
    f = facts(suites={"tls13": [], "tls12": [suite]}, suites_without_forward_secrecy=[suite])
    assert _status("nist-sp-800-52r2", "NIST-04", f) == "pass"  # on the approved list
    assert _status("ncsc-nl-tls-2025", "NL-05", f) == "fail"  # "insufficient"
    assert _status("ietf-rfc9325", "IETF-04", f) == "warn"  # "SHOULD NOT", not "MUST NOT"


def test_should_is_a_warning_and_must_is_a_failure() -> None:
    # RFC 9325 forbids RC4 outright but only discourages RSA key transport,
    # 3DES and CBC without Encrypt-then-MAC. Mixing the two levels up makes
    # every real server "fail".
    rsa = "TLS_RSA_WITH_AES_128_GCM_SHA256"
    cbc = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
    des3 = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    f = facts(
        suites={"tls13": ["TLS_AES_128_GCM_SHA256"], "tls12": [rsa, cbc, des3]},
        suites_without_forward_secrecy=[rsa, des3],
        suites_3des=[des3],
        suites_weak=[des3],
        cbc_without_encrypt_then_mac=[cbc, des3],
    )
    ietf = engine.evaluate(load_builtin()["ietf-rfc9325"], f, D2026)
    by_rule = {x.rule_id: x for x in ietf.findings}
    assert [by_rule[r].status for r in ("IETF-04", "IETF-06", "IETF-13")] == ["warn"] * 3
    assert {by_rule[r].level for r in ("IETF-04", "IETF-06", "IETF-13")} == {"recommended"}
    assert ietf.verdict == "pass_with_warnings"

    rc4 = "TLS_RSA_WITH_RC4_128_SHA"
    f = facts(suites_broken=[rc4], suites_weak=[rc4])
    ietf = engine.evaluate(load_builtin()["ietf-rfc9325"], f, D2026)
    by_rule = {x.rule_id: x for x in ietf.findings}
    assert (by_rule["IETF-03"].status, by_rule["IETF-03"].level) == ("fail", "required")
    assert ietf.verdict == "fail"


def test_nist_tolerates_rsa_key_transport_during_transition() -> None:
    # Appendix D: "may be used" while moving away from it; anything that is
    # on no list at all "shall not be used".
    f = facts(suites={"tls13": [], "tls12": ["TLS_RSA_WITH_AES_256_GCM_SHA384"]})
    assert _status("nist-sp-800-52r2", "NIST-04", f) == "warn"
    f = facts(suites={"tls13": [], "tls12": ["TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"]})
    assert _status("nist-sp-800-52r2", "NIST-04", f) == "fail"


def test_pci_dss_bans_3des_and_early_tls_but_accepts_modern_ciphers() -> None:
    des3 = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    f = facts(suites_3des=[des3], suites_weak=[des3])
    assert _status("pci-dss-4.0.1", "PCI-03", f) == "fail"
    assert _status("pci-dss-4.0.1", "PCI-01", facts(protocol_versions=["TLS1.1", "TLS1.2"])) == (
        "fail"
    )
    # ChaCha20 and x25519 are strong cryptography in PCI's sense.
    chacha = facts(
        suites={"tls13": ["TLS_CHACHA20_POLY1305_SHA256"], "tls12": []},
        groups={"tls12": ["x25519"], "tls13": ["x25519"]},
    )
    ev = engine.evaluate(load_builtin()["pci-dss-4.0.1"], chacha, D2026)
    assert ev.verdict == "pass_with_warnings"  # only the post-quantum hint
    rsa2048 = facts()
    rsa2048["certificate"].update(key_type="RSA", key_bits=2048, curve=None)
    assert _status("pci-dss-4.0.1", "PCI-06", rsa2048) == "warn"  # 128 bits recommended


def test_missing_renegotiation_info_and_compression_are_reported() -> None:
    f = facts(secure_renegotiation=False, compression=True)
    assert _status("ietf-rfc9325", "IETF-15", f) == "fail"  # MUST implement
    assert _status("ietf-rfc9325", "IETF-16", f) == "warn"  # SHOULD disable
    assert _status("nist-sp-800-52r2", "NIST-17", f) == "fail"
    assert _status("nist-sp-800-52r2", "NIST-18", f) == "fail"  # shall be disabled


def test_phase_out_entries_warn() -> None:
    f = facts(suites={"tls13": [], "tls12": ["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"]})
    assert _status("ncsc-nl-tls-2025", "NL-04", f) == "warn"


def test_hybrid_post_quantum_is_rewarded_by_ncsc() -> None:
    f = facts(
        groups={"tls12": [], "tls13": ["X25519MLKEM768", "x25519"]},
        hybrid_pq_groups=["X25519MLKEM768"],
    )
    assert _status("ncsc-nl-tls-2025", "NL-12", f) == "pass"
    assert _status("ncsc-nl-tls-2025", "NL-07", f) == "pass"
    assert _status("nist-sp-800-52r2", "NIST-07", f) == "warn"  # not NIST-approved groups


# --------------------------------------------------------------------------
# Overall rating and the "why does it fail" explanation
# --------------------------------------------------------------------------


def _obs(f: dict[str, Any], *, complete: bool = True) -> dict[str, Any]:
    return {"facts": f, "target": {}, "notes": [], "complete": complete}


def _grade(f: dict[str, Any], *, complete: bool = True) -> str | None:
    grade: str | None = rating.rate(_obs(f, complete=complete), D2026)["grade"]
    return grade


def test_rating_scale_from_a_plus_to_f() -> None:
    assert _grade(facts()) == "A"
    pq = facts(
        groups={"tls12": ["secp256r1"], "tls13": ["X25519MLKEM768", "x25519"]},
        hybrid_pq_groups=["X25519MLKEM768"],
    )
    assert _grade(pq) == "A+"
    rsa = "TLS_RSA_WITH_AES_128_GCM_SHA256"
    assert _grade(facts(suites_without_forward_secrecy=[rsa])) == "B"
    assert _grade(facts(protocol_versions=["TLS1.2"])) == "B"  # no TLS 1.3
    assert _grade(facts(protocol_versions=["TLS1.0", "TLS1.2", "TLS1.3"])) == "C"
    des3 = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    assert _grade(facts(suites_3des=[des3], suites_weak=[des3])) == "C"
    rc4 = "TLS_RSA_WITH_RC4_128_SHA"
    assert _grade(facts(suites_broken=[rc4], suites_weak=[rc4])) == "F"
    expired = facts()
    expired["certificate"]["expired"] = True
    assert _grade(expired) == "F"


def test_rating_names_the_reasons_worst_first() -> None:
    rc4 = "TLS_RSA_WITH_RC4_128_SHA"
    f = facts(protocol_versions=["TLS1.0", "TLS1.2"], suites_broken=[rc4], suites_weak=[rc4])
    result = rating.rate(_obs(f), D2026)
    assert [r["grade"] for r in result["reasons"]] == ["F", "C", "B"]
    assert result["reasons"][0]["evidence"] == [rc4]


def test_an_unknown_is_never_rounded_up_to_a_grade() -> None:
    unknown_trust = facts()
    unknown_trust["certificate"]["trusted"] = None
    result = rating.rate(_obs(unknown_trust), D2026)
    assert result["grade"] is None and result["at_best"] == "A"
    assert [u["id"] for u in result["unknown"]] == ["RATE-F4"]

    assert _grade(facts(), complete=False) is None  # incomplete scan: no grade
    # ... but a definite F stays an F: more data cannot repair it.
    rc4 = "TLS_RSA_WITH_RC4_128_SHA"
    assert _grade(facts(suites_broken=[rc4], suites_weak=[rc4]), complete=False) == "F"


def test_incomplete_scan_can_prove_a_failure_but_never_a_pass() -> None:
    stds = defaults(load_builtin())
    rep = report.build(_obs(facts(), complete=False), stds, D2026)
    assert {e["verdict"] for e in rep["evaluations"]} == {"incomplete"}
    bad = facts(protocol_versions=["TLS1.0", "TLS1.2"])
    rep = report.build(_obs(bad, complete=False), stds, D2026)
    assert {e["verdict"] for e in rep["evaluations"]} == {"fail"}


def test_report_tells_strict_list_apart_from_weakness() -> None:
    # A typical modern server: ChaCha20 and x25519. BSI and NIST only accept
    # what is on their lists, although nobody calls these algorithms weak.
    chacha12 = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    f = facts(
        suites={
            "tls13": ["TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"],
            "tls12": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", chacha12],
        },
        groups={"tls12": ["x25519", "secp256r1"], "tls13": ["x25519", "secp256r1"]},
    )
    rep = report.build(_obs(f), defaults(load_builtin()), D2026)
    by_id = {e["standard"]["id"]: e for e in rep["evaluations"]}
    assert rep["rating"]["grade"] == "A"
    for std in ("bsi-tr-02102-2", "nist-sp-800-52r2"):
        assert by_id[std]["verdict"] == "fail" and by_id[std]["off_list_only"], std
    assert by_id["ietf-rfc9325"]["verdict"] == "pass_with_warnings"
    assert not by_id["ietf-rfc9325"]["off_list_only"]

    # RSA key transport is a real weakness, not a matter of lists.
    rsa = "TLS_RSA_WITH_AES_128_GCM_SHA256"
    f = facts(suites={"tls13": [], "tls12": [rsa]}, suites_without_forward_secrecy=[rsa])
    rep = report.build(_obs(f), defaults(load_builtin()), D2026)
    by_id = {e["standard"]["id"]: e for e in rep["evaluations"]}
    assert by_id["bsi-tr-02102-2"]["verdict"] == "fail"
    assert not by_id["bsi-tr-02102-2"]["off_list_only"]


def test_rating_file_is_validated_like_a_standard() -> None:
    with pytest.raises(StandardError):
        rating.parse("caps:\n - {id: X, grade: A, title: t, check: {subject: a, op: empty}}")
    with pytest.raises(StandardError):
        rating.parse("caps:\n - {id: X, grade: C, title: t, check: {subject: a, op: eval}}")
