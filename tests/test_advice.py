"""The action plan: what to change first, and the configuration that does it."""

import json
import subprocess
from importlib import resources
from typing import Any

import pytest

from tr02102_audit import advice, report
from tr02102_audit.standards import defaults, load_builtin

STANDARDS = defaults(load_builtin())


def lab(name: str) -> dict[str, Any]:
    text = resources.files("tr02102_audit.web").joinpath("demo", f"{name}.json").read_text()
    return report.build(json.loads(text), STANDARDS)


def by_control(actions: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {a["control"]: a for a in actions}


def test_weak_server_starts_with_what_breaks_security() -> None:
    actions = advice.plan(lab("tls-weak"))
    assert actions[0]["priority"] == "critical"
    assert actions[0]["rating_cap"] == "F"
    priorities = [a["priority"] for a in actions]
    assert priorities == sorted(priorities, key=advice.PRIORITIES.index), "ordered by priority"
    protocols = by_control(actions)["protocol-versions"]
    assert protocols["priority"] in ("critical", "high")
    assert "TLS1.0" in protocols["evidence"]
    assert protocols["snippets"]["nginx"] == ["ssl_protocols TLSv1.2 TLSv1.3;"]
    assert protocols["snippets"]["apache"] == ["SSLProtocol -all +TLSv1.2 +TLSv1.3"]


def test_shared_fix_is_shown_once() -> None:
    actions = advice.plan(lab("tls-weak"))
    cipher_actions = [
        a for a in actions if a["snippets"].get("nginx", [""])[0].startswith("ssl_ciphers")
    ]
    assert len(cipher_actions) >= 2
    first = actions.index(cipher_actions[0]) + 1
    assert cipher_actions[0]["same_as"] is None
    assert all(a["same_as"] == first for a in cipher_actions[1:])


def test_typical_website_has_nothing_critical_and_list_objections_are_low() -> None:
    actions = by_control(advice.plan(lab("tls-typical")))
    assert not [a for a in actions.values() if a["priority"] in ("critical", "high")]
    # BSI's 3000-bit minimum is a real requirement of one standard: medium.
    key = actions["certificate-key"]
    assert key["priority"] == "medium" and not key["off_list_only"]
    assert key["snippets"]["shell"][1].startswith("certbot certonly --key-type ecdsa")
    # ChaCha20 in TLS 1.3 is sound; only BSI's and NIST's lists object.
    tls13 = actions["tls13-cipher-suites"]
    assert tls13["priority"] == "low" and tls13["off_list_only"]
    assert tls13["profile"] == "strict"
    assert tls13["snippets"]["nginx"] == [
        "ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256;"
    ]
    assert {x["standard"] for x in tls13["affected"]} >= {"BSI TR-02102-2"}


def test_hardened_server_only_lacks_post_quantum() -> None:
    actions = advice.plan(lab("tls-good"))
    assert [a["control"] for a in actions] == ["post-quantum"]
    assert actions[0]["priority"] == "low" and not actions[0]["off_list_only"]
    assert "X25519MLKEM768" in actions[0]["snippets"]["nginx"][0]


def test_summary_counts() -> None:
    rep = lab("tls-typical")
    actions = advice.plan(rep)
    numbers = advice.summary(rep, actions)
    assert numbers["grade"] == "A"
    assert numbers["standards"] == len(rep["evaluations"])
    assert sum(numbers["actions"].values()) == len(actions)
    assert numbers["first"], "a summary always names a first step"


def test_every_control_and_rating_criterion_has_advice() -> None:
    from tr02102_audit import rating
    from tr02102_audit.standards import CONTROLS

    assert set(CONTROLS) <= set(advice.ACTION_TEXT)
    criteria = {c.id for c in (*rating.load().caps, *rating.load().bonus)}
    assert criteria == set(advice.RATING_CONTROL)
    for control in advice.ACTION_TEXT:
        for profile in advice.PROFILE_TEXT:
            assert advice.snippets(control, profile), control


@pytest.mark.parametrize("profile", ["compatible", "strict"])
def test_cipher_lists_are_understood_by_openssl(profile: str) -> None:
    """Every cipher name in the recommended configuration exists in OpenSSL."""
    line = advice.configuration(profile)["nginx"][1]
    ciphers = line.removeprefix("ssl_ciphers ").removesuffix(";")
    listed = (
        subprocess.run(
            ["openssl", "ciphers", "-tls1_2", ciphers], capture_output=True, text=True, check=True
        )
        .stdout.strip()
        .split(":")
    )
    # OpenSSL 3 lists its TLS 1.3 suites too; they are configured separately.
    assert [c for c in listed if not c.startswith("TLS_")] == ciphers.split(":")
