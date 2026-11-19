"""Run a scan and produce an Observation: facts only, no judgment (principle P2)."""

import time
from datetime import UTC, datetime
from typing import Any

from tr02102_audit import __version__
from tr02102_audit.netguard import ResolvedTarget
from tr02102_audit.tls import prober
from tr02102_audit.tls.registry import HYBRID_PQ_GROUPS, Version, suite_info
from tr02102_audit.x509 import analyse

OBSERVATION_FORMAT = 2


def _all(values: list[bool]) -> bool | None:
    return all(values) if values else None


def _derive(tls: prober.TlsFacts) -> dict[str, Any]:
    """Turn raw probe results into the fact tree that policies refer to.

    ``None`` always means "not determined". The engine reports such a value as
    inconclusive, so an unknown can never be mistaken for a clean result.
    """
    accepted = [v for v in Version if tls.versions.get(v) == "accepted"]
    inconclusive = [v for v in Version if tls.versions.get(v) == "inconclusive"]

    legacy_all: list[str] = []
    legacy_known = True
    for key in ("tls12", "tls11", "tls10", "ssl3"):
        if key in tls.suites and tls.suites[key] is None:
            legacy_known = False
        for name in tls.suites.get(key) or []:
            if name not in legacy_all:
                legacy_all.append(name)
    infos = [suite_info(n) for n in legacy_all]

    def derived(names: list[str]) -> list[str] | None:
        # A list built from an incomplete enumeration proves what it contains,
        # but an empty one proves nothing.
        return names if names or legacy_known else None

    details = list(tls.suite_details.values())
    groups13 = tls.groups_tls13
    tls13 = Version.TLS13 in accepted
    forward_secrecy = tls13 or any(i.forward_secrecy for i in infos)
    return {
        "protocol_versions": [str(v) for v in accepted],
        "protocol_versions_inconclusive": [str(v) for v in inconclusive],
        "version_probes": {str(k): v for k, v in tls.versions.items()},
        "suites": {
            "tls13": tls.suites.get("tls13", []),
            "tls12": tls.suites.get("tls12", []),
            "tls11": tls.suites.get("tls11", []),
            "tls10": tls.suites.get("tls10", []),
            "ssl3": tls.suites.get("ssl3", []),
            "legacy_all": legacy_all,
        },
        "suites_without_forward_secrecy": derived([i.name for i in infos if not i.forward_secrecy]),
        "suites_cbc": derived([i.name for i in infos if i.cbc]),
        # NULL, anonymous, export, RC4, DES: forbidden by every standard.
        "suites_broken": derived([i.name for i in infos if i.broken]),
        # 3DES: 112-bit strength, 64-bit blocks. "MUST NOT" for some, "SHOULD NOT" for others.
        "suites_3des": derived([i.name for i in infos if i.triple_des]),
        "suites_weak": derived([i.name for i in infos if i.weak]),
        "forward_secrecy_supported": forward_secrecy if forward_secrecy or legacy_known else None,
        "cbc_without_encrypt_then_mac": derived(
            [
                name
                for name, detail in tls.suite_details.items()
                if suite_info(name).cbc and not detail.encrypt_then_mac
            ]
        ),
        "extended_master_secret": _all([d.extended_master_secret for d in details]),
        "secure_renegotiation": _all([d.secure_renegotiation for d in details]),
        "compression": tls.compression,
        "groups": {"tls12": tls.groups_tls12, "tls13": groups13},
        "hybrid_pq_groups": (
            [g for g in groups13 if g in HYBRID_PQ_GROUPS] if groups13 is not None else None
        ),
        "dhe_prime_bits": tls.dhe_prime_bits,
    }


def _unknown() -> dict[str, Any]:
    """The fact tree of a scan that measured nothing: every value undetermined.

    An aborted scan (connection refused, deadline reached) leaves ``TlsFacts``
    empty. Derived from that, empty lists would read as measurements ("no TLS
    1.3", "no forward secrecy") and turn into failures. ``None`` keeps them
    unknown, so the engine reports every rule as inconclusive.
    """
    tree = _derive(prober.TlsFacts())
    unknown: dict[str, Any] = dict.fromkeys(tree)
    unknown["protocol_versions_inconclusive"] = []
    unknown["version_probes"] = {}
    unknown["suites"] = dict.fromkeys(tree["suites"])
    unknown["groups"] = dict.fromkeys(tree["groups"])
    return unknown


def scan_tls(
    target: ResolvedTarget, limits: prober.Limits | None = None, *, ca_file: str | None = None
) -> dict[str, Any]:
    """Probe ``target`` and return a JSON-serialisable observation.

    ``ca_file`` names extra trusted CA certificates (PEM), for an internal PKI.
    """
    limits = limits or prober.Limits()
    session = prober.Session(target, limits)
    started = time.monotonic()
    aborted: str | None = None

    try:
        tls = prober.collect(session)
    except prober.ScanAbortedError as exc:
        aborted = str(exc)
        tls = prober.TlsFacts()

    facts: dict[str, Any] = {"tls": _unknown() if aborted else _derive(tls), "certificate": None}

    if not aborted and tls.versions:
        leaf = tls.certificate_chain[0] if tls.certificate_chain else None
        if leaf is None and tls.versions.get(Version.TLS13) == "accepted":
            leaf = prober.fetch_leaf_certificate(session)
        if leaf is not None:
            try:
                cert = analyse(leaf)
            except ValueError as exc:
                session.notes.append(f"certificate could not be parsed: {exc}")
                cert = None
            if cert is not None:
                trusted, error = prober.check_trust(session, ca_file)
                cert["trusted"] = trusted
                cert["trust_error"] = error or None
                cert["chain_length"] = len(tls.certificate_chain) or None
                facts["certificate"] = cert

    notes = list(session.notes)
    incomplete = list(dict.fromkeys(session.incomplete))
    if aborted:
        notes.insert(0, f"scan aborted: {aborted}")
    if not aborted and not facts["tls"]["protocol_versions"]:
        notes.append("no TLS version was accepted; is this a TLS service?")

    return {
        "format": OBSERVATION_FORMAT,
        "tool_version": __version__,
        "collector": "tls",
        "collected_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "duration_s": round(time.monotonic() - started, 2),
        "connections": session.connections,
        "target": {
            "host": target.host,
            "port": target.port,
            "ip": target.ip,
            "sni": target.sni,
        },
        # False whenever something could not be measured. Such a scan can show
        # failures, but it can never be reported as conforming.
        "complete": aborted is None and not incomplete,
        "incomplete": incomplete,
        "facts": facts,
        "notes": notes,
    }
