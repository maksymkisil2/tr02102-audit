"""Run a scan and produce an Observation: facts only, no judgment (principle P2)."""

import time
from datetime import UTC, datetime
from typing import Any

from tr02102_audit import __version__
from tr02102_audit.netguard import ResolvedTarget
from tr02102_audit.tls import prober
from tr02102_audit.tls.registry import HYBRID_PQ_GROUPS, Version, suite_info
from tr02102_audit.x509 import analyse

OBSERVATION_FORMAT = 1


def _derive(tls: prober.TlsFacts) -> dict[str, Any]:
    """Turn raw probe results into the fact tree that policies refer to."""
    accepted = [v for v in Version if tls.versions.get(v) == "accepted"]
    inconclusive = [v for v in Version if tls.versions.get(v) == "inconclusive"]

    legacy_all: list[str] = []
    for key in ("tls12", "tls11", "tls10", "ssl3"):
        for name in tls.suites.get(key, []):
            if name not in legacy_all:
                legacy_all.append(name)
    infos = [suite_info(n) for n in legacy_all]

    groups13 = tls.groups_tls13
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
        "suites_without_forward_secrecy": [i.name for i in infos if not i.forward_secrecy],
        "suites_cbc": [i.name for i in infos if i.cbc],
        "suites_broken": [i.name for i in infos if i.broken],
        "cbc_without_encrypt_then_mac": [
            name
            for name, detail in tls.suite_details.items()
            if suite_info(name).cbc and not detail.encrypt_then_mac
        ],
        "extended_master_secret": (
            all(d.extended_master_secret for d in tls.suite_details.values())
            if tls.suite_details
            else None
        ),
        "groups": {"tls12": tls.groups_tls12, "tls13": groups13},
        "hybrid_pq_groups": (
            [g for g in groups13 if g in HYBRID_PQ_GROUPS] if groups13 is not None else None
        ),
        "dhe_prime_bits": tls.dhe_prime_bits,
    }


def scan_tls(target: ResolvedTarget, limits: prober.Limits | None = None) -> dict[str, Any]:
    """Probe ``target`` and return a JSON-serialisable observation."""
    limits = limits or prober.Limits()
    session = prober.Session(target, limits)
    started = time.monotonic()
    aborted: str | None = None

    try:
        tls = prober.collect(session)
    except prober.ScanAbortedError as exc:
        aborted = str(exc)
        tls = prober.TlsFacts()

    facts: dict[str, Any] = {"tls": _derive(tls), "certificate": None}

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
                trusted, error = prober.check_trust(session)
                cert["trusted"] = trusted
                cert["trust_error"] = error or None
                cert["chain_length"] = len(tls.certificate_chain) or None
                facts["certificate"] = cert

    notes = list(session.notes)
    if aborted:
        notes.insert(0, f"scan aborted: {aborted}")
    if not facts["tls"]["protocol_versions"] and not aborted:
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
        "complete": aborted is None,
        "facts": facts,
        "notes": notes,
    }
