#!/usr/bin/env python3
"""Differential validation of the scanner against OpenSSL on real servers.

The scanner builds its own ClientHello messages, so its results must not be
trusted just because the code looks right. This script scans each target with
the scanner, then asks an independent implementation, ``openssl s_client``,
the same questions and compares the answers:

* Which protocol versions complete a handshake?
* Does every cipher suite the scanner reports as accepted really work, and do
  a sample of the ones it reports as refused really fail?
* Which TLS 1.3 cipher suites and key-exchange groups are accepted?
* Does the certificate verify against the system trust store?

Any disagreement is printed as a MISMATCH and makes the script exit with 1.
OpenSSL cannot negotiate everything (RC4 and 3DES are compiled out of modern
builds), so such values are reported as "not verifiable", never as a match.

Usage:  python validation/differential.py validation/targets.txt
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from tr02102_audit import report
from tr02102_audit.netguard import TargetError, parse_target, resolve
from tr02102_audit.scan import scan_tls
from tr02102_audit.standards import load_builtin

ENV = {**os.environ, "OPENSSL_CONF": "/dev/null"}
SECLEVEL0 = "@SECLEVEL=0"
VERSION_FLAGS = {"TLS1.0": "-tls1", "TLS1.1": "-tls1_1", "TLS1.2": "-tls1_2", "TLS1.3": "-tls1_3"}
TLS13_SUITES = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
]
# scanner name -> OpenSSL name
GROUPS13 = {
    "x25519": "X25519",
    "x448": "X448",
    "secp256r1": "P-256",
    "secp384r1": "P-384",
    "secp521r1": "P-521",
    "ffdhe2048": "ffdhe2048",
    "ffdhe3072": "ffdhe3072",
    "X25519MLKEM768": "X25519MLKEM768",
    "SecP256r1MLKEM768": "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024": "SecP384r1MLKEM1024",
}
GROUPS12 = {"x25519": "X25519", "secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}
# Suites worth probing even when the scanner says they are refused.
REFUSED_SAMPLE = [
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
]
# Output that means OpenSSL could not even attempt what was asked.
CANNOT_TRY = ("Error with command", "SSL_CONF_cmd", "cannot be set", "no cipher match")
TEMP_KEY = re.compile(r"(?:Server|Peer) Temp Key: (?:ECDH, )?([A-Za-z0-9-]+)")
TEMP_KEY_NAMES = {"prime256v1": "secp256r1", "X25519": "x25519", "X448": "x448"}

# Hosts that exist to exhibit one specific property.
EXPECTATIONS: dict[str, list[tuple[str, Any]]] = {
    "tls-v1-0.badssl.com": [("versions", ["TLS1.0"])],
    "rc4.badssl.com": [("has_rc4", True)],
    "expired.badssl.com": [("expired", True)],
}


def run(cmd: list[str], timeout: int = 25) -> tuple[int, str]:
    try:
        proc = subprocess.run(  # noqa: S603 - fixed binary, arguments built here
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=ENV,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    return proc.returncode, proc.stdout + proc.stderr


def openssl_names() -> dict[str, str]:
    """Map IANA cipher-suite names to the names this OpenSSL build knows."""
    _, out = run(["openssl", "ciphers", "-stdname", "-V", f"ALL:eNULL:{SECLEVEL0}"])
    names: dict[str, str] = {}
    for line in out.splitlines():
        parts = [p.strip() for p in line.split(" - ")]
        if len(parts) >= 3 and parts[1].startswith("TLS_"):
            names[parts[1]] = parts[2].split()[0]
    return names


def group_supported(name: str) -> bool:
    """True when this OpenSSL build accepts ``-groups name``."""
    _, out = run(["openssl", "s_client", "-groups", name, "-connect", "127.0.0.1:9"], 10)
    return not any(marker in out for marker in CANNOT_TRY)


class Target:
    def __init__(self, host: str, port: int, ip: str, sni: str | None) -> None:
        self.host, self.port, self.ip, self.sni = host, port, ip, sni

    def _client(self, *args: str) -> tuple[bool | None, str]:
        cmd = ["openssl", "s_client", "-connect", f"{self.ip}:{self.port}", *args]
        cmd += ["-servername", self.sni] if self.sni else ["-noservername"]
        code, out = run(cmd)
        if code == 124 or any(marker in out for marker in CANNOT_TRY):
            return None, out
        done = re.search(r"^(New|Reused), (TLSv|SSLv)", out, re.M) is not None
        return code == 0 and done and "Cipher is (NONE)" not in out, out

    def handshake(self, *args: str) -> bool | None:
        """True/False for a completed/failed handshake, None when OpenSSL cannot try."""
        return self._client(*args)[0]

    def negotiated_group(self, *args: str) -> str | None:
        """Name of the key-exchange group of a completed handshake, else None."""
        ok, out = self._client(*args)
        match = TEMP_KEY.search(out)
        if not ok or match is None:
            return None
        return TEMP_KEY_NAMES.get(match.group(1), match.group(1))


def summarise(rep: dict[str, Any]) -> str:
    parts = []
    for ev in rep["evaluations"]:
        failing = [f["rule_id"] for f in ev["findings"] if f["status"] == "fail"]
        warning = [f["rule_id"] for f in ev["findings"] if f["status"] == "warn"]
        unknown = [f["rule_id"] for f in ev["findings"] if f["status"] == "inconclusive"]
        text = f"  {ev['standard']['id']:22} {ev['verdict']:18}"
        if failing:
            text += f" FAIL: {', '.join(failing)}"
        if warning:
            text += f" | warn: {', '.join(warning)}"
        if unknown:
            text += f" | unknown: {', '.join(unknown)}"
        parts.append(text)
    return "\n".join(parts)


def failing_detail(rep: dict[str, Any]) -> str:
    lines = []
    for ev in rep["evaluations"]:
        for f in ev["findings"]:
            if f["status"] in ("fail", "warn"):
                evidence = "; ".join(f["evidence"][:6])
                more = f" (+{len(f['evidence']) - 6})" if len(f["evidence"]) > 6 else ""
                lines.append(
                    f"    {f['status']:4} {f['rule_id']:11} {f['message'][:70]} :: {evidence}{more}"
                )
    return "\n".join(lines)


def check_target(spec: str, names: dict[str, str], groups_ok: dict[str, bool]) -> int:
    """Scan and cross-check one target. Returns the number of mismatches."""
    try:
        host, port = parse_target(spec)
        # Private addresses are refused unless explicitly allowed, for example to
        # run this check against the lab servers on localhost.
        allow_private = os.environ.get("VALIDATION_ALLOW_PRIVATE") == "1"
        resolved = resolve(host, port, allow_private=allow_private)
    except TargetError as exc:
        print(f"=== {spec}: SKIPPED ({exc})")
        return 0

    obs = scan_tls(resolved)
    rep = report.build(obs, list(load_builtin().values()))
    tls = obs["facts"]["tls"]
    cert = obs["facts"]["certificate"]
    target = Target(resolved.host, resolved.port, resolved.ip, resolved.sni)
    mismatches = 0

    def compare(label: str, ours: Any, theirs: Any, unverifiable: Any = None) -> None:
        nonlocal mismatches
        extra = f" (not verifiable with OpenSSL: {unverifiable})" if unverifiable else ""
        if ours == theirs:
            print(f"  ok       {label}: {ours}{extra}")
        else:
            mismatches += 1
            print(f"  MISMATCH {label}: scanner={ours} openssl={theirs}{extra}")

    print(f"\n=== {resolved.host}:{resolved.port} ({resolved.ip})")
    print(
        f"  scan: {obs['connections']} connections, {obs['duration_s']} s, "
        f"complete={obs['complete']}"
    )
    print(f"  version probes: {tls['version_probes']}")
    for key in ("tls13", "tls12", "tls11", "tls10", "ssl3"):
        if tls["suites"][key]:
            print(f"  {key} suites ({len(tls['suites'][key])}): {', '.join(tls['suites'][key])}")
    print(f"  groups: tls13={tls['groups']['tls13']} tls12={tls['groups']['tls12']}")
    print(
        f"  ems={tls['extended_master_secret']} dhe_bits={tls['dhe_prime_bits']} "
        f"cbc_without_etm={len(tls['cbc_without_encrypt_then_mac'])} "
        f"no_pfs={len(tls['suites_without_forward_secrecy'])} broken={tls['suites_broken']}"
    )
    if cert:
        print(
            f"  cert: {cert['key_type']} {cert['key_bits']} {cert.get('curve') or ''} "
            f"sig={cert['signature_hash']} lifetime={cert['lifetime_days']}d "
            f"expired={cert['expired']} trusted={cert['trusted']} err={cert['trust_error']}"
        )
    else:
        print("  cert: none retrieved")
    for note in obs["notes"]:
        print(f"  note: {note}")
    print(summarise(rep))
    detail = failing_detail(rep)
    if detail:
        print(detail)

    # --- protocol versions -------------------------------------------------
    theirs_versions = {}
    for version, flag in VERSION_FLAGS.items():
        extra = [] if version == "TLS1.3" else ["-cipher", f"ALL:eNULL:{SECLEVEL0}"]
        theirs_versions[version] = target.handshake(flag, *extra)
    ours_versions = {v: tls["version_probes"].get(v) == "accepted" for v in VERSION_FLAGS}
    compare("protocol versions", ours_versions, theirs_versions)

    # --- TLS 1.3 cipher suites and groups -----------------------------------
    if ours_versions["TLS1.3"] or theirs_versions["TLS1.3"]:
        theirs13 = sorted(
            s for s in TLS13_SUITES if target.handshake("-tls1_3", "-ciphersuites", s)
        )
        compare("TLS 1.3 suites", sorted(tls["suites"]["tls13"]), theirs13)

        testable = [g for g in GROUPS13 if groups_ok[GROUPS13[g]]]
        theirs_groups = sorted(
            g for g in testable if target.handshake("-tls1_3", "-groups", GROUPS13[g])
        )
        ours_groups = tls["groups"]["tls13"]
        if ours_groups is None:
            mismatches += 1
            print(f"  MISMATCH TLS 1.3 groups: scanner=unknown openssl={theirs_groups}")
        else:
            compare(
                "TLS 1.3 groups",
                sorted(g for g in ours_groups if g in testable),
                theirs_groups,
                sorted(g for g in ours_groups if g not in testable),
            )

    # --- legacy cipher suites ------------------------------------------------
    for version, key in (("TLS1.2", "tls12"), ("TLS1.1", "tls11"), ("TLS1.0", "tls10")):
        accepted = tls["suites"][key]
        if not accepted:
            continue
        flag = VERSION_FLAGS[version]
        false_positives, unverifiable = [], []
        for suite in accepted:
            if suite not in names:
                unverifiable.append(suite)
                continue
            result = target.handshake(flag, "-cipher", f"{names[suite]}:{SECLEVEL0}")
            if result is None:
                unverifiable.append(suite)
            elif not result:
                false_positives.append(suite)
        false_negatives = []
        if version == "TLS1.2":
            for suite in REFUSED_SAMPLE:
                if suite in accepted or suite not in names:
                    continue
                if target.handshake(flag, "-cipher", f"{names[suite]}:{SECLEVEL0}"):
                    false_negatives.append(suite)
        compare(
            f"{version} suites (reported but not working / missed)",
            ([], []),
            (false_positives, false_negatives),
            unverifiable,
        )

    # --- TLS 1.2 ECDHE groups --------------------------------------------------
    if tls["groups"]["tls12"] is not None and ours_versions["TLS1.2"]:
        # With an ECDSA certificate the curve of the certificate has to be
        # offered as well (RFC 8422, 5.1), so it is appended and the group
        # that was actually negotiated is read back.
        cert_curve = GROUPS12.get((cert or {}).get("curve") or "")
        theirs12 = []
        for group, openssl_name in GROUPS12.items():
            offer = openssl_name
            if cert_curve and cert_curve != openssl_name:
                offer = f"{openssl_name}:{cert_curve}"
            used = target.negotiated_group(
                "-tls1_2", "-cipher", f"ECDHE:{SECLEVEL0}", "-groups", offer
            )
            if used == group:
                theirs12.append(group)
        theirs12.sort()
        compare(
            "TLS 1.2 ECDHE groups",
            sorted(g for g in tls["groups"]["tls12"] if g in GROUPS12),
            theirs12,
            sorted(g for g in tls["groups"]["tls12"] if g not in GROUPS12),
        )

    # --- certificate trust -----------------------------------------------------
    if cert and cert["trusted"] is not None:
        name = resolved.sni or resolved.host
        verified = target.handshake("-verify_return_error", "-verify_hostname", name)
        compare("certificate trusted", cert["trusted"], verified)

    # --- built-in expectations -------------------------------------------------
    for kind, expected in EXPECTATIONS.get(resolved.host, []):
        if kind == "versions":
            compare("expected versions", tls["protocol_versions"], expected)
        elif kind == "has_rc4":
            compare("expected RC4 suites", any("RC4" in s for s in tls["suites_broken"]), expected)
        elif kind == "expired":
            compare("expected expired certificate", bool(cert and cert["expired"]), expected)
    return mismatches


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    targets = [
        line.split("#", 1)[0].strip()
        for line in Path(argv[1]).read_text(encoding="utf-8").splitlines()
    ]
    targets = [t for t in targets if t]

    _, version = run(["openssl", "version"])
    names = openssl_names()
    groups_ok = {name: group_supported(name) for name in {*GROUPS13.values(), *GROUPS12.values()}}
    print(f"OpenSSL: {version.strip()} ({len(names)} cipher suites)")
    print(f"Groups OpenSSL can test: {sorted(g for g, ok in groups_ok.items() if ok)}")

    total = 0
    for spec in targets:
        try:
            total += check_target(spec, names, groups_ok)
        except Exception as exc:  # keep going; the error is reported at the end
            total += 1
            print(f"=== {spec}: ERROR {exc.__class__.__name__}: {exc}")
    print(f"\n{len(targets)} targets checked, {total} mismatch(es)")
    return 1 if total else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
