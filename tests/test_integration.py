"""End-to-end: scan real TLS servers (OpenSSL s_server) and check facts and verdicts.

The three servers mirror the lab targets in lab/. The tests that need them are
skipped when the openssl binary is not available.
"""

import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tr02102_audit import report
from tr02102_audit.netguard import resolve
from tr02102_audit.scan import scan_tls
from tr02102_audit.standards import defaults, load_builtin
from tr02102_audit.tls import prober, wire

OPENSSL = shutil.which("openssl")
pytestmark = pytest.mark.skipif(OPENSSL is None, reason="openssl binary not available")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait(port: int) -> None:
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("test server did not start")


GEN_CERTS = Path(__file__).resolve().parent.parent / "lab" / "scripts" / "gen-certs.sh"
CERT = {"rsa-only": "typical"}  # servers that reuse another server's certificate


@pytest.fixture(scope="module")
def lab(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, int | str]]:
    """Three servers that mirror lab/: hardened, typical and deliberately weak.

    Certificates come from the lab's own script, so the test also covers it:
    a throwaway CA signs all three, and the scanner is told to trust that CA.
    """
    assert OPENSSL
    d: Path = tmp_path_factory.mktemp("certs")
    subprocess.run(
        ["/bin/sh", str(GEN_CERTS)],
        check=True,
        capture_output=True,
        env={"OUT": str(d), "DAYS": "30", "PATH": "/usr/bin:/bin:/usr/local/bin"},
    )
    ports = {n: _free_port() for n in ("good", "typical", "weak", "rsa-only")}
    no_legacy = ["-no_ssl3", "-no_tls1", "-no_tls1_1"]
    args = {
        "good": [
            *no_legacy,
            "-cipher",
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256",
            "-ciphersuites",
            "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256",
            "-groups",
            "secp384r1:prime256v1",
        ],
        "typical": [
            *no_legacy,
            "-cipher",
            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305",
            "-groups",
            "X25519:prime256v1:secp384r1",
        ],
        "weak": ["-no_tls1_3", "-cipher", "ALL:@SECLEVEL=0"],
        "rsa-only": ["-no_tls1_3", *no_legacy, "-cipher", "AES128-GCM-SHA256"],
    }
    procs = [
        subprocess.Popen(
            [
                OPENSSL,
                "s_server",
                "-accept",
                str(ports[n]),
                "-cert",
                str(d / f"tls-{CERT.get(n, n)}.crt"),
                "-key",
                str(d / f"tls-{CERT.get(n, n)}.key"),
                "-quiet",
                *args[n],
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )
        for n in ports
    ]
    try:
        for p in ports.values():
            _wait(p)
        yield {**ports, "ca": str(d / "lab-ca.crt")}
    finally:
        for proc in procs:
            proc.terminate()
            proc.wait(timeout=5)


def _scan(port: int | str, ca: int | str | None = None) -> dict[str, Any]:
    target = resolve("127.0.0.1", int(port), allow_private=True)
    obs = scan_tls(target, ca_file=str(ca) if ca else None)
    return report.build(obs, defaults(load_builtin()))


def _verdicts(rep: dict[str, Any]) -> dict[str, str]:
    return {e["standard"]["id"]: e["verdict"] for e in rep["evaluations"]}


def test_hardened_server_conforms_to_every_formal_standard(lab: dict[str, int | str]) -> None:
    rep = _scan(lab["good"], lab["ca"])
    obs = rep["observation"]
    tls = obs["facts"]["tls"]
    assert obs["complete"], obs["incomplete"]
    assert tls["protocol_versions"] == ["TLS1.2", "TLS1.3"]
    assert set(tls["suites"]["tls13"]) == {"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"}
    assert set(tls["groups"]["tls13"]) == {"secp256r1", "secp384r1"}
    assert (tls["secure_renegotiation"], tls["compression"]) == (True, False)
    cert = obs["facts"]["certificate"]
    assert (cert["key_type"], cert["curve"], cert["trusted"]) == ("EC", "secp256r1", True)
    assert set(_verdicts(rep).values()) <= {"pass", "pass_with_warnings"}, _verdicts(rep)
    assert rep["rating"]["grade"] == "A"  # A+ needs post-quantum key exchange


def test_without_the_lab_ca_the_same_server_is_untrusted(lab: dict[str, int | str]) -> None:
    rep = _scan(lab["good"])
    assert rep["observation"]["facts"]["certificate"]["trusted"] is False
    assert set(_verdicts(rep).values()) == {"fail"}
    assert rep["rating"]["grade"] == "F"


def test_typical_modern_server_is_good_but_off_the_strict_lists(
    lab: dict[str, int | str],
) -> None:
    # The situation behind "why does every site fail?": ChaCha20, x25519 and
    # an RSA-2048 certificate. Good practice, yet not on BSI's or NIST's lists.
    rep = _scan(lab["typical"], lab["ca"])
    verdicts = _verdicts(rep)
    assert rep["rating"]["grade"] == "A"
    assert verdicts["ietf-rfc9325"] == "pass_with_warnings"
    assert verdicts["pci-dss-4.0.1"] == "pass_with_warnings"
    assert verdicts["nist-sp-800-52r2"] == "fail"
    nist = next(e for e in rep["evaluations"] if e["standard"]["id"] == "nist-sp-800-52r2")
    assert nist["off_list_only"]  # no weak algorithm, only the approved list
    assert verdicts["bsi-tr-02102-2"] == "fail"


def test_weak_server(lab: dict[str, int | str]) -> None:
    rep = _scan(lab["weak"], lab["ca"])
    tls = rep["observation"]["facts"]["tls"]
    assert {"TLS1.0", "TLS1.1", "TLS1.2"} <= set(tls["protocol_versions"])
    assert "TLS1.3" not in tls["protocol_versions"]
    assert "TLS_RSA_WITH_AES_128_CBC_SHA" in tls["suites_without_forward_secrecy"]
    assert rep["observation"]["facts"]["certificate"]["key_bits"] == 2048
    assert set(_verdicts(rep).values()) == {"fail"}
    assert rep["rating"]["grade"] == "F"
    assert not any(e["off_list_only"] for e in rep["evaluations"])


def test_server_without_forward_secrecy(lab: dict[str, int | str]) -> None:
    rep = _scan(lab["rsa-only"], lab["ca"])
    obs = rep["observation"]
    tls = obs["facts"]["tls"]
    assert obs["complete"], obs["incomplete"]
    assert tls["suites"]["tls12"] == ["TLS_RSA_WITH_AES_128_GCM_SHA256"]
    assert tls["forward_secrecy_supported"] is False
    assert tls["groups"]["tls12"] == []  # known to be empty, not "unknown"
    ietf = next(e for e in rep["evaluations"] if e["standard"]["id"] == "ietf-rfc9325")
    failed = {f["rule_id"] for f in ietf["findings"] if f["status"] == "fail"}
    assert failed == {"IETF-14"}  # MUST support forward secrecy
    assert not [f for f in ietf["findings"] if f["status"] == "inconclusive"]
    assert rep["rating"]["grade"] == "C"


def test_closed_port_is_never_a_pass() -> None:
    obs = scan_tls(resolve("127.0.0.1", _free_port(), allow_private=True))
    assert not obs["complete"] and obs["connections"] == 1  # gives up at once
    rep = report.build(obs, list(load_builtin().values()))
    assert all(e["verdict"] not in ("pass", "pass_with_warnings") for e in rep["evaluations"])
    assert rep["rating"]["grade"] is None


class _ScriptedSession:
    """Stands in for a Session: answers probes from a fixed script."""

    def __init__(self, script: list[str]) -> None:
        self.script = script
        self.incomplete: list[str] = []
        self.offers: list[list[int]] = []

    def probe(self, spec: wire.HelloSpec, *, until_done: bool = False) -> prober.Outcome:
        self.offers.append(list(spec.cipher_suites))
        kind = self.script.pop(0)
        if kind != "accepted":
            return prober.Outcome(kind, "scripted")  # type: ignore[arg-type]
        hello = wire.ServerHello(0x0303, 0x0303, spec.cipher_suites[0], False)
        return prober.Outcome("accepted", server_hello=hello)


def _enumerate(script: list[str]) -> tuple[list[int], _ScriptedSession]:
    session = _ScriptedSession(script)
    accepted = prober._enumerate(
        session,  # type: ignore[arg-type]
        [1, 2, 3],
        lambda suites: wire.HelloSpec(client_version=0x0303, cipher_suites=suites),
        lambda o: o.server_hello.cipher_suite if o.server_hello else None,
        label="suites",
    )
    return accepted, session


def test_refusal_is_confirmed_by_asking_again_for_an_accepted_value() -> None:
    accepted, session = _enumerate(["accepted", "accepted", "refused", "accepted"])
    assert accepted == [1, 2] and session.incomplete == []
    assert session.offers[-1] == [1]  # the canary


def test_a_server_that_stops_answering_makes_the_scan_incomplete() -> None:
    # A rate limiter that resets connections looks like "refused". Without the
    # canary the scan would report a short, flattering list of cipher suites.
    accepted, session = _enumerate(["accepted", "refused", "refused"])
    assert accepted == [1]
    assert "stopped answering" in session.incomplete[0]


def test_a_probe_without_an_answer_makes_the_scan_incomplete() -> None:
    accepted, session = _enumerate(["accepted", "inconclusive"])
    assert accepted == [1] and "no answer" in session.incomplete[0]
