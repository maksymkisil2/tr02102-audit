"""End-to-end: scan real TLS servers (OpenSSL s_server) and check facts and verdicts.

The two servers mirror the lab targets in lab/. The test is skipped when the
openssl binary is not available.
"""

import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from tr02102_audit import report
from tr02102_audit.netguard import resolve
from tr02102_audit.scan import scan_tls
from tr02102_audit.standards import load_builtin

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


@pytest.fixture(scope="module")
def servers(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, int]]:
    assert OPENSSL
    d: Path = tmp_path_factory.mktemp("certs")
    keys = {
        "good": ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"],
        "weak": ["-newkey", "rsa:2048"],
    }
    for name, key in keys.items():
        subprocess.run(
            [
                OPENSSL,
                "req",
                "-x509",
                "-noenc",
                "-days",
                "30",
                *key,
                "-keyout",
                str(d / f"{name}.key"),
                "-out",
                str(d / f"{name}.crt"),
                "-subj",
                f"/CN=tls-{name}.lab.test",
            ],
            check=True,
            capture_output=True,
        )
    ports = {"good": _free_port(), "weak": _free_port()}
    args = {
        "good": [
            "-no_ssl3",
            "-no_tls1",
            "-no_tls1_1",
            "-cipher",
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256",
            "-ciphersuites",
            "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256",
            "-groups",
            "secp384r1:prime256v1",
        ],
        "weak": ["-no_tls1_3", "-cipher", "ALL:@SECLEVEL=0"],
    }
    procs = [
        subprocess.Popen(
            [
                OPENSSL,
                "s_server",
                "-accept",
                str(ports[n]),
                "-cert",
                str(d / f"{n}.crt"),
                "-key",
                str(d / f"{n}.key"),
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
        yield ports
    finally:
        for proc in procs:
            proc.terminate()
            proc.wait(timeout=5)


def _scan(port: int) -> dict:  # type: ignore[type-arg]
    obs = scan_tls(resolve("127.0.0.1", port, allow_private=True))
    return report.build(obs, list(load_builtin().values()))


def test_good_server(servers: dict[str, int]) -> None:
    rep = _scan(servers["good"])
    tls = rep["observation"]["facts"]["tls"]
    assert tls["protocol_versions"] == ["TLS1.2", "TLS1.3"]
    assert set(tls["suites"]["tls13"]) == {"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"}
    assert set(tls["groups"]["tls13"]) == {"secp256r1", "secp384r1"}
    cert = rep["observation"]["facts"]["certificate"]
    assert (cert["key_type"], cert["curve"], cert["trusted"]) == ("EC", "secp256r1", False)
    verdicts = {e["standard"]["id"]: e for e in rep["evaluations"]}
    bsi_fails = [
        f["rule_id"] for f in verdicts["bsi-tr-02102-2"]["findings"] if f["status"] == "fail"
    ]
    assert bsi_fails == ["BSI-TLS-15"]  # only: self-signed certificate


def test_weak_server(servers: dict[str, int]) -> None:
    rep = _scan(servers["weak"])
    tls = rep["observation"]["facts"]["tls"]
    assert {"TLS1.0", "TLS1.1", "TLS1.2"} <= set(tls["protocol_versions"])
    assert "TLS1.3" not in tls["protocol_versions"]
    assert "TLS_RSA_WITH_AES_128_CBC_SHA" in tls["suites_without_forward_secrecy"]
    assert rep["observation"]["facts"]["certificate"]["key_bits"] == 2048
    assert all(e["verdict"] == "fail" for e in rep["evaluations"])


def test_closed_port_is_never_a_pass() -> None:
    obs = scan_tls(resolve("127.0.0.1", _free_port(), allow_private=True))
    rep = report.build(obs, list(load_builtin().values()))
    assert all(e["verdict"] != "pass" for e in rep["evaluations"])
