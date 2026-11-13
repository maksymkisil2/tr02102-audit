"""Web interface: access control, CSRF, SSRF guard, security headers."""

import re
import time
from typing import Any

import pytest
from flask import Flask
from flask.testing import FlaskClient

from tr02102_audit.netguard import ResolvedTarget
from tr02102_audit.web import create_app

PASSWORD = "correct horse battery staple"


def fake_scan(target: ResolvedTarget) -> dict[str, Any]:
    return {
        "format": 1,
        "tool_version": "test",
        "collector": "tls",
        "collected_at": "2026-11-13T00:00:00+00:00",
        "duration_s": 0.1,
        "connections": 1,
        "complete": True,
        "notes": [],
        "target": {"host": target.host, "port": target.port, "ip": target.ip, "sni": target.sni},
        "facts": {
            "tls": {
                "protocol_versions": ["TLS1.0"],
                "version_probes": {"TLS1.0": "accepted"},
                "suites": {},
                "groups": {"tls12": None, "tls13": None},
            },
            "certificate": None,
        },
    }


@pytest.fixture
def app(monkeypatch: pytest.MonkeyPatch) -> Flask:
    monkeypatch.setenv("APP_PASSWORD", PASSWORD)
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    return create_app({"TESTING": True, "SESSION_COOKIE_SECURE": False, "SCAN_FN": fake_scan})


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    return app.test_client()


def csrf(client: FlaskClient, path: str) -> str:
    html = client.get(path).get_data(as_text=True)
    match = re.search(r'name="csrf" value="([^"]+)"', html)
    assert match
    return match.group(1)


def login(client: FlaskClient, password: str = PASSWORD) -> Any:
    return client.post("/login", data={"csrf": csrf(client, "/login"), "password": password})


def test_public_pages_and_security_headers(client: FlaskClient) -> None:
    for path in ("/", "/standards", "/demo/tls-weak", "/demo/tls-good", "/healthz"):
        resp = client.get(path)
        assert resp.status_code == 200, path
    resp = client.get("/demo/tls-weak")
    assert "default-src 'none'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "Does not conform" in resp.get_data(as_text=True)


def test_scanning_requires_login(client: FlaskClient) -> None:
    assert client.get("/scan").status_code == 302
    assert client.post("/scan", data={"target": "example.org"}).status_code == 302


def test_wrong_password_is_refused_and_rate_limited(client: FlaskClient) -> None:
    assert "Wrong password" in login(client, "nope").get_data(as_text=True)
    for _ in range(10):
        login(client, "nope")
    assert "Too many attempts" in login(client).get_data(as_text=True)


def test_post_without_csrf_token_is_rejected(client: FlaskClient) -> None:
    assert client.post("/login", data={"password": PASSWORD}).status_code == 400


def test_open_redirect_after_login_is_blocked(client: FlaskClient) -> None:
    token = csrf(client, "/login")
    resp = client.post("/login?next=//evil.example", data={"csrf": token, "password": PASSWORD})
    assert resp.headers["Location"] == "/scan"


def test_private_targets_are_refused(client: FlaskClient) -> None:
    login(client)
    for target in ("127.0.0.1", "localhost", "169.254.169.254", "10.0.0.1:8443"):
        resp = client.post(
            "/scan",
            data={"csrf": csrf(client, "/scan"), "target": target, "standard": "bsi-tr-02102-2"},
        )
        assert resp.status_code == 200
        assert "only public addresses" in resp.get_data(as_text=True), target


def test_scan_runs_in_background_and_report_escapes_target_data(client: FlaskClient) -> None:
    login(client)
    resp = client.post(
        "/scan",
        data={"csrf": csrf(client, "/scan"), "target": "1.1.1.1", "standard": "bsi-tr-02102-2"},
    )
    assert resp.status_code == 302
    url = resp.headers["Location"]
    for _ in range(50):
        page = client.get(url).get_data(as_text=True)
        if "Scanning" not in page:
            break
        time.sleep(0.05)
    assert "Does not conform" in page
    assert client.get(url + ".json").status_code == 200


def test_demo_reports_are_downloadable_as_json_and_sarif(client: FlaskClient) -> None:
    assert client.get("/demo/tls-weak.json").get_json()["observation"]["facts"]["tls"]
    log = client.get("/demo/tls-weak.sarif").get_json()
    assert log["version"] == "2.1.0"
    assert log["runs"][0]["results"], "the weak demo server must produce findings"
    assert client.get("/demo/nope.sarif").status_code == 404


def test_demo_only_mode_without_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_PASSWORD", raising=False)
    client = create_app({"TESTING": True}).test_client()
    assert "Scanning is disabled" in client.get("/").get_data(as_text=True)
    assert client.get("/demo/tls-weak").status_code == 200
