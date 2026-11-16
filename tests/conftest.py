"""Shared fixtures for the web tests.

The tests run against an in-memory SQLite database. Set ``TEST_DATABASE_URL``
to a PostgreSQL URL to run the same tests against PostgreSQL (CI does).
"""

import copy
import importlib
import json
import os
import re
import time
from collections.abc import Callable, Iterator
from importlib import resources
from pathlib import Path
from typing import Any

import pytest
from flask import Flask
from flask.testing import FlaskClient
from werkzeug.test import TestResponse

from tr02102_audit.netguard import ResolvedTarget
from tr02102_audit.web import create_app
from tr02102_audit.web.common import Services
from tr02102_audit.web.store import Database, Store

ADMIN = "admin"
ADMIN_PASSWORD = "correct horse battery staple"
USER_PASSWORD = "a long enough passphrase"

# Settings of the developer's shell must not leak into the application under test.
_ENVIRONMENT = (
    "SECRET_KEY",
    "APP_PASSWORD",
    "ADMIN_LOGIN",
    "ADMIN_RESET",
    "DATABASE_URL",
    "DATA_DIR",
    "TRUST_PROXY",
    "CLIENT_IP_HEADER",
    "RENDER",
    "AUDIT_RETENTION_DAYS",
    "REPORT_RETENTION_DAYS",
    "CHECKS_PER_MONTH",
    "OPERATOR_NAME",
    "OPERATOR_ADDRESS",
    "OPERATOR_EMAIL",
    "SESSION_COOKIE_SECURE",
)

_TYPICAL: dict[str, Any] = json.loads(
    resources.files("tr02102_audit.web").joinpath("demo", "tls-typical.json").read_text("utf-8")
)


def fake_scan(target: ResolvedTarget) -> dict[str, Any]:
    """A recorded observation instead of a network scan."""
    observation = copy.deepcopy(_TYPICAL)
    observation["target"] = {
        "host": target.host,
        "port": target.port,
        "ip": target.ip,
        "sni": target.sni,
    }
    return observation


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def database_url() -> str:
    url = os.environ.get("TEST_DATABASE_URL", "")
    if not url:
        return "sqlite://"
    psycopg = importlib.import_module("psycopg")
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS settings, users, events, scans")
    return url


@pytest.fixture
def store(database_url: str, tmp_path: Path) -> Iterator[Store]:
    database = Database(database_url, tmp_path)
    yield Store(database)
    database.close()


AppFactory = Callable[..., Flask]


@pytest.fixture
def make_app(database_url: str) -> Iterator[AppFactory]:
    created: list[Flask] = []

    def factory(**overrides: Any) -> Flask:
        config: dict[str, Any] = {
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "APP_PASSWORD": ADMIN_PASSWORD,
            "DATABASE_URL": database_url,
            "SESSION_COOKIE_SECURE": False,
            "SCRYPT_N_LOG2": 10,  # fast; production uses 15
            "SCAN_FN": fake_scan,
        }
        config.update(overrides)
        app = create_app(config)
        created.append(app)
        return app

    yield factory
    for app in created:
        svc = services(app)
        svc.jobs.close()
        svc.store.db.close()


@pytest.fixture
def app(make_app: AppFactory) -> Flask:
    return make_app()


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    return app.test_client()


def services(app: Flask) -> Services:
    svc: Services = app.extensions["tr02102"]
    return svc


def text(resp: TestResponse) -> str:
    return resp.get_data(as_text=True)


def csrf(client: FlaskClient, path: str = "/login") -> str:
    match = re.search(r'name="csrf" value="([^"]+)"', text(client.get(path)))
    assert match, f"no form with a CSRF token on {path}"
    return match.group(1)


def post(client: FlaskClient, path: str, form_page: str | None = None, **data: Any) -> TestResponse:
    """Send a form the way a browser would: with the token of the page it came from."""
    return client.post(path, data={"csrf": csrf(client, form_page or path), **data})


def sign_in(
    client: FlaskClient, login: str = ADMIN, password: str = ADMIN_PASSWORD
) -> TestResponse:
    return post(client, "/login", login=login, password=password)


def add_user(app: Flask, login: str = "anna@example.org", password: str = USER_PASSWORD) -> int:
    """Create an account the way an administrator does, and return its id."""
    admin = app.test_client()
    sign_in(admin)
    resp = post(admin, "/admin/users", login=login, password=password)
    assert resp.status_code == 302, text(resp)
    user = services(app).store.user_by_login(login)
    assert user is not None
    return int(user["id"])


def start_scan(client: FlaskClient, target: str = "1.1.1.1", **extra: Any) -> TestResponse:
    data: dict[str, Any] = {
        "target": target,
        "standard": ["bsi-tr-02102-2", "ietf-rfc9325"],
        "authorised": "yes",
    }
    data.update(extra)
    return post(client, "/scan", **data)


def wait_for_report(client: FlaskClient, url: str) -> str:
    for _ in range(400):
        html = text(client.get(url))
        if 'http-equiv="refresh"' not in html:
            return html
        time.sleep(0.02)
    raise AssertionError("the scan did not finish")


def events(app: Flask, kind: str = "") -> list[dict[str, Any]]:
    return services(app).store.events(kind=kind, limit=500)


def wait_for_event(app: Flask, kind: str) -> dict[str, Any]:
    for _ in range(400):
        found = events(app, kind)
        if found:
            return found[0]
        time.sleep(0.02)
    raise AssertionError(f"no {kind} event was written")
