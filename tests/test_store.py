"""Storage: the same behaviour on SQLite and, when configured, PostgreSQL."""

import importlib
import time
from pathlib import Path

import pytest

from tr02102_audit.web.store import Database, Store, StoreError


def test_settings_are_replaced_not_duplicated(store: Store) -> None:
    assert store.setting("registration_open") is None
    assert store.setting("registration_open", "0") == "0"
    store.set_setting("registration_open", "1")
    store.set_setting("registration_open", "0")
    assert store.setting("registration_open") == "0"
    assert store.setting("schema_version") == "1"


def test_users_have_unique_logins_and_whitelisted_columns(store: Store) -> None:
    first = store.create_user("anna@example.org", "hash-1")
    second = store.create_user("boris@example.org", "hash-2", role="admin")
    assert first != second
    with pytest.raises(StoreError):
        store.create_user("anna@example.org", "hash-3")
    user = store.user(first)
    assert user is not None
    assert (user["role"], user["blocked"], user["monthly_limit"]) == ("user", 0, None)
    store.update_user(first, monthly_limit=7, blocked=1, locale="de")
    user = store.user_by_login("anna@example.org")
    assert user is not None
    assert (user["monthly_limit"], user["blocked"], user["locale"]) == (7, 1, "de")
    with pytest.raises(ValueError, match="cannot update"):
        store.update_user(first, login="x")
    with pytest.raises(ValueError, match="cannot update"):
        store.update_user(first, **{"role = 'admin' --": 1})
    assert store.count_users() == 2 and store.count_users(role="admin") == 1
    assert [u["login"] for u in store.users(limit=1)] in (
        ["anna@example.org"],
        ["boris@example.org"],
    )


def test_request_text_is_data_never_sql(store: Store) -> None:
    hostile = "x' OR '1'='1"
    store.create_user(hostile + "@example.org", "hash")
    assert store.user_by_login(hostile) is None
    store.add_event("login.failed", login=hostile, ip="203.0.113.7", detail="100% wrong")
    store.add_event("login.ok", login="anna", ip="198.51.100.1")
    assert store.count_events(text="' OR '1'='1") == 1, "matched as text, not run as SQL"
    assert store.count_events(text="'; DROP TABLE events; --") == 0
    assert store.count_events() == 2
    assert [e["login"] for e in store.events(kind="login.failed")] == [hostile]
    assert store.events(kind="login.failed' OR 1=1 --") == []


def test_events_are_filtered_counted_and_purged(store: Store) -> None:
    now = int(time.time())
    for kind, login, ip in (
        ("login.ok", "Anna", "203.0.113.7"),
        ("login.failed", "anna", "203.0.113.7"),
        ("scan.started", "boris", "198.51.100.1"),
    ):
        store.add_event(kind, login=login, ip=ip, country="DE", user_agent="UA", detail="d")
    assert [e["kind"] for e in store.events()] == ["scan.started", "login.failed", "login.ok"]
    assert store.count_events(kind="login") == 2
    assert store.count_events(text="ANNA") == 2, "the search ignores case"
    assert store.count_events(text="203.0.113") == 2
    assert store.count_events(kind="login", since=now + 60) == 0
    assert len(store.events(limit=2)) == 2 and len(store.events(limit=2, offset=2)) == 1
    recent = store.events_since(now - 60, ("scan.started", "login.failed"))
    assert sorted(e["kind"] for e in recent) == ["login.failed", "scan.started"]

    store.db.execute("UPDATE events SET ts = ? WHERE kind = ?", (now - 100, "login.ok"))
    assert store.purge_events(now - 50) == 1
    assert store.count_events() == 2


def test_long_values_are_cut_before_they_are_stored(store: Store) -> None:
    store.add_event("login.failed", login="l" * 500, user_agent="u" * 5000, detail="d" * 5000)
    event = store.events()[0]
    assert (len(event["login"]), len(event["user_agent"]), len(event["detail"])) == (120, 300, 500)


def test_scan_lifecycle(store: Store) -> None:
    owner = store.create_user("anna@example.org", "hash")
    store.create_scan("id-1", owner, "example.org", 443, "93.184.216.34", ["ietf-rfc9325"])
    row = store.scan("id-1")
    assert row is not None
    assert (row["status"], row["standards"], row["observation"]) == (
        "queued",
        ["ietf-rfc9325"],
        None,
    )
    store.set_scan_status("id-1", "running")
    store.finish_scan(
        "id-1", observation={"facts": {"tls": {}}}, grade="A", verdicts={"ietf-rfc9325": "pass"}
    )
    row = store.scan("id-1")
    assert row is not None
    assert (row["status"], row["grade"], row["verdicts"]) == ("done", "A", {"ietf-rfc9325": "pass"})
    assert row["observation"] == {"facts": {"tls": {}}} and row["finished_at"]

    store.create_scan("id-2", owner, "example.net", 8443, "93.184.216.35", [])
    store.finish_scan("id-2", error="scan failed: TimeoutError")
    failed = store.scan("id-2")
    assert failed is not None and failed["status"] == "error" and failed["grade"] is None

    listed = store.scans(user_id=owner)
    assert {s["public_id"] for s in listed} == {"id-1", "id-2"}
    assert all("observation" not in s and s["login"] == "anna@example.org" for s in listed)
    assert store.count_scans(user_id=owner) == 2 and store.count_scans(user_id=owner + 1) == 0
    assert store.scan("missing") is None

    store.delete_scan("id-2")
    store.delete_user(owner)
    assert store.count_scans() == 0 and store.user(owner) is None


def test_unfinished_scans_fail_on_restart_and_old_ones_are_purged(store: Store) -> None:
    now = int(time.time())
    store.create_scan("queued", 1, "a.example", 443, "1.1.1.1", [])
    store.create_scan("running", 1, "b.example", 443, "1.1.1.1", [])
    store.create_scan("done", 1, "c.example", 443, "1.1.1.1", [])
    store.set_scan_status("running", "running")
    store.finish_scan("done", observation={}, grade="B")
    assert store.fail_unfinished_scans() == 2
    for public_id in ("queued", "running"):
        row = store.scan(public_id)
        assert row is not None and row["status"] == "error" and "restart" in row["error"]
    row = store.scan("done")
    assert row is not None and row["status"] == "done"

    store.db.execute("UPDATE scans SET created_at = ? WHERE public_id = ?", (now - 100, "done"))
    assert store.purge_scans(now - 50) == 1
    assert store.count_scans(since=now - 50) == 2


def test_sqlite_file_keeps_data_between_connections(tmp_path: Path) -> None:
    first = Database("", tmp_path)
    Store(first).set_setting("kept", "yes")
    first.close()
    second = Database("", tmp_path)
    assert Store(second).setting("kept") == "yes"
    assert second.location.endswith("tr02102-audit.db")
    second.close()


def test_postgresql_without_a_driver_fails_with_a_clear_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_driver(name: str) -> object:
        raise ImportError(name)

    monkeypatch.setattr(importlib, "import_module", no_driver)
    with pytest.raises(StoreError, match="psycopg"):
        Database("postgresql://user:secret@db.example/app", tmp_path)
