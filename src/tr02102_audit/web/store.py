"""Persistent storage: accounts, audit log, scan history, settings.

Two backends behind one small interface:

* SQLite (default): a file under ``DATA_DIR``. Needs nothing, but on hosting
  with an ephemeral disk the data is lost on every restart.
* PostgreSQL: used when ``DATABASE_URL`` starts with ``postgres``. Needs the
  optional ``psycopg`` package.

The SQL below is the subset both understand. Every statement uses bound
parameters; nothing from a request is ever formatted into SQL (threat T-20).
Timestamps are Unix seconds, booleans are 0/1, structured values are JSON
text, so rows look the same in both backends.
"""

import contextlib
import importlib
import json
import sqlite3
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

_TABLES = (
    """
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS users (
        id {pk},
        login TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        monthly_limit BIGINT,
        locale TEXT,
        blocked BIGINT NOT NULL DEFAULT 0,
        created_at BIGINT NOT NULL,
        last_login_at BIGINT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS events (
        id {pk},
        ts BIGINT NOT NULL,
        kind TEXT NOT NULL,
        user_id BIGINT,
        login TEXT,
        ip TEXT,
        country TEXT,
        user_agent TEXT,
        detail TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS events_ts ON events (ts)",
    """
    CREATE TABLE IF NOT EXISTS scans (
        id {pk},
        public_id TEXT NOT NULL UNIQUE,
        user_id BIGINT NOT NULL,
        host TEXT NOT NULL,
        port BIGINT NOT NULL,
        ip TEXT,
        standards TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        finished_at BIGINT,
        grade TEXT,
        verdicts TEXT,
        observation TEXT,
        error TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS scans_user ON scans (user_id, created_at)",
)

# Columns an update may touch. Anything else is a programming error, and
# column names never come from a request.
_USER_COLUMNS = frozenset(
    {"password_hash", "role", "monthly_limit", "locale", "blocked", "last_login_at"}
)


class StoreError(RuntimeError):
    """The database cannot be reached or refused a statement."""


class Database:
    """One connection, serialised by a lock. Enough for a single small service."""

    def __init__(self, url: str | None, data_dir: Path) -> None:
        self._lock = threading.RLock()
        self._url = url or ""
        self.dialect = (
            "postgres" if self._url.startswith(("postgres://", "postgresql://")) else ("sqlite")
        )
        self.location = "PostgreSQL"
        self._path = ""
        if self.dialect == "sqlite":
            if self._url in ("sqlite://", ":memory:"):
                self._path = ":memory:"
                self.location = "memory"
            else:
                data_dir.mkdir(parents=True, exist_ok=True)
                self._path = str(data_dir / "tr02102-audit.db")
                self.location = self._path
        self._conn: Any = None
        self._errors: tuple[type[BaseException], ...] = (sqlite3.Error,)
        self._lost: tuple[type[BaseException], ...] = ()  # errors that mean "reconnect"
        self._connect()

    def _connect(self) -> None:
        if self.dialect == "sqlite":
            conn = sqlite3.connect(self._path, check_same_thread=False, isolation_level=None)
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA busy_timeout = 5000")
            if self._path != ":memory:":
                conn.execute("PRAGMA journal_mode = WAL")
            self._conn = conn
            return
        try:
            psycopg = importlib.import_module("psycopg")
        except ImportError as exc:
            raise StoreError(
                "DATABASE_URL points to PostgreSQL, but the 'psycopg' package is not installed"
            ) from exc
        self._errors = (psycopg.Error,)
        self._lost = (psycopg.OperationalError, psycopg.InterfaceError)
        try:
            self._conn = psycopg.connect(self._url, autocommit=True, connect_timeout=10)
        except psycopg.Error as exc:
            raise StoreError(f"cannot connect to PostgreSQL: {exc.__class__.__name__}") from exc

    def close(self) -> None:
        with self._lock, contextlib.suppress(*self._errors):
            self._conn.close()

    def _run(self, sql: str, params: Sequence[Any], *, fetch: bool) -> tuple[list[Any], int, Any]:
        if self.dialect == "postgres":
            sql = sql.replace("?", "%s")
        with self._lock:
            for attempt in (1, 2):
                try:
                    cursor = self._conn.cursor()
                    cursor.execute(sql, tuple(params))
                    rows = cursor.fetchall() if fetch else []
                    names = [c[0] for c in cursor.description] if cursor.description else []
                    count = int(cursor.rowcount)
                    cursor.close()
                    return [dict(zip(names, row, strict=True)) for row in rows], count, None
                except self._errors as exc:
                    # A hosted PostgreSQL closes idle connections. Reconnect once
                    # and repeat the statement; any other error is final.
                    if attempt == 2 or not isinstance(exc, self._lost):
                        raise StoreError(f"database error: {exc.__class__.__name__}") from exc
                    with contextlib.suppress(*self._errors):
                        self._conn.close()
                    self._connect()
        raise StoreError("database error")  # pragma: no cover - loop always returns or raises

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        return self._run(sql, params, fetch=True)[0]

    def one(self, sql: str, params: Sequence[Any] = ()) -> dict[str, Any] | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def execute(self, sql: str, params: Sequence[Any] = ()) -> int:
        """Run a statement and return the number of affected rows."""
        return self._run(sql, params, fetch=False)[1]

    def insert(self, sql: str, params: Sequence[Any] = ()) -> int:
        """Run an INSERT and return the new row's id."""
        rows = self.query(sql + " RETURNING id", params)
        return int(rows[0]["id"])

    def migrate(self) -> None:
        pk = (
            "BIGSERIAL PRIMARY KEY"
            if self.dialect == "postgres"
            else "INTEGER PRIMARY KEY AUTOINCREMENT"
        )
        for statement in _TABLES:
            self.execute(statement.format(pk=pk))


def _loads(text: Any, default: Any) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


class Store:
    """Everything the web application reads from or writes to the database."""

    def __init__(self, db: Database) -> None:
        self.db = db
        db.migrate()
        if self.setting("schema_version") is None:
            self.set_setting("schema_version", str(SCHEMA_VERSION))

    @property
    def persistent(self) -> bool:
        """False for the in-memory database used in tests."""
        return self.db.location != "memory"

    # ---------------------------------------------------------------- settings

    def setting(self, key: str, default: str | None = None) -> str | None:
        row = self.db.one("SELECT value FROM settings WHERE key = ?", (key,))
        return str(row["value"]) if row else default

    def set_setting(self, key: str, value: str) -> None:
        self.db.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    # ------------------------------------------------------------------- users

    def create_user(self, login: str, password_hash: str, *, role: str = "user") -> int:
        return self.db.insert(
            "INSERT INTO users (login, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (login, password_hash, role, int(time.time())),
        )

    def user(self, user_id: int) -> dict[str, Any] | None:
        return self.db.one("SELECT * FROM users WHERE id = ?", (user_id,))

    def user_by_login(self, login: str) -> dict[str, Any] | None:
        return self.db.one("SELECT * FROM users WHERE login = ?", (login,))

    def update_user(self, user_id: int, **fields: Any) -> None:
        unknown = set(fields) - _USER_COLUMNS
        if unknown or not fields:
            raise ValueError(f"cannot update user columns {sorted(unknown)}")
        assignments = ", ".join(f"{name} = ?" for name in fields)
        self.db.execute(
            f"UPDATE users SET {assignments} WHERE id = ?",  # noqa: S608 - names are whitelisted
            (*fields.values(), user_id),
        )

    def delete_user(self, user_id: int) -> None:
        self.db.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
        self.db.execute("DELETE FROM users WHERE id = ?", (user_id,))

    def users(self, *, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        return self.db.query(
            "SELECT * FROM users ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )

    def count_users(self, *, role: str | None = None) -> int:
        if role:
            row = self.db.one("SELECT COUNT(*) AS n FROM users WHERE role = ?", (role,))
        else:
            row = self.db.one("SELECT COUNT(*) AS n FROM users")
        return int(row["n"]) if row else 0

    # ------------------------------------------------------------------ events

    def add_event(
        self,
        kind: str,
        *,
        user_id: int | None = None,
        login: str = "",
        ip: str = "",
        country: str = "",
        user_agent: str = "",
        detail: str = "",
    ) -> None:
        self.db.execute(
            "INSERT INTO events (ts, kind, user_id, login, ip, country, user_agent, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                int(time.time()),
                kind,
                user_id,
                login[:120],
                ip[:64],
                country[:8],
                user_agent[:300],
                detail[:500],
            ),
        )

    @staticmethod
    def _event_filter(kind: str, text: str) -> tuple[str, list[Any]]:
        clauses, params = [], []
        if kind:
            clauses.append("kind LIKE ?")
            params.append(kind + "%")
        if text:
            needle = "%" + text.lower() + "%"
            clauses.append("(LOWER(login) LIKE ? OR ip LIKE ? OR LOWER(detail) LIKE ?)")
            params += [needle, needle, needle]
        return (" WHERE " + " AND ".join(clauses) if clauses else ""), params

    def events(
        self, *, kind: str = "", text: str = "", limit: int = 50, offset: int = 0
    ) -> list[dict[str, Any]]:
        where, params = self._event_filter(kind, text)
        return self.db.query(
            f"SELECT * FROM events{where} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",  # noqa: S608
            (*params, limit, offset),
        )

    def count_events(self, *, kind: str = "", text: str = "", since: int = 0) -> int:
        where, params = self._event_filter(kind, text)
        if since:
            where += (" AND " if where else " WHERE ") + "ts >= ?"
            params.append(since)
        row = self.db.one(f"SELECT COUNT(*) AS n FROM events{where}", params)  # noqa: S608
        return int(row["n"]) if row else 0

    def events_since(self, since: int, kinds: Sequence[str]) -> list[dict[str, Any]]:
        """Timestamps and origins of recent events, for the admin overview."""
        marks = ", ".join("?" for _ in kinds)
        return self.db.query(
            f"SELECT ts, kind, ip, country FROM events WHERE ts >= ? AND kind IN ({marks})",  # noqa: S608
            (since, *kinds),
        )

    def purge_events(self, before: int) -> int:
        return self.db.execute("DELETE FROM events WHERE ts < ?", (before,))

    # ------------------------------------------------------------------- scans

    def create_scan(
        self, public_id: str, user_id: int, host: str, port: int, ip: str, standards: list[str]
    ) -> None:
        self.db.execute(
            "INSERT INTO scans (public_id, user_id, host, port, ip, standards, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 'queued', ?)",
            (public_id, user_id, host, port, ip, json.dumps(standards), int(time.time())),
        )

    def set_scan_status(self, public_id: str, status: str) -> None:
        self.db.execute("UPDATE scans SET status = ? WHERE public_id = ?", (status, public_id))

    def finish_scan(
        self,
        public_id: str,
        *,
        observation: dict[str, Any] | None = None,
        grade: str | None = None,
        verdicts: dict[str, str] | None = None,
        error: str = "",
    ) -> None:
        self.db.execute(
            "UPDATE scans SET status = ?, finished_at = ?, grade = ?, verdicts = ?, "
            "observation = ?, error = ? WHERE public_id = ?",
            (
                "error" if error else "done",
                int(time.time()),
                grade,
                json.dumps(verdicts or {}),
                json.dumps(observation) if observation is not None else None,
                error or None,
                public_id,
            ),
        )

    @staticmethod
    def _scan(row: dict[str, Any] | None, *, full: bool = True) -> dict[str, Any] | None:
        if row is None:
            return None
        row["standards"] = _loads(row.get("standards"), [])
        row["verdicts"] = _loads(row.get("verdicts"), {})
        if full:
            row["observation"] = _loads(row.get("observation"), None)
        return row

    def scan(self, public_id: str) -> dict[str, Any] | None:
        return self._scan(self.db.one("SELECT * FROM scans WHERE public_id = ?", (public_id,)))

    def scans(
        self, *, user_id: int | None = None, limit: int = 50, offset: int = 0
    ) -> list[dict[str, Any]]:
        columns = (
            "s.public_id, s.user_id, s.host, s.port, s.ip, s.standards, s.status, "
            "s.created_at, s.finished_at, s.grade, s.verdicts, s.error, u.login"
        )
        sql = f"SELECT {columns} FROM scans s LEFT JOIN users u ON u.id = s.user_id"  # noqa: S608
        params: list[Any] = []
        if user_id is not None:
            sql += " WHERE s.user_id = ?"
            params.append(user_id)
        sql += " ORDER BY s.created_at DESC, s.id DESC LIMIT ? OFFSET ?"
        rows = self.db.query(sql, (*params, limit, offset))
        return [r for r in (self._scan(row, full=False) for row in rows) if r is not None]

    def count_scans(self, *, user_id: int | None = None, since: int = 0) -> int:
        clauses, params = [], []
        if user_id is not None:
            clauses.append("user_id = ?")
            params.append(user_id)
        if since:
            clauses.append("created_at >= ?")
            params.append(since)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        row = self.db.one(f"SELECT COUNT(*) AS n FROM scans{where}", params)  # noqa: S608
        return int(row["n"]) if row else 0

    def delete_scan(self, public_id: str) -> None:
        self.db.execute("DELETE FROM scans WHERE public_id = ?", (public_id,))

    def fail_unfinished_scans(self) -> int:
        """After a restart no worker is left for scans that were still running."""
        return self.db.execute(
            "UPDATE scans SET status = 'error', error = ?, finished_at = ? "
            "WHERE status IN ('queued', 'running')",
            ("interrupted by a restart of the service", int(time.time())),
        )

    def purge_scans(self, before: int) -> int:
        return self.db.execute("DELETE FROM scans WHERE created_at < ?", (before,))
