"""Persistent storage: accounts, audit log, scan history, settings.

Two backends behind one small interface:

* SQLite (default): a file under ``DATA_DIR``. Needs nothing, but on hosting
  with an ephemeral disk the data is lost on every restart.
* PostgreSQL: used when ``DATABASE_URL`` starts with ``postgres``. Needs the
  optional ``psycopg`` package. Works with hosted services that close idle
  connections or put the database to sleep (Neon, Supabase): a lost
  connection is opened again once and the statement repeated.

The SQL below is the subset both understand. Every statement uses bound
parameters; nothing from a request is ever formatted into SQL (threat T-20).
Timestamps are Unix seconds, booleans are 0/1, structured values are JSON
text, so rows look the same in both backends.

The schema has a version number in ``settings``. ``_TABLES`` is version 1;
every later change is a step in ``_MIGRATIONS`` that runs once, in order, at
start-up. To change the schema, append a step; never edit an old one.
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

# (version, statements). A statement is SQL, or ("add_column", table, column,
# type), which is skipped when the column already exists, so a step that was
# interrupted half-way can run again.
_MIGRATIONS: tuple[tuple[int, tuple[Any, ...]], ...] = (
    (
        2,
        (
            # Servers a user keeps an eye on: checked again with one click,
            # compared before and after a change.
            """
            CREATE TABLE IF NOT EXISTS targets (
                id {pk},
                user_id BIGINT NOT NULL,
                host TEXT NOT NULL,
                port BIGINT NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                standards TEXT NOT NULL DEFAULT '[]',
                created_at BIGINT NOT NULL,
                UNIQUE (user_id, host, port)
            )
            """,
            "CREATE INDEX IF NOT EXISTS scans_endpoint ON scans (user_id, host, port, created_at)",
            # The report format chosen before the check: web, pdf, json or sarif.
            ("add_column", "scans", "output", "TEXT"),
        ),
    ),
)
SCHEMA_VERSION = _MIGRATIONS[-1][0]

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
            # prepare_threshold=None: no server-side prepared statements, which
            # connection poolers in transaction mode (Neon, Supabase) do not keep.
            self._conn = psycopg.connect(
                self._url, autocommit=True, connect_timeout=15, prepare_threshold=None
            )
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

    @property
    def _pk(self) -> str:
        if self.dialect == "postgres":
            return "BIGSERIAL PRIMARY KEY"
        return "INTEGER PRIMARY KEY AUTOINCREMENT"

    def columns(self, table: str) -> set[str]:
        if self.dialect == "postgres":
            rows = self.query(
                "SELECT column_name AS name FROM information_schema.columns "
                "WHERE table_schema = current_schema() AND table_name = ?",
                (table,),
            )
        else:
            if not table.isidentifier():
                raise ValueError(f"not a table name: {table!r}")
            rows = self.query(f"PRAGMA table_info({table})")
        return {str(r["name"]) for r in rows}

    def run_statement(self, statement: Any) -> None:
        if isinstance(statement, tuple):
            _, table, column, kind = statement
            if column not in self.columns(table):
                self.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")
            return
        self.execute(statement.format(pk=self._pk))

    def migrate(self) -> None:
        """Create the version 1 tables if they are missing."""
        for statement in _TABLES:
            self.run_statement(statement)


_SCAN_LIST = (
    "s.public_id, s.user_id, s.host, s.port, s.ip, s.standards, s.status, s.output, "
    "s.created_at, s.finished_at, s.grade, s.verdicts, s.error, u.login"
)


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
        self.schema_version = self._upgrade()

    def _upgrade(self) -> int:
        # A database without a version number is version 1: either it was
        # just created from _TABLES, or it predates the number.
        version = int(self.setting("schema_version") or 1)
        for step, statements in _MIGRATIONS:
            if step <= version:
                continue
            for statement in statements:
                self.db.run_statement(statement)
            self.set_setting("schema_version", str(step))
            version = step
        if self.setting("schema_version") is None:
            self.set_setting("schema_version", str(version))
        return version

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
        self.db.execute("DELETE FROM targets WHERE user_id = ?", (user_id,))
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
    def _event_filter(
        kind: str = "",
        text: str = "",
        *,
        ip: str = "",
        login: str = "",
        since: int = 0,
        until: int = 0,
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if kind:
            clauses.append("kind LIKE ?")
            params.append(kind + "%")
        if text:
            needle = "%" + text.lower() + "%"
            clauses.append(
                "(LOWER(login) LIKE ? OR ip LIKE ? OR LOWER(detail) LIKE ? "
                "OR LOWER(user_agent) LIKE ?)"
            )
            params += [needle, needle, needle, needle]
        if ip:
            clauses.append("ip = ?")
            params.append(ip)
        if login:
            clauses.append("LOWER(login) = ?")
            params.append(login.lower())
        if since:
            clauses.append("ts >= ?")
            params.append(since)
        if until:
            clauses.append("ts < ?")
            params.append(until)
        return (" WHERE " + " AND ".join(clauses) if clauses else ""), params

    def events(self, *, limit: int = 50, offset: int = 0, **filters: Any) -> list[dict[str, Any]]:
        """Audit events, newest first. Filters: kind, text, ip, login, since, until."""
        where, params = self._event_filter(**filters)
        return self.db.query(
            f"SELECT * FROM events{where} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",  # noqa: S608
            (*params, limit, offset),
        )

    def count_events(self, **filters: Any) -> int:
        where, params = self._event_filter(**filters)
        row = self.db.one(f"SELECT COUNT(*) AS n FROM events{where}", params)  # noqa: S608
        return int(row["n"]) if row else 0

    def events_since(self, since: int, kinds: Sequence[str]) -> list[dict[str, Any]]:
        """Recent events of some kinds, oldest first, for the overview and its signals."""
        marks = ", ".join("?" for _ in kinds)
        return self.db.query(
            "SELECT ts, kind, user_id, login, ip, country, detail FROM events "  # noqa: S608
            f"WHERE ts >= ? AND kind IN ({marks}) ORDER BY ts, id",
            (since, *kinds),
        )

    def purge_events(self, before: int) -> int:
        return self.db.execute("DELETE FROM events WHERE ts < ?", (before,))

    # ------------------------------------------------------------------- scans

    def create_scan(
        self,
        public_id: str,
        user_id: int,
        host: str,
        port: int,
        ip: str,
        standards: list[str],
        output: str = "web",
    ) -> None:
        self.db.execute(
            "INSERT INTO scans (public_id, user_id, host, port, ip, standards, status, "
            "created_at, output) VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?)",
            (public_id, user_id, host, port, ip, json.dumps(standards), int(time.time()), output),
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
        sql = f"SELECT {_SCAN_LIST} FROM scans s LEFT JOIN users u ON u.id = s.user_id"  # noqa: S608
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

    def endpoint_scans(
        self, user_id: int, host: str, port: int, *, limit: int = 50
    ) -> list[dict[str, Any]]:
        """History of one endpoint for one account, newest first, without observations."""
        rows = self.db.query(
            f"SELECT {_SCAN_LIST} FROM scans s LEFT JOIN users u ON u.id = s.user_id "  # noqa: S608
            "WHERE s.user_id = ? AND s.host = ? AND s.port = ? "
            "ORDER BY s.created_at DESC, s.id DESC LIMIT ?",
            (user_id, host, port, limit),
        )
        return [r for r in (self._scan(row, full=False) for row in rows) if r is not None]

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

    # ----------------------------------------------------------------- targets

    @staticmethod
    def _target(row: dict[str, Any] | None) -> dict[str, Any] | None:
        if row is not None:
            row["standards"] = _loads(row.get("standards"), [])
        return row

    def save_target(
        self, user_id: int, host: str, port: int, *, label: str = "", standards: list[str]
    ) -> int:
        """Add an endpoint to the account's servers, or update its label and standards."""
        found = self.target_by_endpoint(user_id, host, port)
        if found is not None:
            self.db.execute(
                "UPDATE targets SET label = ?, standards = ? WHERE id = ?",
                (label[:80], json.dumps(standards), found["id"]),
            )
            return int(found["id"])
        return self.db.insert(
            "INSERT INTO targets (user_id, host, port, label, standards, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, host, port, label[:80], json.dumps(standards), int(time.time())),
        )

    def target(self, target_id: int) -> dict[str, Any] | None:
        return self._target(self.db.one("SELECT * FROM targets WHERE id = ?", (target_id,)))

    def target_by_endpoint(self, user_id: int, host: str, port: int) -> dict[str, Any] | None:
        return self._target(
            self.db.one(
                "SELECT * FROM targets WHERE user_id = ? AND host = ? AND port = ?",
                (user_id, host, port),
            )
        )

    def targets(self, *, user_id: int | None = None, limit: int = 200) -> list[dict[str, Any]]:
        """Servers with their owner and their last check, ordered by label and address."""
        sql = (
            "SELECT t.*, u.login, "
            "(SELECT COUNT(*) FROM scans s WHERE s.user_id = t.user_id AND s.host = t.host "
            "AND s.port = t.port) AS checks, "
            "(SELECT MAX(s.created_at) FROM scans s WHERE s.user_id = t.user_id "
            "AND s.host = t.host AND s.port = t.port) AS last_check "
            "FROM targets t LEFT JOIN users u ON u.id = t.user_id"
        )
        params: list[Any] = []
        if user_id is not None:
            sql += " WHERE t.user_id = ?"
            params.append(user_id)
        sql += " ORDER BY t.label, t.host, t.port LIMIT ?"
        rows = self.db.query(sql, (*params, limit))
        result = []
        for row in rows:
            target = self._target(row)
            if target is None:  # pragma: no cover - rows are never None
                continue
            latest = self.endpoint_scans(target["user_id"], target["host"], target["port"], limit=1)
            target["latest"] = latest[0] if latest else None
            result.append(target)
        return result

    def count_targets(self) -> int:
        row = self.db.one("SELECT COUNT(*) AS n FROM targets")
        return int(row["n"]) if row else 0

    def delete_target(self, target_id: int) -> None:
        self.db.execute("DELETE FROM targets WHERE id = ?", (target_id,))

    # ------------------------------------------------------------------ health

    def health(self) -> dict[str, Any]:
        """What the administration shows about the database."""
        started = time.perf_counter()
        self.db.one("SELECT 1 AS ok")
        return {
            "dialect": self.db.dialect,
            "location": self.db.location,
            "schema_version": self.schema_version,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            "users": self.count_users(),
            "scans": self.count_scans(),
            "targets": self.count_targets(),
            "events": self.count_events(),
        }
