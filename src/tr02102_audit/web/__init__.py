"""Web interface: accounts, scanning, reports, administration.

Configuration (environment variables):

    SECRET_KEY              signs session cookies; set a long random value in production
    APP_PASSWORD            password of the first administrator, created at start-up
    ADMIN_LOGIN             login name of that administrator (default: admin)
    ADMIN_RESET             "1" sets the administrator's password to APP_PASSWORD again
    DATABASE_URL            postgres://... for PostgreSQL; unset for a SQLite file
    DATA_DIR                directory of the SQLite file (default: ./data)
    SESSION_COOKIE_SECURE   "1" (default) sends cookies over HTTPS only; "0" for local HTTP
    TRUST_PROXY             "1" when running behind one reverse proxy (Render, nginx)
    CLIENT_IP_HEADER        header with the visitor's address (Render: CF-Connecting-IP)
    AUDIT_RETENTION_DAYS    how long audit events are kept (default: 30)
    REPORT_RETENTION_DAYS   how long reports are kept (default: 365)
    CHECKS_PER_MONTH        monthly limit of an account unless an administrator
                            sets another one for it (default: 50)
    OPERATOR_NAME, OPERATOR_ADDRESS, OPERATOR_EMAIL
                            who runs this instance; shown on the legal pages
"""

import json
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from flask import Flask, Response, g, render_template, request, session
from werkzeug.middleware.proxy_fix import ProxyFix

from tr02102_audit import __version__
from tr02102_audit.engine import STATUS_RANK
from tr02102_audit.standards import CATEGORIES, CONTROLS, load_builtin
from tr02102_audit.tls.registry import suite_info
from tr02102_audit.web import common, i18n, quota, security
from tr02102_audit.web.jobs import JobRunner
from tr02102_audit.web.store import Database, Store, StoreError

CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self' data:; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)


def _env_flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    return default if value is None else value.strip().lower() in ("1", "true", "yes")


def _env_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, "")))
    except ValueError:
        return default


def _client_ip_header() -> str:
    explicit = os.environ.get("CLIENT_IP_HEADER", "").strip()
    if explicit:
        return explicit
    # Render puts Cloudflare in front of every service. The address in
    # X-Forwarded-For is Cloudflare's; the visitor's is in this header.
    return "CF-Connecting-IP" if os.environ.get("RENDER") else ""


def _bootstrap_admin(app: Flask, store: Store) -> None:
    """Create the first administrator from APP_PASSWORD, so a new instance is usable."""
    password = app.config["APP_PASSWORD"]
    login = app.config["ADMIN_LOGIN"]
    if not password:
        return
    if len(password) < security.MIN_PASSWORD:
        app.logger.warning(
            "APP_PASSWORD is shorter than %d characters; choose a longer one.",
            security.MIN_PASSWORD,
        )
    existing = store.user_by_login(login)
    cost = app.config["SCRYPT_N_LOG2"]
    if existing is None:
        store.create_user(login, security.hash_password(password, cost), role="admin")
    elif app.config["ADMIN_RESET"]:
        store.update_user(
            existing["id"], password_hash=security.hash_password(password, cost), role="admin"
        )


def create_app(config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    env = os.environ.get
    app.config.update(
        SECRET_KEY=env("SECRET_KEY") or secrets.token_hex(32),
        APP_PASSWORD=env("APP_PASSWORD", ""),
        ADMIN_LOGIN=(env("ADMIN_LOGIN") or "admin").strip().lower(),
        ADMIN_RESET=_env_flag("ADMIN_RESET", False),
        DATABASE_URL=env("DATABASE_URL", ""),
        DATA_DIR=env("DATA_DIR", "data"),
        SESSION_COOKIE_SECURE=_env_flag("SESSION_COOKIE_SECURE", True),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
        MAX_CONTENT_LENGTH=256 * 1024,
        TRUST_PROXY=_env_flag("TRUST_PROXY", False),
        CLIENT_IP_HEADER=_client_ip_header(),
        AUDIT_RETENTION_DAYS=_env_int("AUDIT_RETENTION_DAYS", 30),
        REPORT_RETENTION_DAYS=_env_int("REPORT_RETENTION_DAYS", 365),
        CHECKS_PER_MONTH=_env_int("CHECKS_PER_MONTH", quota.DEFAULT_MONTHLY_LIMIT),
        SCRYPT_N_LOG2=security.SCRYPT_N_LOG2,
        OPERATOR={
            "name": env("OPERATOR_NAME", "").strip(),
            "address": env("OPERATOR_ADDRESS", "").strip(),
            "email": env("OPERATOR_EMAIL", "").strip(),
        },
        EPHEMERAL_HOST=bool(env("RENDER")),
        SCAN_FN=None,  # tests may inject a fake scanner
        ALLOW_PRIVATE_TARGETS=False,
    )
    if config:
        app.config.update(config)
    if app.config["TRUST_PROXY"]:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)  # type: ignore[method-assign]

    store = Store(Database(app.config["DATABASE_URL"], Path(app.config["DATA_DIR"])))
    store.fail_unfinished_scans()
    _bootstrap_admin(app, store)
    app.extensions["tr02102"] = common.Services(
        store=store,
        jobs=JobRunner(store, max_workers=2),
        standards=load_builtin(),
        # Failed sign-ins: 10 per address, 100 per login name, in 15 minutes.
        # The second number is higher on purpose. With 10, anybody could lock
        # the administrator out by typing wrong passwords; with 100 that takes
        # more than ten addresses, while guessing across many addresses is
        # still capped.
        login_limiter=security.RateLimiter(limit=10, window_s=15 * 60),
        account_limiter=security.RateLimiter(limit=100, window_s=15 * 60),
        register_limiter=security.RateLimiter(limit=5, window_s=60 * 60),
        scan_limiter=security.RateLimiter(limit=quota.HOURLY_LIMIT, window_s=60 * 60),
        # Verified for logins that do not exist, so a wrong login name takes
        # as long as a wrong password (no user enumeration by timing).
        dummy_hash=security.hash_password(secrets.token_hex(16), app.config["SCRYPT_N_LOG2"]),
    )

    # ----------------------------------------------------------- Jinja helpers

    app.jinja_env.filters["by_status"] = lambda findings: sorted(
        findings, key=lambda f: -STATUS_RANK[f["status"]]
    )

    def when(timestamp: int | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
        if not timestamp:
            return ""
        return datetime.fromtimestamp(int(timestamp), UTC).strftime(fmt)

    app.jinja_env.filters["when"] = when
    app.jinja_env.filters["pretty_json"] = lambda data: json.dumps(data, indent=2)
    app.jinja_env.globals.update(
        _=common.tr, csrf_token=common.csrf_token, lang_url=common.lang_url
    )

    @app.context_processor
    def inject() -> dict[str, Any]:
        user = common.current_user()
        return {
            "user": user,
            "is_admin": common.is_admin(),
            "can_sign_in": store.count_users() > 0,
            "registration_open": store.setting("registration_open") == "1",
            "version": __version__,
            "controls": CONTROLS,
            "categories": CATEGORIES,
            "suite_info": suite_info,
            "lang": g.get("lang", i18n.DEFAULT),
            "languages": i18n.LANGUAGES,
            "operator": app.config["OPERATOR"],
        }

    # ------------------------------------------------------------------- hooks

    @app.before_request
    def prepare() -> None:
        g.user = None
        g.lang = i18n.DEFAULT
        if request.endpoint in ("static", "public.healthz"):
            return
        uid = session.get("uid")
        if uid is not None:
            user = store.user(int(uid))
            stamp = security.session_stamp(user["password_hash"]) if user else ""
            if user and not user["blocked"] and session.get("sv") == stamp:
                g.user = user
            else:
                session.clear()  # deleted, blocked, or the password was changed

        wanted = request.args.get("lang", "")
        if wanted in i18n.LANGUAGES:
            session["lang"] = wanted
            if g.user and g.user.get("locale") != wanted:
                store.update_user(g.user["id"], locale=wanted)
        g.lang = (
            session.get("lang")
            or (g.user or {}).get("locale")
            or i18n.from_header(request.headers.get("Accept-Language", ""))
            or i18n.DEFAULT
        )
        if g.lang not in i18n.LANGUAGES:
            g.lang = i18n.DEFAULT

        if request.method == "POST":
            common.check_csrf()

    @app.after_request
    def security_headers(resp: Response) -> Response:
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if request.is_secure:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        if request.endpoint not in ("static", "public.healthz"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(413)
    def http_error(err: Any) -> tuple[str, int]:
        messages = {
            403: common.tr("This page is for administrators."),
            404: common.tr("This page does not exist."),
        }
        message = messages.get(err.code, err.description)
        return render_template("error.html", message=message, code=err.code), err.code

    @app.errorhandler(StoreError)
    def database_error(err: StoreError) -> Response:
        # No template here: rendering one would ask the database again.
        app.logger.error("database error: %s", err)
        resp = Response(
            "The database cannot be reached right now. Try again in a moment.\n",
            status=503,
            mimetype="text/plain",
        )
        resp.headers["Retry-After"] = "30"
        return resp

    from tr02102_audit.web import views_account, views_admin, views_public

    app.register_blueprint(views_public.bp)
    app.register_blueprint(views_account.bp)
    app.register_blueprint(views_admin.bp)
    return app
