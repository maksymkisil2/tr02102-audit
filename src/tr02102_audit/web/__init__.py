"""Web interface: password-protected scanning, public demo reports.

Configuration (environment variables):

    APP_PASSWORD            required to enable scanning; without it the site is demo-only
    SECRET_KEY              signs session cookies; set a long random value in production
    SESSION_COOKIE_SECURE   "1" (default) sends cookies over HTTPS only; "0" for local HTTP
    TRUST_PROXY             "1" when running behind one reverse proxy (Render, nginx)
"""

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from datetime import timedelta
from functools import wraps
from importlib import resources
from typing import Any, ParamSpec, TypeVar

from flask import (
    Flask,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix

from tr02102_audit import __version__, report, sarif
from tr02102_audit.engine import STATUS_RANK
from tr02102_audit.netguard import TargetError, parse_target, resolve
from tr02102_audit.standards import CONTROLS, load_builtin
from tr02102_audit.tls.registry import suite_info
from tr02102_audit.web.jobs import JobStore

P = ParamSpec("P")
R = TypeVar("R")

DEMOS = {
    "tls-weak": "Deliberately weak server from the test lab",
    "tls-good": "Modern server from the test lab",
}

CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self' data:; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)


class RateLimiter:
    """Sliding-window counter per key. In memory: one process, one instance."""

    def __init__(self, limit: int, window_s: float) -> None:
        self.limit = limit
        self.window = window_s
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True


def _env_flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    return default if value is None else value.strip().lower() in ("1", "true", "yes")


def _load_demo(name: str) -> dict[str, Any]:
    text = resources.files("tr02102_audit.web").joinpath("demo", f"{name}.json").read_text("utf-8")
    data: dict[str, Any] = json.loads(text)
    return data


def create_app(config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    password = os.environ.get("APP_PASSWORD", "")
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        APP_PASSWORD=password,
        SESSION_COOKIE_SECURE=_env_flag("SESSION_COOKIE_SECURE", True),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        MAX_CONTENT_LENGTH=16 * 1024,
        TRUST_PROXY=_env_flag("TRUST_PROXY", False),
        SCAN_FN=None,  # tests may inject a fake scanner
        ALLOW_PRIVATE_TARGETS=False,
    )
    if config:
        app.config.update(config)
    if app.config["TRUST_PROXY"]:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)  # type: ignore[method-assign]

    app.jinja_env.filters["by_status"] = lambda findings: sorted(
        findings, key=lambda f: -STATUS_RANK[f["status"]]
    )

    standards = load_builtin()
    jobs = JobStore(max_workers=2, max_jobs=50)
    login_limiter = RateLimiter(limit=10, window_s=15 * 60)
    scan_limiter = RateLimiter(limit=10, window_s=60 * 60)

    # ------------------------------------------------------------------ helpers

    def scanning_enabled() -> bool:
        return bool(app.config["APP_PASSWORD"])

    def logged_in() -> bool:
        return bool(session.get("auth"))

    def csrf_token() -> str:
        token = session.get("csrf")
        if not isinstance(token, str):
            token = secrets.token_urlsafe(32)
            session["csrf"] = token
        return token

    def check_csrf() -> None:
        sent = request.form.get("csrf", "")
        expected = session.get("csrf", "")
        if not expected or not hmac.compare_digest(str(sent), str(expected)):
            abort(400, "invalid form token; reload the page and try again")

    def login_required(view: Callable[P, R]) -> Callable[P, R | Response]:
        @wraps(view)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R | Response:
            if not logged_in():
                return redirect(url_for("login", next=request.path))  # type: ignore[return-value]
            return view(*args, **kwargs)

        return wrapper

    def password_ok(candidate: str) -> bool:
        expected = app.config["APP_PASSWORD"]
        if not expected:
            return False
        a = hashlib.sha256(candidate.encode()).digest()
        b = hashlib.sha256(expected.encode()).digest()
        return hmac.compare_digest(a, b)

    def render_report(
        rep: dict[str, Any], *, demo: str | None = None, job_id: str | None = None
    ) -> str:
        return render_template(
            "report.html", r=rep, demo=demo, demo_title=DEMOS.get(demo or ""), job_id=job_id
        )

    @app.context_processor
    def inject() -> dict[str, Any]:
        return {
            "csrf_token": csrf_token,
            "logged_in": logged_in(),
            "scanning_enabled": scanning_enabled(),
            "version": __version__,
            "controls": CONTROLS,
            "suite_info": suite_info,
        }

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
        if request.endpoint not in ("static", "healthz"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ------------------------------------------------------------------- routes

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/")
    def index() -> str:
        return render_template("index.html", standards=standards.values(), demos=DEMOS)

    @app.get("/standards")
    def standards_page() -> str:
        return render_template("standards.html", standards=standards.values())

    @app.route("/login", methods=["GET", "POST"])
    def login() -> str | Response:
        if request.method == "POST":
            check_csrf()
            ip = request.remote_addr or "unknown"
            if not login_limiter.allow(ip):
                flash("Too many attempts. Try again in 15 minutes.", "error")
            elif password_ok(request.form.get("password", "")):
                session.clear()
                session.permanent = True
                session["auth"] = True
                csrf_token()
                target = request.args.get("next", "")
                safe = target.startswith("/") and not target.startswith("//")
                return redirect(target if safe else url_for("scan"))  # type: ignore[return-value]
            else:
                flash("Wrong password.", "error")
        return render_template("login.html")

    @app.post("/logout")
    def logout() -> Response:
        check_csrf()
        session.clear()
        return redirect(url_for("index"))  # type: ignore[return-value]

    @app.route("/scan", methods=["GET", "POST"])
    @login_required
    def scan() -> str | Response:
        target_text = ""
        chosen = list(standards)
        if request.method == "POST":
            check_csrf()
            target_text = request.form.get("target", "")[:300]
            chosen = [s for s in request.form.getlist("standard") if s in standards]
            try:
                if not chosen:
                    raise TargetError("choose at least one standard")
                host, port = parse_target(target_text)
                target = resolve(host, port, allow_private=app.config["ALLOW_PRIVATE_TARGETS"])
            except TargetError as exc:
                flash(str(exc), "error")
            else:
                if not scan_limiter.allow(str(session.get("csrf"))):
                    flash("Scan limit reached (10 per hour). Try again later.", "error")
                else:
                    selected = [standards[s] for s in chosen]
                    scan_fn = app.config["SCAN_FN"]
                    job_id = jobs.submit(target, selected, scan_fn)
                    if job_id is None:
                        flash("The scanner is busy. Try again in a minute.", "error")
                    else:
                        return redirect(url_for("job", job_id=job_id))  # type: ignore[return-value]
        form = {"target": target_text, "standards": chosen}
        return render_template("scan.html", form=form, standards=standards.values())

    @app.get("/reports/<job_id>")
    @login_required
    def job(job_id: str) -> str:
        j = jobs.get(job_id)
        if j is None:
            abort(404)
        if j.status in ("queued", "running"):
            return render_template("pending.html", job=j)
        if j.status == "error":
            return render_template("error.html", message=j.error), 500  # type: ignore[return-value]
        if j.report is None:
            abort(404)
        return render_report(j.report, job_id=job_id)

    @app.get("/reports/<job_id>.json")
    @login_required
    def job_json(job_id: str) -> Response:
        j = jobs.get(job_id)
        if j is None or j.report is None:
            abort(404)
        return _json_download(j.report, f"tr02102-audit-{job_id}.json")

    @app.get("/reports/<job_id>.sarif")
    @login_required
    def job_sarif(job_id: str) -> Response:
        j = jobs.get(job_id)
        if j is None or j.report is None:
            abort(404)
        return _json_download(sarif.build(j.report), f"tr02102-audit-{job_id}.sarif")

    @app.get("/demo/<name>")
    def demo(name: str) -> str:
        if name not in DEMOS:
            abort(404)
        rep = report.build(_load_demo(name), list(standards.values()))
        return render_report(rep, demo=name)

    @app.get("/demo/<name>.json")
    def demo_json(name: str) -> Response:
        if name not in DEMOS:
            abort(404)
        rep = report.build(_load_demo(name), list(standards.values()))
        return _json_download(rep, f"demo-{name}.json")

    @app.get("/demo/<name>.sarif")
    def demo_sarif(name: str) -> Response:
        if name not in DEMOS:
            abort(404)
        rep = report.build(_load_demo(name), list(standards.values()))
        return _json_download(sarif.build(rep), f"demo-{name}.sarif")

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(413)
    def http_error(err: Any) -> tuple[str, int]:
        return render_template("error.html", message=err.description), err.code

    return app


def _json_download(data: dict[str, Any], filename: str) -> Response:
    resp = Response(json.dumps(data, indent=2), mimetype="application/json")
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp
