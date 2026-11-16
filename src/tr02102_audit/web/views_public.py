"""Pages that need no account: start page, standards, pricing, samples, sign-in."""

import json
import re
import time
from importlib import resources
from typing import Any

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    redirect,
    render_template,
    request,
    url_for,
)
from flask import session as flask_session
from flask.typing import ResponseReturnValue

from tr02102_audit import __version__, report, sarif
from tr02102_audit.standards import defaults
from tr02102_audit.web import i18n, plans, security
from tr02102_audit.web.common import audit, current_user, notice, remote_ip, services
from tr02102_audit.web.frameworks import FRAMEWORKS

bp = Blueprint("public", __name__)

DEMOS = {
    "tls-weak": "A deliberately weak server",
    "tls-typical": "A typical modern website",
    "tls-good": "A server hardened to the BSI lists",
}
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")


def _load_demo(name: str) -> dict[str, Any]:
    path = resources.files("tr02102_audit.web").joinpath("demo", f"{name}.json")
    data: dict[str, Any] = json.loads(path.read_text("utf-8"))
    return data


def _demo_report(name: str) -> dict[str, Any]:
    if name not in DEMOS:
        abort(404)
    return report.build(_load_demo(name), defaults(services().standards))


def json_download(data: dict[str, Any], filename: str) -> Response:
    resp = Response(json.dumps(data, indent=2), mimetype="application/json")
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp


def _sign_in(user: dict[str, Any]) -> None:
    """Start a fresh session for ``user`` (a new session id against fixation)."""
    lang = flask_session.get("lang")
    flask_session.clear()
    flask_session.permanent = True
    flask_session["uid"] = user["id"]
    flask_session["sv"] = security.session_stamp(user["password_hash"])
    if lang:
        flask_session["lang"] = lang


def _safe_next() -> str:
    target = request.args.get("next", "")
    if target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return url_for("account.scan")


@bp.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@bp.get("/")
def index() -> str:
    svc = services()
    reports = {name: _demo_report(name) for name in DEMOS}
    return render_template(
        "index.html",
        standards=list(svc.standards.values()),
        demos=DEMOS,
        sample=reports["tls-typical"],
        grades={name: rep["rating"]["grade"] for name, rep in reports.items()},
    )


@bp.get("/standards")
def standards_page() -> str:
    return render_template(
        "standards.html", standards=list(services().standards.values()), frameworks=FRAMEWORKS
    )


@bp.get("/pricing")
def pricing() -> str:
    svc = services()
    return render_template(
        "pricing.html",
        plans=plans.PLANS,
        pack_checks=plans.CREDIT_PACK_CHECKS,
        pack_price=plans.CREDIT_PACK_PRICE_EUR,
        sells={p: svc.stripe.sells(p) for p in ("pro", "business", "credits")},
        price_note=current_app.config["PRICE_NOTE"],
        stripe_enabled=svc.stripe.enabled,
    )


@bp.get("/legal/<page>")
def legal(page: str) -> str:
    if page not in ("imprint", "privacy", "terms"):
        abort(404)
    return render_template(
        f"legal_{page}.html",
        retention_days=current_app.config["AUDIT_RETENTION_DAYS"],
        stripe_enabled=services().stripe.enabled,
    )


@bp.get("/demo/<name>")
def demo(name: str) -> str:
    return render_template(
        "report.html", r=_demo_report(name), demo=name, demo_title=DEMOS[name], scan=None
    )


@bp.get("/demo/<name>.json")
def demo_json(name: str) -> Response:
    return json_download(_demo_report(name), f"demo-{name}.json")


@bp.get("/demo/<name>.sarif")
def demo_sarif(name: str) -> Response:
    return json_download(sarif.build(_demo_report(name)), f"demo-{name}.sarif")


@bp.route("/login", methods=["GET", "POST"])
def login() -> ResponseReturnValue:
    svc = services()
    if current_user() is not None:
        return redirect(_safe_next())
    name = ""
    if request.method == "POST":
        name = request.form.get("login", "").strip().lower()[:120]
        password = request.form.get("password", "")
        keys = (f"ip:{remote_ip()}", f"login:{name}")
        if not all(svc.login_limiter.peek(k) for k in keys):
            audit("login.blocked", "too many failed attempts", login=security.mask_login(name))
            notice("Too many failed attempts. Try again in 15 minutes.", "error")
        else:
            user = svc.store.user_by_login(name) if name else None
            stored = user["password_hash"] if user else svc.dummy_hash
            correct = security.verify_password(password, stored)
            if user and correct and not user["blocked"]:
                _sign_in(user)
                svc.store.update_user(user["id"], last_login_at=_now())
                audit("login.ok", user=user)
                return redirect(_safe_next())
            for key in keys:
                svc.login_limiter.allow(key)
            if user and correct:
                audit("login.failed", "account is blocked", user=user)
            elif user:
                audit("login.failed", "wrong password", login=user["login"])
            else:
                audit("login.failed", "unknown login name", login=security.mask_login(name))
            notice("Wrong login name or password.", "error")
    return render_template("login.html", login=name)


@bp.route("/register", methods=["GET", "POST"])
def register() -> ResponseReturnValue:
    svc = services()
    if current_user() is not None:
        return redirect(url_for("account.scan"))
    is_open = svc.store.setting("registration_open") == "1"
    name = ""
    if request.method == "POST":
        if not is_open:
            abort(403, "registration is closed")
        name = request.form.get("login", "").strip().lower()[:120]
        password = request.form.get("password", "")
        problem = security.password_problem(password, name)
        if not svc.register_limiter.allow(f"ip:{remote_ip()}"):
            audit("register.blocked", "too many registrations from this address")
            notice("Too many registrations from this address. Try again later.", "error")
        elif not _EMAIL.match(name) or not security.LOGIN_PATTERN.match(name):
            notice("Enter a valid e-mail address.", "error")
        elif problem:
            notice(problem, "error", n=security.MIN_PASSWORD)
        elif password != request.form.get("password2", ""):
            notice("The two passwords do not match.", "error")
        elif request.form.get("terms") != "yes":
            notice("Please accept the terms of use.", "error")
        elif svc.store.user_by_login(name) is not None:
            notice("This e-mail address already has an account.", "error")
        else:
            cost = current_app.config["SCRYPT_N_LOG2"]
            user_id = svc.store.create_user(name, security.hash_password(password, cost))
            user = svc.store.user(user_id)
            if user is None:
                abort(500)
            _sign_in(user)
            audit("register", user=user)
            notice(
                "Your account is ready. The free plan includes %(n)s checks a month.",
                "ok",
                n=plans.PLANS["free"].checks_per_month,
            )
            return redirect(url_for("account.scan"))
    return render_template(
        "register.html", login=name, is_open=is_open, min_password=security.MIN_PASSWORD
    )


@bp.post("/logout")
def logout() -> ResponseReturnValue:
    if current_user() is not None:
        audit("logout")
    lang = flask_session.get("lang")
    flask_session.clear()
    if lang in i18n.LANGUAGES:
        flask_session["lang"] = lang
    return redirect(url_for("public.index"))


def _now() -> int:
    return int(time.time())
