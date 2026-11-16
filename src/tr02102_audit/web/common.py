"""Helpers shared by the views: services, the current user, CSRF, the audit log."""

import contextlib
import hmac
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, ParamSpec

from flask import abort, current_app, flash, g, redirect, request, session, url_for
from flask.typing import ResponseReturnValue
from werkzeug.routing import BuildError

from tr02102_audit.standards import Standard
from tr02102_audit.web import i18n, security
from tr02102_audit.web.jobs import JobRunner
from tr02102_audit.web.store import Store

P = ParamSpec("P")
PAGE_SIZE = 50


@dataclass(slots=True)
class Services:
    store: Store
    jobs: JobRunner
    standards: dict[str, Standard]
    login_limiter: security.RateLimiter
    account_limiter: security.RateLimiter
    register_limiter: security.RateLimiter
    scan_limiter: security.RateLimiter
    dummy_hash: str
    last_purge: list[float] = field(default_factory=lambda: [0.0])


def services() -> Services:
    svc: Services = current_app.extensions["tr02102"]
    return svc


def tr(text: str, **params: Any) -> str:
    """Translate into the language of the current request."""
    return i18n.translate(getattr(g, "lang", i18n.DEFAULT), text, **params)


def lang_url(code: str) -> str:
    """Address of the current page in another language.

    Built from the matched route, not from the raw request path: a path such
    as "//evil.example" would turn the language link into a link elsewhere.
    """
    if request.endpoint and request.endpoint != "static":
        with contextlib.suppress(BuildError):
            return url_for(request.endpoint, **(request.view_args or {}), lang=code)
    return url_for("public.index", lang=code)


def current_user() -> dict[str, Any] | None:
    user: dict[str, Any] | None = getattr(g, "user", None)
    return user


def is_admin() -> bool:
    user = current_user()
    return bool(user and user["role"] == "admin")


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
        abort(400, tr("The form has expired. Reload the page and try again."))


def login_required[**P](view: Callable[P, ResponseReturnValue]) -> Callable[P, ResponseReturnValue]:
    @wraps(view)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> ResponseReturnValue:
        if current_user() is None:
            return redirect(url_for("public.login", next=request.path))
        return view(*args, **kwargs)

    return wrapper


def admin_required[**P](view: Callable[P, ResponseReturnValue]) -> Callable[P, ResponseReturnValue]:
    @wraps(view)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> ResponseReturnValue:
        if current_user() is None:
            return redirect(url_for("public.login", next=request.path))
        if not is_admin():
            abort(403)
        return view(*args, **kwargs)

    return wrapper


def remote_ip() -> str:
    return security.client_ip(request, current_app.config["CLIENT_IP_HEADER"])


def audit(
    kind: str, detail: str = "", *, user: dict[str, Any] | None = None, login: str = ""
) -> None:
    """Write one line to the audit log: who did what, from where."""
    svc = services()
    user = user or current_user()
    svc.store.add_event(
        kind,
        user_id=int(user["id"]) if user else None,
        login=str(user["login"]) if user else login,
        ip=remote_ip(),
        country=security.client_country(request, bool(current_app.config["CLIENT_IP_HEADER"])),
        user_agent=request.headers.get("User-Agent", ""),
        detail=detail,
    )
    purge_old_records(svc)


def purge_old_records(svc: Services, *, force: bool = False) -> None:
    """Delete audit events and reports past their retention time, at most hourly."""
    now = time.time()
    if not force and now - svc.last_purge[0] < 3600:
        return
    svc.last_purge[0] = now
    days = int(current_app.config["AUDIT_RETENTION_DAYS"])
    svc.store.purge_events(int(now) - days * 86400)
    svc.store.purge_scans(int(now) - int(current_app.config["REPORT_RETENTION_DAYS"]) * 86400)


def page_number() -> int:
    try:
        return max(1, min(int(request.args.get("page", "1")), 10_000))
    except ValueError:
        return 1


def notice(text: str, category: str = "info", **params: Any) -> None:
    flash(tr(text, **params), category)
