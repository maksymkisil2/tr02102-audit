"""Administration: who uses the service and from where, accounts, settings."""

import time
from collections import Counter
from typing import Any

from flask import Blueprint, abort, current_app, redirect, render_template, request, url_for
from flask.typing import ResponseReturnValue

from tr02102_audit.web import quota, security
from tr02102_audit.web.common import (
    PAGE_SIZE,
    admin_required,
    audit,
    current_user,
    notice,
    page_number,
    services,
)

bp = Blueprint("admin", __name__, url_prefix="/admin")

EVENT_GROUPS = ("login", "register", "scan", "report", "account", "admin")
ACTIVITY_DAYS = 14
DAY = 86400


# Geometry of the activity chart, in SVG user units.
CHART_W, CHART_H = 720, 240
PLOT_LEFT, PLOT_TOP, PLOT_BOTTOM = 34, 62, 204
BAR_W, BAR_GAP, TIP_W = 13, 2, 236


def _nice_ceiling(value: int) -> int:
    """Smallest 1, 2 or 5 times a power of ten that is not below ``value``."""
    step = 1
    while True:
        for factor in (1, 2, 5):
            if factor * step >= value:
                return factor * step
        step *= 10


def _column(x: float, value: int, top_value: int) -> str:
    """Path of one column: square at the baseline, rounded at the data end."""
    height = (PLOT_BOTTOM - PLOT_TOP) * value / top_value
    if height <= 0:
        return ""
    radius = min(4.0, height, BAR_W / 2)
    top = PLOT_BOTTOM - height
    right = x + BAR_W
    return (
        f"M{x:.1f},{PLOT_BOTTOM} V{top + radius:.1f} Q{x:.1f},{top:.1f} {x + radius:.1f},{top:.1f} "
        f"H{right - radius:.1f} Q{right:.1f},{top:.1f} {right:.1f},{top + radius:.1f} "
        f"V{PLOT_BOTTOM} Z"
    )


def _activity(now: int) -> dict[str, Any]:
    """Checks and failed sign-ins per day, plus where requests came from."""
    svc = services()
    first_day = (now // DAY - (ACTIVITY_DAYS - 1)) * DAY
    kinds = ("scan.started", "login.failed", "login.blocked", "login.ok", "scan.rejected")
    events = svc.store.events_since(first_day, kinds)
    days = [first_day + i * DAY for i in range(ACTIVITY_DAYS)]
    scans = dict.fromkeys(days, 0)
    failures = dict.fromkeys(days, 0)
    countries: Counter[str] = Counter()
    addresses: Counter[str] = Counter()
    week_ago = now - 7 * DAY
    for event in events:
        day = int(event["ts"]) // DAY * DAY
        if event["kind"] == "scan.started":
            scans[day] = scans.get(day, 0) + 1
        elif event["kind"] in ("login.failed", "login.blocked"):
            failures[day] = failures.get(day, 0) + 1
        if int(event["ts"]) >= week_ago:
            if event["country"]:
                countries[str(event["country"])] += 1
            if event["ip"]:
                addresses[str(event["ip"])] += 1

    top_value = _nice_ceiling(max([1, *scans.values(), *failures.values()]))
    slot = (CHART_W - PLOT_LEFT) / ACTIVITY_DAYS
    series = []
    for index, day in enumerate(days):
        left = PLOT_LEFT + index * slot
        first_bar = left + (slot - 2 * BAR_W - BAR_GAP) / 2
        series.append(
            {
                "day": day,
                "scans": scans[day],
                "failures": failures[day],
                "slot_x": round(left, 1),
                "slot_w": round(slot, 1),
                "center": round(left + slot / 2, 1),
                "scans_path": _column(first_bar, scans[day], top_value),
                "failures_path": _column(first_bar + BAR_W + BAR_GAP, failures[day], top_value),
                "tip_x": round(
                    min(max(left + slot / 2 - TIP_W / 2, PLOT_LEFT), CHART_W - TIP_W), 1
                ),
            }
        )
    ticks = [0, top_value] if top_value == 1 else [0, top_value // 2, top_value]
    return {
        "series": series,
        "ticks": [
            {"value": t, "y": round(PLOT_BOTTOM - (PLOT_BOTTOM - PLOT_TOP) * t / top_value, 1)}
            for t in ticks
        ],
        "box": {
            "w": CHART_W,
            "h": CHART_H,
            "left": PLOT_LEFT,
            "top": PLOT_TOP,
            "bottom": PLOT_BOTTOM,
            "tip_w": TIP_W,
        },
        "countries": countries.most_common(8),
        "addresses": addresses.most_common(8),
    }


def _limit_from_form(text: str) -> int | None:
    """A monthly limit typed by an administrator; empty means the instance default."""
    text = text.strip()
    if not text:
        return None
    if not (text.isascii() and text.isdigit()):
        raise ValueError("not a whole number")
    return min(int(text), quota.MAX_MONTHLY_LIMIT)


@bp.get("")
@admin_required
def overview() -> str:
    svc = services()
    now = int(time.time())
    store = svc.store
    figures = {
        "users": store.count_users(),
        "scans_today": store.count_scans(since=now // DAY * DAY),
        "scans_30d": store.count_scans(since=now - 30 * DAY),
        "failed_24h": store.count_events(kind="login.failed", since=now - DAY)
        + store.count_events(kind="login.blocked", since=now - DAY),
        "rejected_7d": store.count_events(kind="scan.rejected", since=now - 7 * DAY),
    }
    db = store.db
    return render_template(
        "admin_overview.html",
        figures=figures,
        activity=_activity(now),
        recent=store.events(limit=12),
        storage={
            "dialect": db.dialect,
            "location": db.location,
            # A SQLite file on a host that wipes its disk on restart loses
            # accounts, history and this log. The operator has to know.
            "volatile": db.dialect == "sqlite" and current_app.config["EPHEMERAL_HOST"],
        },
        retention_days=current_app.config["AUDIT_RETENTION_DAYS"],
        ip_header=current_app.config["CLIENT_IP_HEADER"],
        monthly_limit=current_app.config["CHECKS_PER_MONTH"],
        hourly_limit=quota.HOURLY_LIMIT,
        report_days=current_app.config["REPORT_RETENTION_DAYS"],
    )


@bp.get("/events")
@admin_required
def events() -> str:
    svc = services()
    kind = request.args.get("kind", "")
    kind = kind if kind in EVENT_GROUPS else ""
    text = request.args.get("q", "").strip()[:80]
    page = page_number()
    rows = svc.store.events(kind=kind, text=text, limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE)
    total = svc.store.count_events(kind=kind, text=text)
    return render_template(
        "admin_events.html",
        events=rows,
        total=total,
        kind=kind,
        q=text,
        groups=EVENT_GROUPS,
        page=page,
        pages=max(1, -(-total // PAGE_SIZE)),
        retention_days=current_app.config["AUDIT_RETENTION_DAYS"],
    )


@bp.get("/scans")
@admin_required
def scans() -> str:
    svc = services()
    page = page_number()
    rows = svc.store.scans(limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE)
    total = svc.store.count_scans()
    return render_template(
        "admin_scans.html", scans=rows, page=page, pages=max(1, -(-total // PAGE_SIZE))
    )


@bp.route("/users", methods=["GET", "POST"])
@admin_required
def users() -> ResponseReturnValue:
    svc = services()
    if request.method == "POST":
        name = request.form.get("login", "").strip().lower()[:120]
        password = request.form.get("password", "")
        role = "admin" if request.form.get("role") == "admin" else "user"
        problem = security.password_problem(password, name)
        if not security.LOGIN_PATTERN.match(name):
            notice("Login names use letters, digits and . _ - @ (3 to 120 characters).", "error")
        elif problem:
            notice(problem, "error", n=security.MIN_PASSWORD)
        elif svc.store.user_by_login(name) is not None:
            notice("This login name is already taken.", "error")
        else:
            hashed = security.hash_password(password, current_app.config["SCRYPT_N_LOG2"])
            svc.store.create_user(name, hashed, role=role)
            audit("admin.user.created", f"{name} ({role})")
            notice("The account %(name)s was created.", "ok", name=name)
            return redirect(url_for("admin.users"))
    page = page_number()
    total = svc.store.count_users()
    return render_template(
        "admin_users.html",
        users=svc.store.users(limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE),
        page=page,
        pages=max(1, -(-total // PAGE_SIZE)),
        min_password=security.MIN_PASSWORD,
        default_limit=current_app.config["CHECKS_PER_MONTH"],
    )


@bp.route("/users/<int:user_id>", methods=["GET", "POST"])
@admin_required
def user_page(user_id: int) -> ResponseReturnValue:
    svc = services()
    store = svc.store
    target = store.user(user_id)
    me = current_user()
    if target is None or me is None:
        abort(404)
    is_self = target["id"] == me["id"]
    last_admin = target["role"] == "admin" and store.count_users(role="admin") <= 1

    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "save":
            role = "admin" if request.form.get("role") == "admin" else "user"
            blocked = 1 if request.form.get("blocked") == "yes" else 0
            try:
                limit = _limit_from_form(request.form.get("monthly_limit", ""))
            except ValueError:
                notice("The monthly limit has to be a whole number, or empty.", "error")
                return redirect(url_for("admin.user_page", user_id=user_id))
            if (is_self or last_admin) and (role != "admin" or blocked):
                notice("You cannot remove or block the last administrator or yourself.", "error")
            else:
                store.update_user(user_id, role=role, blocked=blocked, monthly_limit=limit)
                audit(
                    "admin.user.updated",
                    f"{target['login']}: role={role} blocked={blocked} "
                    f"monthly_limit={'default' if limit is None else limit}",
                )
                notice("Saved.", "ok")
        elif action == "password":
            password = request.form.get("password", "")
            problem = security.password_problem(password, target["login"])
            if problem:
                notice(problem, "error", n=security.MIN_PASSWORD)
            else:
                hashed = security.hash_password(password, current_app.config["SCRYPT_N_LOG2"])
                store.update_user(user_id, password_hash=hashed)
                audit("admin.user.password", target["login"])
                notice("The password was replaced. The account was signed out everywhere.", "ok")
        elif action == "delete":
            if is_self or last_admin:
                notice("You cannot remove or block the last administrator or yourself.", "error")
            else:
                store.delete_user(user_id)
                audit("admin.user.deleted", target["login"])
                notice("The account %(name)s was deleted.", "ok", name=target["login"])
                return redirect(url_for("admin.users"))
        return redirect(url_for("admin.user_page", user_id=user_id))

    return render_template(
        "admin_user.html",
        target=target,
        is_self=is_self,
        default_limit=current_app.config["CHECKS_PER_MONTH"],
        used=store.count_scans(user_id=user_id, since=quota.month_start()),
        scans=store.scans(user_id=user_id, limit=10),
        min_password=security.MIN_PASSWORD,
    )


@bp.post("/settings")
@admin_required
def settings() -> ResponseReturnValue:
    wanted = "1" if request.form.get("registration_open") == "yes" else "0"
    services().store.set_setting("registration_open", wanted)
    audit("admin.settings", f"registration_open={wanted}")
    notice("Saved.", "ok")
    return redirect(url_for("admin.overview"))
