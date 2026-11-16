"""Pages of a signed-in user: new scan, reports, account settings."""

import secrets
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

from tr02102_audit import report, sarif
from tr02102_audit.netguard import TargetError, parse_target, resolve
from tr02102_audit.standards import Standard, defaults
from tr02102_audit.web import quota, security
from tr02102_audit.web.common import (
    PAGE_SIZE,
    audit,
    current_user,
    is_admin,
    login_required,
    notice,
    page_number,
    services,
    tr,
)
from tr02102_audit.web.views_public import json_download

bp = Blueprint("account", __name__)


# What the visitor is told when a target is refused. The audit log keeps the
# technical reason.
TARGET_PROBLEMS = {
    "invalid": "This is not a valid host name or IP address.",
    "unresolved": "This host name could not be found.",
    "private": (
        "This address is private, loopback or reserved. Only public addresses can be checked here."
    ),
}


def _me() -> dict[str, Any]:
    user = current_user()
    if user is None:  # login_required runs first; this only narrows the type
        abort(401)
    return user


def _allowance(user: dict[str, Any]) -> quota.Allowance:
    used = services().store.count_scans(user_id=user["id"], since=quota.month_start())
    return quota.allowance(user, used, current_app.config["CHECKS_PER_MONTH"])


def _chosen_standards(ids: list[str]) -> list[Standard]:
    available = services().standards
    return [available[i] for i in ids if i in available]


@bp.route("/scan", methods=["GET", "POST"])
@login_required
def scan() -> ResponseReturnValue:
    svc = services()
    user = _me()
    target_text = request.args.get("target", "")[:300]
    chosen = [s.id for s in defaults(svc.standards)]
    allowance = _allowance(user)

    if request.method == "POST":
        target_text = request.form.get("target", "")[:300]
        chosen = [s for s in request.form.getlist("standard") if s in svc.standards]
        target = None
        if not chosen:
            notice("Choose at least one standard.", "error")
        elif request.form.get("authorised") != "yes":
            notice("Confirm that you are authorised to test this server.", "error")
        else:
            try:
                host, port = parse_target(target_text)
                target = resolve(
                    host, port, allow_private=current_app.config["ALLOW_PRIVATE_TARGETS"]
                )
            except TargetError as exc:
                # Refused targets are logged: probing for private addresses is
                # what an attack on the scanner itself looks like (threat T-14).
                audit("scan.rejected", f"{target_text[:120]}: {exc}")
                notice(TARGET_PROBLEMS.get(exc.reason, TARGET_PROBLEMS["invalid"]), "error")
        if target is not None:
            where = f"{target.host}:{target.port}"
            if not allowance.can_scan:
                audit("scan.quota", f"{where} (monthly limit)")
                notice("No checks left this month. The limit starts again on the first.", "error")
            elif svc.jobs.busy():
                notice("The scanner is busy. Try again in a minute.", "error")
            elif not svc.scan_limiter.allow(f"user:{user['id']}"):
                audit("scan.quota", f"{where} (hourly limit)")
                notice(
                    "Hourly limit reached (%(n)s checks). Try again later.",
                    "error",
                    n=svc.scan_limiter.limit,
                )
            else:
                public_id = secrets.token_urlsafe(12)
                svc.store.create_scan(
                    public_id, user["id"], target.host, target.port, target.ip, chosen
                )
                audit("scan.started", f"{where} ({target.ip}); {', '.join(chosen)}")
                store, login, user_id = svc.store, user["login"], user["id"]

                def done(scan_id: str, outcome: str) -> None:
                    store.add_event(
                        "scan.finished", user_id=user_id, login=login, detail=f"{where}: {outcome}"
                    )

                svc.jobs.submit(
                    public_id,
                    target,
                    _chosen_standards(chosen),
                    current_app.config["SCAN_FN"],
                    done,
                )
                return redirect(url_for("account.report_page", public_id=public_id))

    return render_template(
        "scan.html",
        form={"target": target_text, "standards": chosen},
        standards=list(svc.standards.values()),
        allowance=allowance,
    )


def _owned_scan(public_id: str) -> dict[str, Any]:
    found = services().store.scan(public_id)
    user = _me()
    # Reports of other accounts answer exactly like reports that do not exist.
    if found is None or (found["user_id"] != user["id"] and not is_admin()):
        abort(404)
    return found


def _report_of(scan_row: dict[str, Any]) -> dict[str, Any]:
    if scan_row["status"] != "done" or scan_row["observation"] is None:
        abort(404)
    standards = _chosen_standards(scan_row["standards"]) or defaults(services().standards)
    return report.build(scan_row["observation"], standards)


@bp.get("/reports")
@login_required
def reports() -> str:
    svc = services()
    user = _me()
    page = page_number()
    rows = svc.store.scans(user_id=user["id"], limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE)
    total = svc.store.count_scans(user_id=user["id"])
    return render_template(
        "reports.html",
        scans=rows,
        page=page,
        pages=max(1, -(-total // PAGE_SIZE)),
        allowance=_allowance(user),
        report_days=current_app.config["REPORT_RETENTION_DAYS"],
    )


@bp.get("/reports/<public_id>")
@login_required
def report_page(public_id: str) -> ResponseReturnValue:
    row = _owned_scan(public_id)
    if row["status"] in ("queued", "running"):
        return render_template("pending.html", scan=row)
    if row["status"] == "error":
        return render_template(
            "error.html",
            message=tr("The check could not be completed."),
            detail=row["error"],
            code=None,
        )
    return render_template("report.html", r=_report_of(row), demo=None, scan=row)


@bp.get("/reports/<public_id>.json")
@login_required
def report_json(public_id: str) -> Response:
    return json_download(_report_of(_owned_scan(public_id)), f"tls-audit-{public_id}.json")


@bp.get("/reports/<public_id>.sarif")
@login_required
def report_sarif(public_id: str) -> Response:
    rep = _report_of(_owned_scan(public_id))
    return json_download(sarif.build(rep), f"tls-audit-{public_id}.sarif")


@bp.post("/reports/<public_id>/delete")
@login_required
def report_delete(public_id: str) -> ResponseReturnValue:
    row = _owned_scan(public_id)
    services().store.delete_scan(public_id)
    audit("report.deleted", f"{row['host']}:{row['port']}")
    notice("The report was deleted.", "ok")
    return redirect(url_for("account.reports"))


@bp.route("/account", methods=["GET", "POST"])
@login_required
def account() -> ResponseReturnValue:
    svc = services()
    user = _me()
    if request.method == "POST":
        action = request.form.get("action", "")
        current = request.form.get("current", "")
        if not security.verify_password(current, user["password_hash"]):
            audit("account.denied", f"wrong current password ({action})")
            notice("The current password is wrong.", "error")
        elif action == "password":
            new = request.form.get("password", "")
            problem = security.password_problem(new, user["login"])
            if problem:
                notice(problem, "error", n=security.MIN_PASSWORD)
            elif new != request.form.get("password2", ""):
                notice("The two passwords do not match.", "error")
            else:
                hashed = security.hash_password(new, current_app.config["SCRYPT_N_LOG2"])
                svc.store.update_user(user["id"], password_hash=hashed)
                # Every other session of this account ends here; this one continues.
                flask_session["sv"] = security.session_stamp(hashed)
                audit("account.password")
                notice("The password was changed. Other devices were signed out.", "ok")
                return redirect(url_for("account.account"))
        elif action == "delete":
            if user["role"] == "admin" and svc.store.count_users(role="admin") <= 1:
                notice("The last administrator cannot be deleted.", "error")
            else:
                audit("account.deleted")
                svc.store.delete_user(user["id"])
                flask_session.clear()
                return redirect(url_for("public.index"))
    return render_template(
        "account.html",
        allowance=_allowance(user),
        min_password=security.MIN_PASSWORD,
    )
