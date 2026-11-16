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
from tr02102_audit.web import plans, security
from tr02102_audit.web.common import (
    PAGE_SIZE,
    audit,
    current_user,
    is_admin,
    login_required,
    notice,
    page_number,
    services,
)
from tr02102_audit.web.views_public import json_download

bp = Blueprint("account", __name__)


def _me() -> dict[str, Any]:
    user = current_user()
    if user is None:  # login_required runs first; this only narrows the type
        abort(401)
    return user


def _allowance(user: dict[str, Any]) -> plans.Allowance:
    used = services().store.count_scans(user_id=user["id"], since=plans.month_start())
    return plans.allowance(user, used)


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
        error = ""
        try:
            if not chosen:
                raise TargetError("choose at least one standard")
            if request.form.get("authorised") != "yes":
                raise TargetError("confirm that you are authorised to test this server")
            host, port = parse_target(target_text)
            target = resolve(host, port, allow_private=current_app.config["ALLOW_PRIVATE_TARGETS"])
        except TargetError as exc:
            error = str(exc)
            # Refused targets are logged: probing for private addresses is
            # what an attack on the scanner itself looks like (threat T-14).
            audit("scan.rejected", f"{target_text[:120]}: {error}")
            notice(error[:1].upper() + error[1:] + ".", "error")
        if not error:
            if not allowance.can_scan:
                audit("scan.quota", f"{host}:{port}")
                notice("No checks left this month. See the plans for more.", "error")
            elif svc.jobs.busy():
                notice("The scanner is busy. Try again in a minute.", "error")
            elif not svc.scan_limiter.allow(f"user:{user['id']}"):
                audit("scan.quota", f"{host}:{port} (hourly limit)")
                notice(
                    "Hourly limit reached (%(n)s checks). Try again later.",
                    "error",
                    n=plans.HOURLY_LIMIT,
                )
            elif (
                not allowance.unlimited
                and allowance.left_this_month == 0
                and not svc.store.spend_credit(user["id"])
            ):
                notice("No checks left this month. See the plans for more.", "error")
            else:
                public_id = secrets.token_urlsafe(12)
                svc.store.create_scan(public_id, user["id"], host, port, target.ip, chosen)
                audit("scan.started", f"{host}:{port} ({target.ip}); {', '.join(chosen)}")
                store, login, user_id = svc.store, user["login"], user["id"]

                def done(scan_id: str, outcome: str) -> None:
                    store.add_event(
                        "scan.finished",
                        user_id=user_id,
                        login=login,
                        detail=f"{host}:{port}: {outcome}",
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
        plan=plans.plan_of(user),
    )


@bp.get("/reports/<public_id>")
@login_required
def report_page(public_id: str) -> ResponseReturnValue:
    row = _owned_scan(public_id)
    if row["status"] in ("queued", "running"):
        return render_template("pending.html", scan=row)
    if row["status"] == "error":
        return render_template("error.html", message=row["error"], code=None), 500
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
        plan=plans.plan_of(user),
        min_password=security.MIN_PASSWORD,
        stripe_enabled=svc.stripe.enabled,
    )
