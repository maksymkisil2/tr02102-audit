"""The servers an account keeps an eye on: history, a new check, before and after.

A saved server is an address plus the standards to check it against. Its
history is every check of that address by the same account, saved or not.
Two checks of a history can be compared, which is how the effect of a change
to a server's configuration becomes visible.
"""

from typing import Any

from flask import Blueprint, abort, current_app, redirect, render_template, request, url_for
from flask.typing import ResponseReturnValue

from tr02102_audit import compare
from tr02102_audit.web import reporting
from tr02102_audit.web.common import audit, current_user, is_admin, login_required, notice, services
from tr02102_audit.web.views_account import owned_scan, report_of, start_scan

bp = Blueprint("servers", __name__)


def _me() -> dict[str, Any]:
    user = current_user()
    if user is None:  # login_required runs first; this only narrows the type
        abort(401)
    return user


def _owned_target(target_id: int) -> dict[str, Any]:
    found = services().store.target(target_id)
    if found is None or (found["user_id"] != _me()["id"] and not is_admin()):
        abort(404)
    return found


@bp.get("/servers")
@login_required
def servers() -> str:
    return render_template(
        "servers.html", targets=services().store.targets(user_id=_me()["id"]), mine=True
    )


@bp.route("/servers/<int:target_id>", methods=["GET", "POST"])
@login_required
def server(target_id: int) -> ResponseReturnValue:
    svc = services()
    target = _owned_target(target_id)
    if request.method == "POST":
        label = request.form.get("label", "").strip()[:80]
        chosen = [s for s in request.form.getlist("standard") if s in svc.standards]
        if not chosen:
            notice("Choose at least one standard.", "error")
        else:
            svc.store.save_target(
                target["user_id"], target["host"], target["port"], label=label, standards=chosen
            )
            notice("Saved.", "ok")
        return redirect(url_for("servers.server", target_id=target_id))
    history = svc.store.endpoint_scans(target["user_id"], target["host"], target["port"])
    done = [h for h in history if h["status"] == "done"]
    return render_template(
        "server.html",
        target=target,
        history=history,
        trend=list(reversed(done[:12])),
        standards=list(svc.standards.values()),
        can_compare=len(done) >= 2,
    )


@bp.post("/servers/<int:target_id>/check")
@login_required
def check(target_id: int) -> ResponseReturnValue:
    target = _owned_target(target_id)
    user = _me()
    if target["user_id"] != user["id"]:
        abort(404)  # an administrator checks a server as its owner never
    public_id = start_scan(
        user,
        f"{target['host']}:{target['port']}",
        [s for s in target["standards"] if s in services().standards]
        or [s.id for s in services().standards.values() if s.default],
    )
    if public_id is None:
        return redirect(url_for("servers.server", target_id=target_id))
    return redirect(url_for("account.report_page", public_id=public_id))


@bp.post("/servers/<int:target_id>/delete")
@login_required
def delete(target_id: int) -> ResponseReturnValue:
    target = _owned_target(target_id)
    services().store.delete_target(target_id)
    audit("server.removed", f"{target['host']}:{target['port']}")
    notice("The server was removed from the list. Its reports stay.", "ok")
    return redirect(url_for("servers.servers"))


@bp.get("/compare")
@login_required
def compare_page() -> ResponseReturnValue:
    first, second = request.args.get("a", ""), request.args.get("b", "")
    if not first or not second:
        abort(404)
    rows = [owned_scan(first[:40]), owned_scan(second[:40])]
    rows.sort(key=lambda r: r["created_at"])  # always "before" to "after"
    old, new = rows
    if old["public_id"] == new["public_id"]:
        notice("Choose two different checks.", "error")
        return redirect(url_for("account.report_page", public_id=old["public_id"]))
    before, after = report_of(old), report_of(new)
    return render_template(
        "compare.html",
        old=old,
        new=new,
        diff=compare.compare(before, after),
        same_endpoint=(old["host"], old["port"]) == (new["host"], new["port"]),
        target=services().store.target_by_endpoint(new["user_id"], new["host"], new["port"]),
        formats=reporting.FORMATS,
        retention=current_app.config["REPORT_RETENTION_DAYS"],
    )
