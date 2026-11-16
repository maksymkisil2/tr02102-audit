"""Buying a plan or a pack of checks, and the webhook Stripe reports to."""

from typing import Any

from flask import Blueprint, Response, abort, current_app, redirect, request, url_for
from flask.typing import ResponseReturnValue

from tr02102_audit.web import plans
from tr02102_audit.web.billing import BillingError
from tr02102_audit.web.common import audit, current_user, login_required, notice, services

bp = Blueprint("billing", __name__, url_prefix="/billing")

ACTIVE = ("active", "trialing", "past_due")  # Stripe keeps retrying a past_due invoice


@bp.post("/checkout")
@login_required
def checkout() -> ResponseReturnValue:
    svc = services()
    user = current_user()
    product = request.form.get("product", "")
    if user is None or product not in ("pro", "business", "credits"):
        abort(400)
    if not current_app.config["BILLING_READY"]() or not svc.stripe.sells(product):
        notice("Card payment is not available on this instance yet.", "error")
        return redirect(url_for("public.pricing"))
    try:
        url = svc.stripe.checkout_url(
            product=product,
            user=user,
            success_url=url_for("account.account", paid="1", _external=True),
            cancel_url=url_for("public.pricing", _external=True),
            credits=plans.CREDIT_PACK_CHECKS if product == "credits" else 0,
        )
    except BillingError as exc:
        audit("billing.error", f"checkout {product}: {exc}")
        notice("The payment page could not be opened. Try again later.", "error")
        return redirect(url_for("public.pricing"))
    audit("billing.checkout", product)
    return redirect(url, code=303)


@bp.post("/portal")
@login_required
def portal() -> ResponseReturnValue:
    svc = services()
    user = current_user()
    if user is None or not user.get("stripe_customer_id") or not svc.stripe.enabled:
        abort(400)
    try:
        url = svc.stripe.portal_url(
            customer_id=str(user["stripe_customer_id"]),
            return_url=url_for("account.account", _external=True),
        )
    except BillingError as exc:
        audit("billing.error", f"portal: {exc}")
        notice("The payment page could not be opened. Try again later.", "error")
        return redirect(url_for("account.account"))
    return redirect(url, code=303)


def _apply(event: dict[str, Any]) -> str:
    """Change an account according to a verified Stripe event. Returns a log line."""
    svc = services()
    store = svc.store
    kind = str(event.get("type", ""))
    obj = (event.get("data") or {}).get("object") or {}
    customer = str(obj.get("customer") or "")

    if kind == "checkout.session.completed":
        reference = str(obj.get("client_reference_id") or "")
        user = store.user(int(reference)) if reference.isdigit() else None
        if user is None:
            return f"{kind}: no account for reference {reference!r}"
        meta = obj.get("metadata") or {}
        product = str(meta.get("product") or "")
        if customer:
            store.update_user(user["id"], stripe_customer_id=customer)
        if obj.get("mode") == "subscription" and product in plans.PLANS and product != "free":
            store.update_user(
                user["id"], plan=product, stripe_subscription_id=str(obj.get("subscription") or "")
            )
            return f"{kind}: {user['login']} is now on {product}"
        if obj.get("mode") == "payment" and obj.get("payment_status") == "paid":
            amount = plans.CREDIT_PACK_CHECKS if product == "credits" else 0
            if amount:
                store.add_credits(user["id"], amount)
            return f"{kind}: {user['login']} bought {amount} checks"
        return f"{kind}: nothing to do"

    if kind in ("customer.subscription.updated", "customer.subscription.deleted"):
        user = store.user_by_stripe(customer=customer, subscription=str(obj.get("id") or ""))
        if user is None:
            return f"{kind}: no account for customer {customer!r}"
        status = str(obj.get("status") or "")
        if kind.endswith("deleted") or status not in ACTIVE:
            store.update_user(user["id"], plan="free", stripe_subscription_id=None)
            return f"{kind}: {user['login']} is back on free ({status or 'deleted'})"
        items = ((obj.get("items") or {}).get("data")) or [{}]
        price = str((items[0].get("price") or {}).get("id") or "")
        plan = svc.stripe.plan_for_price(price)
        if plan and plan != user["plan"]:
            store.update_user(user["id"], plan=plan)
            return f"{kind}: {user['login']} switched to {plan}"
        return f"{kind}: {user['login']} unchanged ({status})"

    return f"{kind}: ignored"


@bp.post("/webhook")
def webhook() -> ResponseReturnValue:
    """Called by Stripe, not by a browser: authenticated by its signature (T-24)."""
    svc = services()
    if not svc.stripe.enabled:
        abort(404)
    try:
        event = svc.stripe.verify(
            request.get_data(cache=False), request.headers.get("Stripe-Signature", "")
        )
    except BillingError as exc:
        svc.store.add_event("billing.rejected", ip=request.remote_addr or "", detail=str(exc))
        return Response("invalid signature", status=400, mimetype="text/plain")
    if not svc.store.first_delivery(event["id"]):
        return Response("already processed", status=200, mimetype="text/plain")
    svc.store.add_event("billing.webhook", detail=_apply(event))
    return Response("ok", status=200, mimetype="text/plain")
