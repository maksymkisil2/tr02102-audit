"""Card payments through Stripe Checkout.

Card data never touches this application: the customer pays on a page hosted
by Stripe, and Stripe reports the outcome with a signed webhook. That keeps
the service out of scope for most of PCI DSS (SAQ A).

The integration talks to Stripe's REST API directly. It needs three calls,
which is not worth a dependency. Everything stays switched off until the
operator sets STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET.
"""

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

API = "https://api.stripe.com/v1"
SIGNATURE_TOLERANCE_S = 300

# (method, url, form fields, secret key) -> decoded JSON. Tests replace it.
HttpFn = Callable[[str, str, Mapping[str, str], str], dict[str, Any]]


class BillingError(RuntimeError):
    """Stripe refused a request, or a webhook did not verify."""


def _http(method: str, url: str, fields: Mapping[str, str], secret_key: str) -> dict[str, Any]:
    request = urllib.request.Request(  # noqa: S310 - fixed https URL, see API above
        url,
        data=urllib.parse.urlencode(fields).encode(),
        method=method,
        headers={
            "Authorization": f"Bearer {secret_key}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
            data: dict[str, Any] = json.loads(response.read())
            return data
    except urllib.error.HTTPError as exc:
        raise BillingError(f"Stripe answered with HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise BillingError(f"Stripe could not be reached: {exc.__class__.__name__}") from exc


@dataclass(slots=True)
class Stripe:
    secret_key: str = ""
    webhook_secret: str = ""
    prices: dict[str, str] = field(default_factory=dict)  # "pro", "business", "credits"
    http: HttpFn = _http

    @property
    def enabled(self) -> bool:
        return bool(self.secret_key and self.webhook_secret)

    def sells(self, product: str) -> bool:
        return self.enabled and bool(self.prices.get(product))

    def plan_for_price(self, price_id: str) -> str | None:
        for product, configured in self.prices.items():
            if configured == price_id and product != "credits":
                return product
        return None

    def checkout_url(
        self,
        *,
        product: str,
        user: Mapping[str, Any],
        success_url: str,
        cancel_url: str,
        credits: int = 0,
    ) -> str:
        """Create a Checkout Session and return the address of the payment page."""
        if not self.sells(product):
            raise BillingError("this product is not for sale on this instance")
        subscription = product != "credits"
        fields = {
            "mode": "subscription" if subscription else "payment",
            "line_items[0][price]": self.prices[product],
            "line_items[0][quantity]": "1",
            "client_reference_id": str(user["id"]),
            "success_url": success_url,
            "cancel_url": cancel_url,
            "metadata[product]": product,
            "metadata[credits]": str(credits),
        }
        if user.get("stripe_customer_id"):
            fields["customer"] = str(user["stripe_customer_id"])
        elif "@" in str(user["login"]):
            fields["customer_email"] = str(user["login"])
        session = self.http("POST", f"{API}/checkout/sessions", fields, self.secret_key)
        url = session.get("url")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise BillingError("Stripe did not return a payment page")
        return url

    def portal_url(self, *, customer_id: str, return_url: str) -> str:
        """Address of Stripe's page for changing or cancelling a subscription."""
        fields = {"customer": customer_id, "return_url": return_url}
        session = self.http("POST", f"{API}/billing_portal/sessions", fields, self.secret_key)
        url = session.get("url")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise BillingError("Stripe did not return a portal page")
        return url

    def verify(self, payload: bytes, header: str, now: float | None = None) -> dict[str, Any]:
        """Check the Stripe-Signature header and return the event (threat T-24).

        The header reads ``t=<unix time>,v1=<hex hmac>[,v1=...]``. The MAC is
        HMAC-SHA256 over ``"<t>.<payload>"`` with the endpoint's secret. Old
        timestamps are refused, so a captured webhook cannot be replayed.
        """
        if not self.webhook_secret:
            raise BillingError("webhooks are not configured")
        timestamp = ""
        candidates: list[str] = []
        for part in header.split(","):
            name, _, value = part.strip().partition("=")
            if name == "t":
                timestamp = value
            elif name == "v1":
                candidates.append(value)
        if not timestamp.isdigit() or not candidates:
            raise BillingError("malformed signature header")
        signed = timestamp.encode() + b"." + payload
        expected = hmac.new(self.webhook_secret.encode(), signed, hashlib.sha256).hexdigest()
        if not any(hmac.compare_digest(expected, c) for c in candidates):
            raise BillingError("signature does not match")
        if abs((now if now is not None else time.time()) - int(timestamp)) > SIGNATURE_TOLERANCE_S:
            raise BillingError("signature is too old")
        try:
            event = json.loads(payload)
        except ValueError as exc:
            raise BillingError("payload is not JSON") from exc
        if not isinstance(event, dict) or not isinstance(event.get("id"), str):
            raise BillingError("payload is not an event")
        return event


def sign(payload: bytes, secret: str, timestamp: int | None = None) -> str:
    """Build a Stripe-Signature header. Used by the tests and for local trials."""
    stamp = str(int(time.time()) if timestamp is None else timestamp)
    mac = hmac.new(secret.encode(), stamp.encode() + b"." + payload, hashlib.sha256).hexdigest()
    return f"t={stamp},v1={mac}"
