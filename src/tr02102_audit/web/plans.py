"""Plans and quotas.

What is sold is one check: one endpoint (host and port) scanned once and
evaluated against any number of standards. Looking at a stored report again
costs nothing, because the measurement is not repeated.

A check costs the operator almost nothing to run, so the price is not about
compute. It is about what the result replaces: the hour an engineer needs to
collect the same evidence by hand for an audit. Quotas keep the service fair
and keep one account from turning the scanner against third parties.
"""

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True, slots=True)
class Plan:
    id: str
    name: str
    price_eur: int  # per month
    checks_per_month: int
    history_days: int  # how long finished reports are kept
    audience: str


PLANS: dict[str, Plan] = {
    "free": Plan("free", "Free", 0, 5, 30, "Try it on your own server."),
    "pro": Plan("pro", "Pro", 19, 200, 180, "For an administrator or a freelance auditor."),
    "business": Plan("business", "Business", 79, 2000, 365, "For a team or an agency."),
}

# Prepaid checks for people who audit once and do not want a subscription.
# They are used after the monthly allowance and do not expire.
CREDIT_PACK_CHECKS = 25
CREDIT_PACK_PRICE_EUR = 9

HOURLY_LIMIT = 30  # checks per account and hour, whatever the plan


def plan_of(user: dict[str, object]) -> Plan:
    return PLANS.get(str(user.get("plan")), PLANS["free"])


def month_start(now: datetime | None = None) -> int:
    """Unix time of the first second of the current calendar month (UTC)."""
    now = now or datetime.now(UTC)
    return int(now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp())


@dataclass(frozen=True, slots=True)
class Allowance:
    unlimited: bool
    used: int
    included: int
    credits: int

    @property
    def left_this_month(self) -> int:
        return max(0, self.included - self.used)

    @property
    def can_scan(self) -> bool:
        return self.unlimited or self.left_this_month > 0 or self.credits > 0


def allowance(user: dict[str, object], used_this_month: int) -> Allowance:
    plan = plan_of(user)
    credits = user.get("credits")
    return Allowance(
        unlimited=user.get("role") == "admin",
        used=used_this_month,
        included=plan.checks_per_month,
        credits=int(credits) if isinstance(credits, int) else 0,
    )
