"""Fair-use limits.

The unit is one check: one endpoint (host and port) measured once and
evaluated against any number of standards. Looking at a stored report again
costs nothing, because nothing is measured again.

Limits keep the service fair and keep one account from turning the scanner
against third parties. Every account has a monthly limit: the instance
default, or the number an administrator set for that account. Administrators
have no monthly limit. The hourly limit applies to everybody.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

DEFAULT_MONTHLY_LIMIT = 50
MAX_MONTHLY_LIMIT = 100_000
HOURLY_LIMIT = 30  # checks per account and hour


def month_start(now: datetime | None = None) -> int:
    """Unix time of the first second of the current calendar month (UTC)."""
    now = now or datetime.now(UTC)
    return int(now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp())


@dataclass(frozen=True, slots=True)
class Allowance:
    unlimited: bool
    used: int
    included: int

    @property
    def left(self) -> int:
        return max(0, self.included - self.used)

    @property
    def can_scan(self) -> bool:
        return self.unlimited or self.left > 0


def monthly_limit(user: dict[str, Any], default: int) -> int:
    """The account's own limit if an administrator set one, else the default."""
    own = user.get("monthly_limit")
    return int(own) if isinstance(own, int) and own >= 0 else default


def allowance(user: dict[str, Any], used_this_month: int, default: int) -> Allowance:
    return Allowance(
        unlimited=user.get("role") == "admin",
        used=used_this_month,
        included=monthly_limit(user, default),
    )
