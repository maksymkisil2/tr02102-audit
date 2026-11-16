"""Passwords, rate limiting and the address a request really comes from."""

import base64
import hashlib
import hmac
import ipaddress
import os
import re
import threading
import time
from collections import defaultdict, deque

from flask import Request

# scrypt with N=2^15, r=8, p=3: one of the parameter sets OWASP lists for
# password storage. One hash needs 32 MiB of memory, so only two may run at
# a time; a burst of login attempts cannot exhaust a small instance (T-23).
SCRYPT_N_LOG2 = 15
SCRYPT_R = 8
SCRYPT_P = 3
_hash_slots = threading.BoundedSemaphore(2)

MIN_PASSWORD = 10
MAX_PASSWORD = 200
LOGIN_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._+@-]{2,119}$")
_COUNTRY = re.compile(r"^[A-Z0-9]{2}$")


def _scrypt(password: str, salt: bytes, n_log2: int, r: int, p: int) -> bytes:
    with _hash_slots:
        return hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=1 << n_log2,
            r=r,
            p=p,
            maxmem=256 * r * (1 << n_log2),
            dklen=32,
        )


def hash_password(password: str, n_log2: int = SCRYPT_N_LOG2) -> str:
    salt = os.urandom(16)
    key = _scrypt(password, salt, n_log2, SCRYPT_R, SCRYPT_P)
    encode = base64.b64encode
    return f"scrypt${n_log2}${SCRYPT_R}${SCRYPT_P}${encode(salt).decode()}${encode(key).decode()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check. A malformed or oversized hash never verifies."""
    try:
        scheme, n_log2, r, p, salt, key = stored.split("$")
        cost = (int(n_log2), int(r), int(p))
        if scheme != "scrypt" or not (10 <= cost[0] <= 17 and cost[1] == 8 and 1 <= cost[2] <= 4):
            return False
        expected = base64.b64decode(key)
        actual = _scrypt(password[:MAX_PASSWORD], base64.b64decode(salt), *cost)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def password_problem(password: str, login: str = "") -> str | None:
    """Why a new password is not acceptable, or None."""
    if len(password) < MIN_PASSWORD:
        return "The password needs at least %(n)s characters."
    if len(password) > MAX_PASSWORD:
        return "The password is too long."
    if login and password.lower() == login.lower():
        return "The password must differ from the login name."
    return None


def session_stamp(password_hash: str) -> str:
    """Changes with the password, which signs out every older session."""
    return hashlib.sha256(password_hash.encode()).hexdigest()[:16]


def mask_login(text: str) -> str:
    """Shorten a login name nobody owns before it is written to the audit log.

    People type passwords into the wrong field. Keeping only the first two
    characters still shows what an attacker is guessing ("ad…", "ro…").
    """
    text = text.strip()
    if not text:
        return "(empty)"
    return f"{text[:2]}… ({len(text)} characters)"


class RateLimiter:
    """Sliding-window counter per key. In memory: one process, one instance."""

    def __init__(self, limit: int, window_s: float) -> None:
        self.limit = limit
        self.window = window_s
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def peek(self, key: str) -> bool:
        """True if another attempt would be allowed; does not count as one."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits.get(key)
            if not hits:
                return True
            while hits and now - hits[0] > self.window:
                hits.popleft()
            return len(hits) < self.limit

    def allow(self, key: str) -> bool:
        """Count one attempt; False if the limit is already reached."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            if len(self._hits) > 20_000:  # forget idle keys before memory grows
                for name in [k for k, v in self._hits.items() if not v]:
                    del self._hits[name]
            return True


def client_ip(request: Request, header: str) -> str:
    """The visitor's address.

    Behind a proxy the TCP peer is the proxy. ``header`` names the request
    header in which the platform passes the real address (Render and
    Cloudflare: CF-Connecting-IP). It is only read when the operator
    configured it, because a client can send any header it likes to a
    service that is reachable directly.
    """
    if header:
        value = request.headers.get(header, "").split(",")[0].strip()
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            pass
    return request.remote_addr or ""


def client_country(request: Request, trusted: bool) -> str:
    """Two-letter country code supplied by the platform, if any."""
    if not trusted:
        return ""
    value = request.headers.get("CF-IPCountry", "").strip().upper()
    return value if _COUNTRY.match(value) and value != "XX" else ""
