"""Passwords, rate limiting and the address a request comes from."""

import time

import pytest
from flask import Flask, request

from tr02102_audit.web import quota, security
from tr02102_audit.web.views_admin import _column, _limit_from_form, _nice_ceiling

COST = 10  # fast; production uses 15


def test_password_hash_roundtrip_and_salt() -> None:
    first = security.hash_password("correct horse", COST)
    second = security.hash_password("correct horse", COST)
    assert first != second, "every hash has its own salt"
    assert first.startswith("scrypt$10$8$3$")
    assert "correct horse" not in first
    assert security.verify_password("correct horse", first)
    assert not security.verify_password("correct horse ", first)
    assert not security.verify_password("", first)


def test_production_cost_follows_the_owasp_parameters() -> None:
    assert (security.SCRYPT_N_LOG2, security.SCRYPT_R, security.SCRYPT_P) == (15, 8, 3)
    assert security.hash_password("x" * 12).startswith("scrypt$15$8$3$")


@pytest.mark.parametrize(
    "stored",
    [
        "",
        "plain text",
        "scrypt$10$8$3$only-five-fields",
        "md5$10$8$3$c2FsdA==$a2V5",
        "scrypt$30$8$3$c2FsdA==$a2V5",  # a cost that would exhaust memory
        "scrypt$10$8$99$c2FsdA==$a2V5",
        "scrypt$x$8$3$c2FsdA==$a2V5",
        "scrypt$10$8$3$not base64$a2V5",
    ],
)
def test_malformed_or_hostile_hashes_never_verify(stored: str) -> None:
    assert not security.verify_password("anything", stored)


def test_password_rules() -> None:
    assert security.password_problem("short") == "The password needs at least %(n)s characters."
    assert security.password_problem("x" * 201) == "The password is too long."
    assert (
        security.password_problem("Anna@Example.org", "anna@example.org")
        == "The password must differ from the login name."
    )
    assert security.password_problem("a long enough passphrase", "anna") is None


def test_session_stamp_changes_with_the_password() -> None:
    one = security.hash_password("first password", COST)
    two = security.hash_password("second password", COST)
    assert security.session_stamp(one) == security.session_stamp(one)
    assert security.session_stamp(one) != security.session_stamp(two)


def test_unknown_login_names_are_shortened_for_the_log() -> None:
    assert security.mask_login("hunter2-is-my-password") == "hu… (22 characters)"
    assert security.mask_login("  ") == "(empty)"


def test_rate_limiter_counts_per_key_and_forgets(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    limiter = security.RateLimiter(limit=2, window_s=60)
    assert limiter.peek("a"), "peeking does not count"
    assert limiter.allow("a") and limiter.allow("a")
    assert not limiter.allow("a") and not limiter.peek("a")
    assert limiter.allow("b"), "another key has its own count"
    now[0] += 61
    assert limiter.peek("a") and limiter.allow("a")


def test_visitor_address_comes_from_the_header_only_when_configured() -> None:
    app = Flask(__name__)
    headers = {"CF-Connecting-IP": "203.0.113.7, 10.0.0.1", "CF-IPCountry": "de"}
    with app.test_request_context(headers=headers, environ_base={"REMOTE_ADDR": "198.51.100.1"}):
        assert security.client_ip(request, "") == "198.51.100.1"
        assert security.client_ip(request, "CF-Connecting-IP") == "203.0.113.7"
        assert security.client_ip(request, "X-Missing") == "198.51.100.1"
        assert security.client_country(request, trusted=True) == "DE"
        assert security.client_country(request, trusted=False) == ""
    hostile = {"CF-Connecting-IP": "<script>", "CF-IPCountry": "Germany"}
    with app.test_request_context(headers=hostile, environ_base={"REMOTE_ADDR": "198.51.100.1"}):
        assert security.client_ip(request, "CF-Connecting-IP") == "198.51.100.1"
        assert security.client_country(request, trusted=True) == ""


def test_allowance() -> None:
    user = {"role": "user", "monthly_limit": None}
    assert quota.allowance(user, 3, 50).left == 47
    assert quota.allowance(user, 50, 50).can_scan is False
    assert quota.allowance(user, 99, 50).left == 0
    assert quota.allowance({"role": "user", "monthly_limit": 5}, 4, 50).left == 1
    assert quota.allowance({"role": "user", "monthly_limit": 0}, 0, 50).can_scan is False
    admin = quota.allowance({"role": "admin", "monthly_limit": 0}, 500, 50)
    assert admin.unlimited and admin.can_scan


def test_limit_typed_by_an_administrator() -> None:
    assert _limit_from_form("") is None
    assert _limit_from_form(" 25 ") == 25
    assert _limit_from_form("999999999") == quota.MAX_MONTHLY_LIMIT
    for text in ("-1", "1.5", "ten", "٣"):
        with pytest.raises(ValueError, match="whole number"):
            _limit_from_form(text)


def test_chart_axis_and_columns() -> None:
    assert [_nice_ceiling(n) for n in (1, 2, 3, 7, 10, 11, 49, 180)] == [
        1,
        2,
        5,
        10,
        10,
        20,
        50,
        200,
    ]
    assert _column(10.0, 0, 10) == ""
    full = _column(10.0, 10, 10)
    assert full.startswith("M10.0,204 V") and full.endswith("V204 Z")
