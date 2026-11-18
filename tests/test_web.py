"""Web interface: accounts, roles, limits, the audit log, languages, headers."""

import re
import time
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient

from tests.conftest import (
    ADMIN,
    ADMIN_PASSWORD,
    USER_PASSWORD,
    AppFactory,
    add_user,
    csrf,
    events,
    post,
    services,
    sign_in,
    start_scan,
    text,
    wait_for_event,
    wait_for_report,
)
from tr02102_audit.web.store import StoreError

PUBLIC_PAGES = (
    "/",
    "/standards",
    "/legal/imprint",
    "/legal/privacy",
    "/legal/terms",
    "/demo/tls-weak",
    "/demo/tls-typical",
    "/demo/tls-good",
    "/login",
    "/register",
)
ACCOUNT_PAGES = ("/scan", "/reports", "/account")
ADMIN_PAGES = ("/admin", "/admin/events", "/admin/scans", "/admin/users", "/admin/users/1")


def user_client(app: Flask, login: str = "anna@example.org") -> FlaskClient:
    add_user(app, login)
    client = app.test_client()
    assert sign_in(client, login, USER_PASSWORD).status_code == 302
    return client


# ------------------------------------------------------------ pages and headers


def test_public_pages_render_in_every_language(client: FlaskClient) -> None:
    for lang in ("en", "de", "uk"):
        for path in PUBLIC_PAGES:
            resp = client.get(f"{path}?lang={lang}")
            assert resp.status_code == 200, (path, lang)
            assert f'<html lang="{lang}">' in text(resp)


def test_security_headers_and_no_script_anywhere(client: FlaskClient) -> None:
    sign_in(client)
    for path in (*PUBLIC_PAGES, *ACCOUNT_PAGES, *ADMIN_PAGES):
        resp = client.get(path, follow_redirects=True)
        assert resp.headers["Content-Security-Policy"] == (
            "default-src 'none'; style-src 'self'; img-src 'self' data:; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["Referrer-Policy"] == "no-referrer"
        assert resp.headers["Cache-Control"] == "no-store"
        html = text(resp).lower()
        assert "<script" not in html, path
        assert " onclick=" not in html and "javascript:" not in html, path


def test_static_files_may_be_cached_and_health_check_needs_no_session(client: FlaskClient) -> None:
    assert client.get("/static/app.css").headers.get("Cache-Control") != "no-store"
    health = client.get("/healthz")
    assert health.get_json()["status"] == "ok"
    assert "Set-Cookie" not in health.headers


def test_unknown_page_is_a_translated_404(client: FlaskClient) -> None:
    resp = client.get("/nope?lang=de")
    assert resp.status_code == 404
    assert "Diese Seite gibt es nicht." in text(resp)


def test_demo_reports_are_downloadable_as_json_and_sarif(client: FlaskClient) -> None:
    assert client.get("/demo/tls-weak.json").get_json()["observation"]["facts"]["tls"]
    log = client.get("/demo/tls-weak.sarif").get_json()
    assert log["version"] == "2.1.0"
    assert log["runs"][0]["results"], "the weak demo server must produce findings"
    assert client.get("/demo/nope").status_code == 404
    assert client.get("/demo/nope.sarif").status_code == 404


def test_instance_without_an_administrator_only_shows_samples(make_app: AppFactory) -> None:
    client = make_app(APP_PASSWORD="").test_client()
    assert "Checking is switched off on this instance" in text(client.get("/"))
    assert "Checking is switched off on this instance" in text(client.get("/login"))
    assert client.get("/demo/tls-weak").status_code == 200
    assert client.get("/scan").status_code == 302


def test_unreachable_database_is_a_plain_503(
    app: Flask, client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def down(*args: object, **kwargs: object) -> None:
        raise StoreError("database error: OperationalError")

    monkeypatch.setattr(services(app).store.db, "_run", down)
    resp = client.get("/")
    assert resp.status_code == 503
    assert resp.headers["Retry-After"] == "30"
    assert "cannot be reached" in text(resp) and "OperationalError" not in text(resp)
    assert client.get("/healthz").status_code == 200


# --------------------------------------------------------------------- sign-in


def test_pages_behind_the_login_redirect_to_it(client: FlaskClient) -> None:
    for path in (*ACCOUNT_PAGES, *ADMIN_PAGES):
        resp = client.get(path)
        assert resp.status_code == 302, path
        assert resp.headers["Location"] == f"/login?next={path}"
    assert client.post("/scan", data={"target": "1.1.1.1"}).status_code == 400  # no CSRF token


def test_administrator_from_app_password_can_sign_in(app: Flask, client: FlaskClient) -> None:
    resp = sign_in(client)
    assert resp.status_code == 302 and resp.headers["Location"] == "/scan"
    assert client.get("/admin").status_code == 200
    event = events(app, "login.ok")[0]
    assert event["login"] == ADMIN and event["ip"] == "127.0.0.1"
    admin = services(app).store.user_by_login(ADMIN)
    assert admin is not None and admin["last_login_at"]


def test_wrong_password_and_unknown_login_get_the_same_answer(
    app: Flask, client: FlaskClient
) -> None:
    wrong = text(sign_in(client, ADMIN, "not the password"))
    unknown = text(sign_in(client, "my-real-password-typed-here", "x"))
    assert "Wrong login name or password." in wrong
    assert "Wrong login name or password." in unknown
    details = {e["detail"]: e["login"] for e in events(app, "login.failed")}
    assert details["wrong password"] == ADMIN
    # A login nobody owns may be a password typed into the wrong field: only
    # its first two characters are written down.
    assert re.fullmatch(r"my… \(27 characters, #[0-9a-f]{4}\)", details["unknown login name"])


def test_failed_sign_ins_are_rate_limited(app: Flask, client: FlaskClient) -> None:
    for _ in range(10):
        sign_in(client, ADMIN, "wrong")
    blocked = sign_in(client)  # even the right password has to wait now
    assert "Too many failed attempts" in text(blocked)
    assert client.get("/scan").status_code == 302
    assert events(app, "login.blocked")


def test_one_address_cannot_lock_an_account_for_everybody(app: Flask) -> None:
    attacker = app.test_client()
    for _ in range(12):
        sign_in(attacker, ADMIN, "wrong")
    assert "Too many failed attempts" in text(sign_in(attacker))
    elsewhere = {"REMOTE_ADDR": "198.51.100.9"}
    owner = app.test_client()
    token = csrf(owner)
    resp = owner.post(
        "/login",
        data={"csrf": token, "login": ADMIN, "password": ADMIN_PASSWORD},
        environ_base=elsewhere,
    )
    assert resp.status_code == 302, "the administrator can still sign in from another address"


def test_many_addresses_guessing_one_login_are_stopped(app: Flask) -> None:
    services(app).account_limiter.limit = 3
    for n in range(3):
        guesser = app.test_client()
        guesser.post(
            "/login",
            data={"csrf": csrf(guesser), "login": ADMIN, "password": "wrong"},
            environ_base={"REMOTE_ADDR": f"198.51.100.{n + 1}"},
        )
    late = app.test_client()
    resp = late.post(
        "/login",
        data={"csrf": csrf(late), "login": ADMIN, "password": ADMIN_PASSWORD},
        environ_base={"REMOTE_ADDR": "198.51.100.200"},
    )
    assert "Too many failed attempts" in text(resp)


def test_language_links_never_point_to_another_site(client: FlaskClient) -> None:
    for path in ("//evil.example", "//evil.example/x", "/\\evil.example"):
        # The path as a server receives it; the test client would otherwise
        # read "//host" as another host.
        resp = client.get("/", environ_overrides={"PATH_INFO": path})
        html = text(resp)
        assert resp.status_code == 404, path
        assert 'href="//' not in html and "evil.example" not in html, path
        assert 'href="/?lang=de"' in html, path
    assert 'href="/standards?lang=uk"' in text(client.get("/standards"))
    assert 'href="/demo/tls-weak?lang=de"' in text(client.get("/demo/tls-weak"))


def test_redirect_after_sign_in_stays_on_this_site(client: FlaskClient) -> None:
    for target in (
        "//evil.example",
        "https://evil.example",
        "/\\evil.example",
        "/%09/evil.example",  # browsers drop the tab: //evil.example
        "/%0a/evil.example",
        "/ /evil.example",
    ):
        fresh = client.application.test_client()
        token = csrf(fresh)
        resp = fresh.post(
            f"/login?next={target}",
            data={"csrf": token, "login": ADMIN, "password": ADMIN_PASSWORD},
        )
        assert resp.headers["Location"] == "/scan", target
    fresh = client.application.test_client()
    resp = fresh.post(
        "/login?next=/reports",
        data={"csrf": csrf(fresh), "login": ADMIN, "password": ADMIN_PASSWORD},
    )
    assert resp.headers["Location"] == "/reports"


def test_forms_without_a_valid_token_are_rejected(client: FlaskClient) -> None:
    assert client.post("/login", data={"login": ADMIN, "password": ADMIN_PASSWORD}).status_code == (
        400
    )
    old_token = csrf(client)
    sign_in(client)
    # Signing in starts a new session, so a token from before is worthless.
    assert client.post("/logout", data={"csrf": old_token}).status_code == 400
    assert client.post("/admin/settings", data={"registration_open": "yes"}).status_code == 400
    assert client.get("/admin").status_code == 200


def test_sign_out_ends_the_session(app: Flask, client: FlaskClient) -> None:
    sign_in(client)
    assert post(client, "/logout", form_page="/").status_code == 302
    assert client.get("/scan").status_code == 302
    assert events(app, "logout")


def test_session_cookie_is_http_only_and_same_site(make_app: AppFactory) -> None:
    client = make_app(SESSION_COOKIE_SECURE=True).test_client()
    cookie = client.get("/login").headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie and "Secure" in cookie


# ---------------------------------------------------------------- registration


def open_registration(app: Flask) -> None:
    admin = app.test_client()
    sign_in(admin)
    resp = post(admin, "/admin/settings", form_page="/admin", registration_open="yes")
    assert resp.status_code == 302
    assert services(app).store.setting("registration_open") == "1"


def test_registration_is_closed_until_an_administrator_opens_it(
    app: Flask, client: FlaskClient
) -> None:
    assert "Registration is closed on this instance" in text(client.get("/register"))
    resp = client.post(
        "/register",
        data={
            "csrf": csrf(client),
            "login": "new@example.org",
            "password": USER_PASSWORD,
            "password2": USER_PASSWORD,
            "terms": "yes",
        },
    )
    assert resp.status_code == 403
    assert services(app).store.user_by_login("new@example.org") is None
    assert events(app, "register.blocked")


def test_open_registration_creates_a_signed_in_user(app: Flask, client: FlaskClient) -> None:
    open_registration(app)
    resp = post(
        client,
        "/register",
        login="New@Example.org",
        password=USER_PASSWORD,
        password2=USER_PASSWORD,
        terms="yes",
    )
    assert resp.status_code == 302 and resp.headers["Location"] == "/scan"
    assert "It includes 50 checks a month." in text(client.get("/scan"))
    user = services(app).store.user_by_login("new@example.org")
    assert user is not None and user["role"] == "user"
    assert not user["password_hash"].startswith(USER_PASSWORD)
    assert client.get("/admin").status_code == 403
    assert events(app, "register")[0]["login"] == "new@example.org"


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"login": "not-an-address"}, "Enter a valid e-mail address."),
        ({"password": "short", "password2": "short"}, "The password needs at least 10 characters."),
        ({"password2": "something else entirely"}, "The two passwords do not match."),
        ({"terms": ""}, "Please accept the terms of use."),
        (
            {"password": "new@example.org", "password2": "new@example.org"},
            "The password must differ from the login name.",
        ),
    ],
)
def test_registration_rejects_incomplete_forms(
    app: Flask, client: FlaskClient, changes: dict[str, str], message: str
) -> None:
    open_registration(app)
    form = {
        "login": "new@example.org",
        "password": USER_PASSWORD,
        "password2": USER_PASSWORD,
        "terms": "yes",
    }
    form.update(changes)
    resp = post(client, "/register", **form)
    assert resp.status_code == 200
    assert message in text(resp)
    assert services(app).store.count_users() == 1


def test_registration_is_limited_per_address_and_refuses_duplicates(app: Flask) -> None:
    open_registration(app)
    form = {"password": USER_PASSWORD, "password2": USER_PASSWORD, "terms": "yes"}
    first = app.test_client()
    assert post(first, "/register", login="one@example.org", **form).status_code == 302
    again = app.test_client()
    assert "already has an account" in text(
        post(again, "/register", login="one@example.org", **form)
    )
    for n in range(3):
        fresh = app.test_client()
        assert post(fresh, "/register", login=f"more{n}@example.org", **form).status_code == 302
    sixth = app.test_client()
    assert "Too many registrations" in text(
        post(sixth, "/register", login="six@example.org", **form)
    )
    assert services(app).store.user_by_login("six@example.org") is None


# ----------------------------------------------------------------------- roles


def test_users_cannot_open_the_administration(app: Flask) -> None:
    client = user_client(app)
    for path in ADMIN_PAGES:
        assert client.get(path).status_code == 403, path
    assert post(
        client, "/admin/settings", form_page="/scan", registration_open="yes"
    ).status_code == (403)
    assert services(app).store.setting("registration_open") != "1"
    assert "Administration" not in text(client.get("/scan"))


def test_administrator_creates_blocks_and_deletes_accounts(app: Flask) -> None:
    user_id = add_user(app)
    admin = app.test_client()
    sign_in(admin)
    page = f"/admin/users/{user_id}"
    user = app.test_client()
    sign_in(user, "anna@example.org", USER_PASSWORD)
    assert user.get("/scan").status_code == 200

    post(admin, page, action="save", blocked="yes", monthly_limit="7")
    stored = services(app).store.user(user_id)
    assert stored is not None and stored["blocked"] == 1 and stored["monthly_limit"] == 7
    assert user.get("/scan").status_code == 302, "a blocked account loses its session"
    assert "Wrong login name or password." in text(sign_in(user, "anna@example.org", USER_PASSWORD))
    assert events(app, "login.failed")[0]["detail"] == "account is blocked"

    post(admin, page, action="save", monthly_limit="")
    stored = services(app).store.user(user_id)
    assert stored is not None and stored["blocked"] == 0 and stored["monthly_limit"] is None
    post(admin, page, action="save", monthly_limit="lots")
    assert "has to be a whole number" in text(admin.get(page))

    post(admin, page, action="delete")
    assert services(app).store.user(user_id) is None
    kinds = {e["kind"] for e in events(app, "admin")}
    assert {"admin.user.created", "admin.user.updated", "admin.user.deleted"} <= kinds


def test_administrator_can_replace_a_password_which_signs_the_user_out(app: Flask) -> None:
    user_id = add_user(app)
    user = app.test_client()
    sign_in(user, "anna@example.org", USER_PASSWORD)
    admin = app.test_client()
    sign_in(admin)
    post(admin, f"/admin/users/{user_id}", action="password", password="a brand new passphrase")
    assert user.get("/scan").status_code == 302
    assert sign_in(user, "anna@example.org", "a brand new passphrase").status_code == 302


def test_last_administrator_cannot_be_removed_blocked_or_demoted(
    app: Flask, client: FlaskClient
) -> None:
    sign_in(client)
    post(client, "/admin/users/1", action="save", blocked="yes")
    post(client, "/admin/users/1", action="save")  # role checkbox not ticked: demotion
    post(client, "/admin/users/1", action="delete")
    admin = services(app).store.user(1)
    assert admin is not None and admin["role"] == "admin" and not admin["blocked"]
    resp = post(client, "/account", action="delete", current=ADMIN_PASSWORD)
    assert "The last administrator cannot be deleted." in text(resp)
    assert client.get("/admin").status_code == 200


def test_admin_form_rejects_bad_login_names_and_duplicates(app: Flask, client: FlaskClient) -> None:
    sign_in(client)
    assert "Login names use letters" in text(
        post(client, "/admin/users", login="a b", password=USER_PASSWORD)
    )
    assert "already taken" in text(
        post(client, "/admin/users", login=ADMIN, password=USER_PASSWORD)
    )
    assert "at least 10 characters" in text(
        post(client, "/admin/users", login="bob", password="short")
    )
    assert services(app).store.count_users() == 1


# --------------------------------------------------------------------- account


def test_changing_the_password_signs_out_other_devices(app: Flask) -> None:
    laptop = user_client(app)
    phone = app.test_client()
    sign_in(phone, "anna@example.org", USER_PASSWORD)
    new = "another long passphrase"

    wrong = post(laptop, "/account", action="password", current="nope", password=new, password2=new)
    assert "The current password is wrong." in text(wrong)
    assert events(app, "account.denied")
    resp = post(
        laptop, "/account", action="password", current=USER_PASSWORD, password=new, password2=new
    )
    assert resp.status_code == 302
    assert laptop.get("/account").status_code == 200, "this device stays signed in"
    assert phone.get("/account").status_code == 302, "the other device does not"
    assert sign_in(phone, "anna@example.org", new).status_code == 302


def test_user_can_delete_the_account_with_its_reports(app: Flask) -> None:
    client = user_client(app)
    url = start_scan(client).headers["Location"]
    wait_for_report(client, url)
    assert post(client, "/account", action="delete", current=USER_PASSWORD).status_code == 302
    store = services(app).store
    assert store.user_by_login("anna@example.org") is None
    assert store.count_scans() == 0
    assert client.get("/scan").status_code == 302


# ----------------------------------------------------------------------- scans


def test_scan_runs_in_background_and_ends_in_a_report(app: Flask) -> None:
    client = user_client(app)
    resp = start_scan(client, target="https://1.1.1.1:8443/path")
    assert resp.status_code == 302
    url = resp.headers["Location"]
    html = wait_for_report(client, url)
    assert "1.1.1.1:8443" in html
    assert 'aria-label="Rating: A"' in html
    assert "BSI TR-02102-2" in html and "RFC 9325" in html

    report = client.get(url + ".json").get_json()
    assert report["observation"]["target"]["port"] == 8443
    assert [e["standard"]["id"] for e in report["evaluations"]] == [
        "bsi-tr-02102-2",
        "ietf-rfc9325",
    ]
    assert client.get(url + ".sarif").get_json()["version"] == "2.1.0"
    assert "1.1.1.1:8443" in text(client.get("/reports"))

    started = events(app, "scan.started")[0]
    assert started["login"] == "anna@example.org"
    assert started["detail"] == "1.1.1.1:8443 (1.1.1.1); bsi-tr-02102-2, ietf-rfc9325"
    assert wait_for_event(app, "scan.finished")["detail"] == "1.1.1.1:8443: rating A"


def test_reports_belong_to_their_owner(app: Flask) -> None:
    anna = user_client(app, "anna@example.org")
    boris = user_client(app, "boris@example.org")
    url = start_scan(anna).headers["Location"]
    wait_for_report(anna, url)

    for path in (url, url + ".json", url + ".sarif"):
        assert boris.get(path).status_code == 404, path
    assert post(boris, url + "/delete", form_page="/scan").status_code == 404
    assert "1.1.1.1" not in text(boris.get("/reports"))

    admin = app.test_client()
    sign_in(admin)
    assert admin.get(url).status_code == 200, "administrators can open every report"
    assert "anna@example.org" in text(admin.get("/admin/scans"))

    assert post(anna, url + "/delete", form_page=url).status_code == 302
    assert anna.get(url).status_code == 404
    assert events(app, "report.deleted")[0]["detail"] == "1.1.1.1:443"


def test_scan_form_needs_a_standard_and_the_authorisation(app: Flask) -> None:
    client = user_client(app)
    assert "Choose at least one standard." in text(start_scan(client, standard=["nope"]))
    assert "Confirm that you are authorised" in text(start_scan(client, authorised=""))
    assert services(app).store.count_scans() == 0


@pytest.mark.parametrize(
    "target", ["127.0.0.1", "localhost", "169.254.169.254", "10.0.0.1:8443", "[::1]", "0.0.0.0"]
)
def test_private_targets_are_refused_and_logged(app: Flask, target: str) -> None:
    client = user_client(app)
    resp = start_scan(client, target=target)
    assert resp.status_code == 200
    assert "Only public addresses can be checked here." in text(resp)
    assert services(app).store.count_scans() == 0
    event = events(app, "scan.rejected")[0]
    assert event["detail"].startswith(f"{target}: target resolves to a private")


def test_malformed_targets_are_refused(app: Flask) -> None:
    client = user_client(app)
    for target in ("exa mple.org", "1.1.1.1:99999", "-bad-.example", "<script>"):
        resp = start_scan(client, target=target)
        assert "This is not a valid host name or IP address." in text(resp), target
        assert "<script>" not in text(resp)
    assert services(app).store.count_scans() == 0


def test_failed_scan_is_shown_as_failed_not_as_a_report(make_app: AppFactory) -> None:
    def broken(target: object) -> dict[str, object]:
        raise RuntimeError("secret internal detail")

    app = make_app(SCAN_FN=broken)
    client = app.test_client()
    sign_in(client)
    url = start_scan(client).headers["Location"]
    html = wait_for_report(client, url)
    assert "The check could not be completed." in html
    assert "scan failed: RuntimeError" in html
    assert "secret internal detail" not in html
    assert client.get(url + ".json").status_code == 404
    assert wait_for_event(app, "scan.finished")["detail"].endswith("scan failed: RuntimeError")


def test_scans_interrupted_by_a_restart_are_marked_as_failed(
    make_app: AppFactory, tmp_path: Path, database_url: str
) -> None:
    settings = {"DATA_DIR": str(tmp_path)}
    if database_url == "sqlite://":
        settings["DATABASE_URL"] = ""  # a file under DATA_DIR, shared by both instances
    first = make_app(**settings)
    services(first).store.create_scan("abc", 1, "example.org", 443, "1.1.1.1", ["ietf-rfc9325"])
    second = make_app(**settings)
    row = services(second).store.scan("abc")
    assert row is not None and row["status"] == "error"
    assert "restart" in row["error"]


# ---------------------------------------------------------------------- limits


def test_monthly_limit_applies_to_users_but_not_to_administrators(make_app: AppFactory) -> None:
    app = make_app(CHECKS_PER_MONTH=2)
    client = user_client(app)
    assert "2 of 2 checks left this month." in text(client.get("/scan"))
    for _ in range(2):
        wait_for_report(client, start_scan(client).headers["Location"])
    assert "0 of 2 checks left this month." in text(client.get("/scan"))
    refused = start_scan(client)
    assert refused.status_code == 200
    assert "No checks left this month." in text(refused)
    assert services(app).store.count_scans() == 2
    assert events(app, "scan.quota")[0]["detail"] == "1.1.1.1:443 (monthly limit)"

    admin = app.test_client()
    sign_in(admin)
    assert "Administrator: no monthly limit." in text(admin.get("/scan"))
    for _ in range(3):
        wait_for_report(admin, start_scan(admin).headers["Location"])
    assert services(app).store.count_scans() == 5


def test_administrator_can_set_a_limit_for_one_account(make_app: AppFactory) -> None:
    app = make_app(CHECKS_PER_MONTH=1)
    user_id = add_user(app)
    admin = app.test_client()
    sign_in(admin)
    post(admin, f"/admin/users/{user_id}", action="save", monthly_limit="3")
    client = app.test_client()
    sign_in(client, "anna@example.org", USER_PASSWORD)
    assert "3 of 3 checks left this month." in text(client.get("/scan"))
    post(admin, f"/admin/users/{user_id}", action="save", monthly_limit="0")
    assert "No checks left this month." in text(start_scan(client))


def test_hourly_limit(app: Flask) -> None:
    services(app).scan_limiter.limit = 1
    client = user_client(app)
    wait_for_report(client, start_scan(client).headers["Location"])
    refused = start_scan(client)
    assert "Hourly limit reached (1 checks)." in text(refused)
    assert events(app, "scan.quota")[0]["detail"].endswith("(hourly limit)")


# ------------------------------------------------------------------- audit log


def test_audit_log_shows_who_did_what_from_where(make_app: AppFactory) -> None:
    app = make_app(CLIENT_IP_HEADER="CF-Connecting-IP")
    client = app.test_client()
    visitor = {
        "CF-Connecting-IP": "203.0.113.7",
        "CF-IPCountry": "DE",
        "User-Agent": "TestBrowser/1.0",
    }
    client.post(
        "/login", data={"csrf": csrf(client), "login": ADMIN, "password": "wrong"}, headers=visitor
    )
    event = events(app, "login.failed")[0]
    assert (event["ip"], event["country"], event["user_agent"]) == (
        "203.0.113.7",
        "DE",
        "TestBrowser/1.0",
    )

    sign_in(client)
    page = text(client.get("/admin/events?kind=login&q=203.0.113"))
    assert "203.0.113.7" in page and "TestBrowser/1.0" in page and "wrong password" in page
    assert "login.failed" in page and "login.ok" not in page
    overview = text(client.get("/admin"))
    assert "203.0.113.7" in overview and ">DE<" in overview
    assert client.get("/admin/events?page=abc&kind=nope").status_code == 200


def test_address_headers_are_ignored_unless_the_operator_trusts_them(
    app: Flask, client: FlaskClient
) -> None:
    spoofed = {
        "CF-Connecting-IP": "203.0.113.7",
        "CF-IPCountry": "DE",
        "X-Forwarded-For": "1.2.3.4",
    }
    client.post(
        "/login", data={"csrf": csrf(client), "login": ADMIN, "password": "wrong"}, headers=spoofed
    )
    event = events(app, "login.failed")[0]
    assert event["ip"] == "127.0.0.1" and event["country"] == ""


def test_render_is_recognised_and_warns_about_its_disk(
    make_app: AppFactory, monkeypatch: pytest.MonkeyPatch, database_url: str
) -> None:
    monkeypatch.setenv("RENDER", "true")
    app = make_app()
    assert app.config["CLIENT_IP_HEADER"] == "CF-Connecting-IP"
    client = app.test_client()
    sign_in(client)
    warned = "Data is not kept across restarts." in text(client.get("/admin"))
    assert warned == (database_url == "sqlite://")


def test_markup_in_logged_text_is_escaped(app: Flask, client: FlaskClient) -> None:
    hostile = "<img src=x onerror=alert(1)>"
    client.post(
        "/login",
        data={"csrf": csrf(client), "login": hostile, "password": "x"},
        headers={"User-Agent": hostile},
    )
    sign_in(client)
    page = text(client.get("/admin/events"))
    assert hostile not in page
    assert "&lt;img src=x onerror=alert(1)&gt;" in page


def test_old_audit_events_and_reports_are_deleted(make_app: AppFactory) -> None:
    app = make_app(AUDIT_RETENTION_DAYS=30, REPORT_RETENTION_DAYS=90)
    store = services(app).store
    now = int(time.time())
    store.add_event("login.ok", login="old")
    store.add_event("login.ok", login="recent")
    store.db.execute("UPDATE events SET ts = ? WHERE login = ?", (now - 31 * 86400, "old"))
    store.create_scan("old", 1, "old.example", 443, "1.1.1.1", [])
    store.create_scan("new", 1, "new.example", 443, "1.1.1.1", [])
    store.db.execute(
        "UPDATE scans SET created_at = ? WHERE public_id = ?", (now - 91 * 86400, "old")
    )

    client = app.test_client()
    sign_in(client)  # writing an audit event triggers the clean-up
    assert {e["login"] for e in events(app, "login.ok")} == {"recent", ADMIN}
    assert store.scan("old") is None and store.scan("new") is not None


# ------------------------------------------------------------------- languages


def test_language_follows_the_choice_then_the_account_then_the_browser(app: Flask) -> None:
    client = app.test_client()
    assert "Sign in" in text(client.get("/login"))
    assert "Увійти" in text(client.get("/login", headers={"Accept-Language": "uk-UA,uk;q=0.9"}))
    assert "Anmelden" in text(client.get("/login?lang=de"))
    # The choice is remembered and beats the browser's preference.
    assert "Anmelden" in text(client.get("/login", headers={"Accept-Language": "uk"}))
    assert "Anmelden" in text(client.get("/login?lang=xx")), "unknown codes are ignored"

    sign_in(client)
    admin = services(app).store.user_by_login(ADMIN)
    assert admin is not None and admin["locale"] is None
    client.get("/scan?lang=uk")
    admin = services(app).store.user_by_login(ADMIN)
    assert admin is not None and admin["locale"] == "uk"

    other_device = app.test_client()
    sign_in(other_device)
    assert "Нова перевірка" in text(other_device.get("/scan")), "the account remembers it"
    post(other_device, "/logout", form_page="/")
    assert "Увійти" in text(other_device.get("/login")), "signing out keeps the language"


def test_messages_and_reports_are_translated(app: Flask) -> None:
    client = app.test_client()
    client.get("/?lang=de")
    assert "Anmeldename oder Passwort ist falsch." in text(sign_in(client, ADMIN, "wrong"))
    sign_in(client)
    html = wait_for_report(client, start_scan(client).headers["Location"])
    assert "Nicht konform" in html and "Konform, mit Warnungen" in html
    assert re.search(r'aria-label="Bewertung: A"', html)
    assert "Regeltexte und Quellenangaben" in html
    assert "Diese Adresse ist privat" in text(start_scan(client, target="127.0.0.1"))


# --------------------------------------------------------------- administration


def test_overview_counts_and_chart(app: Flask) -> None:
    client = user_client(app)
    wait_for_report(client, start_scan(client).headers["Location"])
    start_scan(client, target="10.0.0.1")
    sign_in(app.test_client(), ADMIN, "wrong")
    admin = app.test_client()
    sign_in(admin)
    html = text(admin.get("/admin"))
    figures = dict(re.findall(r"<dt>([^<]+)</dt><dd>(\d+)</dd>", html))
    assert figures["Accounts"] == "2"
    assert figures["Checks today"] == "1"
    assert figures["Failed sign-ins, 24 hours"] == "1"
    assert figures["Refused targets, 7 days"] == "1"
    assert html.count('<path class="s1"') == 1 and html.count('<path class="s2"') == 1
    assert "Checks started: <tspan" in html
    assert "50 checks a month, 30 an hour" in html


def test_first_administrator_is_created_once_and_can_be_reset(
    make_app: AppFactory, tmp_path: Path, database_url: str
) -> None:
    settings = {"DATA_DIR": str(tmp_path), "ADMIN_LOGIN": "root"}
    if database_url == "sqlite://":
        settings["DATABASE_URL"] = ""
    make_app(**settings)
    changed = make_app(**settings, APP_PASSWORD="a different passphrase")
    client = changed.test_client()
    assert sign_in(client, "root", "a different passphrase").status_code == 200, (
        "a changed APP_PASSWORD does not overwrite the stored password"
    )
    assert sign_in(client, "root", ADMIN_PASSWORD).status_code == 302

    reset = make_app(**settings, APP_PASSWORD="a different passphrase", ADMIN_RESET=True)
    assert sign_in(reset.test_client(), "root", "a different passphrase").status_code == 302
    assert services(reset).store.count_users() == 1


# ------------------------------------------------- formats, servers, comparison


def test_format_chosen_before_the_check_is_offered_when_it_is_done(app: Flask) -> None:
    client = user_client(app)
    url = start_scan(client, output="pdf").headers["Location"]
    html = wait_for_report(client, url)
    assert "Your report is ready." in html
    assert f'href="{url}.pdf"' in html
    assert "What to do, in this order" in html and "Recommended configuration" in html
    pdf = client.get(url + ".pdf")
    assert pdf.mimetype == "application/pdf" and pdf.data.startswith(b"%PDF")
    assert "attachment" in pdf.headers["Content-Disposition"]
    data = client.get(url + ".json").get_json()
    assert data["actions"] and data["actions"][0]["priority"] in (
        "critical",
        "high",
        "medium",
        "low",
    )
    row = services(app).store.scan(url.rsplit("/", 1)[1])
    assert row is not None and row["output"] == "pdf"
    # An unknown format falls back to the web page.
    other = start_scan(client, output="exe").headers["Location"]
    assert "Your report is ready." not in wait_for_report(client, other)


def test_demo_reports_come_as_pdf_too(client: FlaskClient) -> None:
    resp = client.get("/demo/tls-typical.pdf?lang=de")
    assert resp.mimetype == "application/pdf" and resp.data.startswith(b"%PDF")
    assert client.get("/demo/tls-typical.exe").status_code == 404


def test_report_page_leads_with_figures_and_folds_the_details(client: FlaskClient) -> None:
    html = text(client.get("/demo/tls-typical"))
    # Key figures first, then a way to jump to each part.
    assert 'class="tally"' in html and "Standards met" in html
    assert 'class="report-nav' in html and 'href="#findings"' in html
    # Steps that need work stay open; low-priority ones are folded together.
    assert html.index("Use a stronger certificate key") < html.index("Low priority")
    assert "Required by:" in html
    # Findings per standard start folded, each with its verdict in the summary line.
    assert '<details class="sheet standard"' in html
    assert '<details class="sheet standard" id="bsi-tr-02102-2" open' not in html
    assert "not applicable to this server" in html
    assert "1 warnings" not in html


def test_server_without_main_steps_shows_the_low_ones_open(client: FlaskClient) -> None:
    # With the default standards the hardened lab server only lacks post-quantum
    # key exchange, a low-priority step; folding it away would hide the whole plan.
    html = text(client.get("/demo/tls-good"))
    assert '<details class="minor" open>' in html
    assert "Add hybrid post-quantum key exchange" in html


def test_keeping_a_server_checking_it_again_and_comparing(app: Flask) -> None:
    client = user_client(app)
    first = start_scan(client, keep="yes", label="Lab nginx").headers["Location"]
    wait_for_report(client, first)
    servers = text(client.get("/servers"))
    assert "Lab nginx" in servers and "1.1.1.1:443" in servers
    target = services(app).store.targets()[0]
    again = post(client, f"/servers/{target['id']}/check", form_page="/servers")
    assert again.status_code == 302
    second = again.headers["Location"]
    html = wait_for_report(client, second)
    assert "Compare with the previous check" in html
    a, b = first.rsplit("/", 1)[1], second.rsplit("/", 1)[1]
    compared = text(client.get(f"/compare?a={b}&b={a}"))  # order does not matter
    assert "Nothing changed between the two checks." in compared
    history = text(client.get(f"/servers/{target['id']}"))
    assert "Compare the two checks" in history and history.count('name="a"') == 2
    post(client, f"/servers/{target['id']}", label="Renamed", standard=["ietf-rfc9325"])
    renamed = services(app).store.target(target["id"])
    assert renamed is not None and renamed["label"] == "Renamed"
    assert renamed["standards"] == ["ietf-rfc9325"]
    post(client, f"/servers/{target['id']}/delete", form_page=f"/servers/{target['id']}")
    assert services(app).store.target(target["id"]) is None
    assert client.get(first).status_code == 200, "removing a server keeps its reports"


def test_servers_and_comparisons_belong_to_their_owner(app: Flask) -> None:
    anna = user_client(app, "anna@example.org")
    boris = user_client(app, "boris@example.org")
    url = start_scan(anna, keep="yes").headers["Location"]
    wait_for_report(anna, url)
    mine = wait_for_report(boris, start_scan(boris).headers["Location"])
    assert mine
    target = services(app).store.targets()[0]
    for path in (f"/servers/{target['id']}",):
        assert boris.get(path).status_code == 404
    assert post(boris, f"/servers/{target['id']}/check", form_page="/servers").status_code == 404
    assert post(boris, f"/servers/{target['id']}/delete", form_page="/servers").status_code == 404
    boris_user = services(app).store.user_by_login("boris@example.org")
    assert boris_user is not None
    own = services(app).store.scans(user_id=boris_user["id"])
    foreign = url.rsplit("/", 1)[1]
    assert boris.get(f"/compare?a={foreign}&b={own[0]['public_id']}").status_code == 404
    assert "1.1.1.1" not in text(boris.get("/servers"))
    admin = app.test_client()
    sign_in(admin)
    assert "anna@example.org" in text(admin.get("/admin/servers"))
    assert admin.get(f"/servers/{target['id']}").status_code == 200


def test_lab_networks_can_be_allowed(make_app: AppFactory) -> None:
    app = make_app(PRIVATE_NETWORKS="10.0.0.0/24")
    client = user_client(app)
    assert "10.0.0.0/24" in text(client.get("/scan"))
    allowed = start_scan(client, target="10.0.0.5:8443")
    assert allowed.status_code == 302
    refused = start_scan(client, target="10.0.1.5")
    assert "Only public addresses can be checked here." in text(refused)
    admin = app.test_client()
    sign_in(admin)
    assert "10.0.0.0/24" in text(admin.get("/admin"))


# ---------------------------------------------------------- audit log tools


def test_audit_log_filters_and_csv_export(app: Flask) -> None:
    store = services(app).store
    store.add_event("login.failed", login="=HYPERLINK(1)", ip="203.0.113.7", detail="+cmd")
    store.add_event("login.failed", login="anna", ip="198.51.100.1")
    client = app.test_client()
    sign_in(client)
    page = text(client.get("/admin/events?ip=203.0.113.7"))
    assert "=HYPERLINK(1)" in page and "anna" not in page.split("<tbody>")[1]
    assert "1 entries" in page
    assert "anna" in text(client.get("/admin/events?login=anna&from=2000-01-01&to=2100-01-01"))
    assert "Nothing recorded yet." in text(client.get("/admin/events?to=2000-01-01"))
    assert client.get("/admin/events?from=nonsense").status_code == 200
    csv_resp = client.get("/admin/events.csv?ip=203.0.113.7")
    assert csv_resp.mimetype == "text/csv"
    body = csv_resp.get_data(as_text=True)
    assert body.startswith("﻿time_utc,event,account,ip")
    # Visitor text that a spreadsheet would run as a formula is written as text.
    assert "'=HYPERLINK(1)" in body and "'+cmd" in body
    assert events(app, "admin.export")
    assert user_client(app).get("/admin/events.csv").status_code == 403


def test_overview_shows_signals_and_database_health(app: Flask) -> None:
    for n in range(6):
        stranger = app.test_client()
        stranger.post(
            "/login",
            data={"csrf": csrf(stranger), "login": f"guess{n}", "password": "x"},
            environ_base={"REMOTE_ADDR": "203.0.113.9"},
        )
    admin = app.test_client()
    admin.post(
        "/login",
        data={"csrf": csrf(admin), "login": ADMIN, "password": ADMIN_PASSWORD},
        environ_base={"REMOTE_ADDR": "198.51.100.200"},
    )
    html = text(admin.get("/admin"))
    assert "Many failed sign-ins from one address" in html
    assert "One address tries many login names" in html
    assert 'href="/admin/events?ip=203.0.113.9"' in html
    assert "reachable" in html and "schema version 2" in html


def test_about_page_and_start_page_blocks(client: FlaskClient) -> None:
    home = text(client.get("/"))
    for heading in (
        "The idea",
        "What a report contains",
        "Who it is for",
        "Practise on your own server",
    ):
        assert heading in home
    about = text(client.get("/about?lang=uk"))
    assert "Про проєкт" in about and "lab-admin-password" in about
