"""End-to-end check of the web interface inside the lab, as a user would use it.

Signs in, checks two lab servers through the browser forms, downloads a PDF,
checks a server again from "My servers", compares the two checks and makes
sure a private address outside the lab network is refused. Standard library
only; run on the host after "docker compose up -d --wait web my-site":

    python lab/scripts/web-e2e.py [http://127.0.0.1:8080] [password]
"""

import http.cookiejar
import re
import sys
import time
import urllib.parse
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
PASSWORD = sys.argv[2] if len(sys.argv) > 2 else "lab-admin-password"

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def need(condition: object, message: str = "unexpected page content") -> None:
    if not condition:
        raise SystemExit(f"FAILED: {message}")


def get(path: str) -> tuple[str, str, bytes]:
    with opener.open(BASE + path, timeout=30) as resp:
        return resp.geturl(), resp.headers.get("Content-Type", ""), resp.read()


def text(path: str) -> tuple[str, str]:
    url, _, body = get(path)
    return url, body.decode("utf-8")


def token(html: str) -> str:
    match = re.search(r'name="csrf" value="([^"]+)"', html)
    need(match, "no CSRF token on the page")
    return match.group(1)


def post(path: str, form_page: str, fields: list[tuple[str, str]]) -> tuple[str, str]:
    _, html = text(form_page)
    data = urllib.parse.urlencode([("csrf", token(html)), *fields]).encode()
    with opener.open(BASE + path, data=data, timeout=30) as resp:
        return resp.geturl(), resp.read().decode("utf-8")


def wait(url: str) -> str:
    for _ in range(120):
        _, html = text(urllib.parse.urlparse(url).path)
        if 'http-equiv="refresh"' not in html:
            return html
        time.sleep(1)
    raise AssertionError(f"check did not finish: {url}")


def check(target: str, *, output: str = "web", label: str = "") -> tuple[str, str]:
    _, form = text("/scan")
    standards = re.findall(r'name="standard" value="([^"]+)" checked', form)
    need(standards, "no default standards on the scan form")
    fields = [("target", target), ("authorised", "yes"), ("output", output), ("keep", "yes")]
    fields += [("label", label)] + [("standard", s) for s in standards]
    url, _ = post("/scan", "/scan", fields)
    need("/reports/" in url, f"check of {target} was not started: {url}")
    return url, wait(url)


def step(message: str) -> None:
    print(f"- {message}", flush=True)


step("sign in as admin")
url, _ = post("/login", "/login", [("login", "admin"), ("password", PASSWORD)])
need(url.endswith("/scan"), f"sign-in failed, ended on {url}")

step("check tls-typical, PDF chosen before the check")
typical_url, html = check("tls-typical", output="pdf", label="Lab: typical website")
need('aria-label="Rating: A"' in html, "tls-typical should be rated A")
need("Your report is ready." in html and "What to do, in this order" in html)
_, kind, body = get(urllib.parse.urlparse(typical_url).path + ".pdf")
need(kind == "application/pdf" and body.startswith(b"%PDF"), "not a PDF")
step(f"PDF downloaded, {len(body)} bytes")

step("check my-site")
first_url, html = check("my-site:443", label="My site")
grade = re.search(r'aria-label="Rating: ([^"]+)"', html)
need(grade, "my-site report has no rating")
step(f"my-site rated {grade.group(1)}")

step("check my-site again from My servers")
_, servers = text("/servers")
targets = re.findall(r'href="/servers/(\d+)"><strong>My site</strong>', servers)
need(targets, "my-site is not in My servers")
second_url, _ = post(f"/servers/{targets[0]}/check", f"/servers/{targets[0]}", [])
html = wait(second_url)
need("Compare with the previous check" in html)

step("compare the two checks")
a, b = first_url.rsplit("/", 1)[1], second_url.rsplit("/", 1)[1]
_, html = text(f"/compare?a={a}&b={b}")
need("Before and after" in html and "Nothing changed between the two checks." in html)

step("a private address outside the lab network is refused")
_, form = text("/scan")
_, html = post(
    "/scan",
    "/scan",
    [("target", "10.11.12.13"), ("authorised", "yes"), ("standard", "ietf-rfc9325")],
)
need("This address is private" in html, "10.11.12.13 should be refused")

step("administration: overview, audit log, CSV export")
_, html = text("/admin")
need("Needs a look" in html and "reachable" in html)
_, kind, body = get("/admin/events.csv?kind=scan")
need(kind.startswith("text/csv") and b"scan.started" in body)
print("web interface works end to end")
