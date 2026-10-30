"""Real Chromium + owned ephemeral loopback server integration test.

Run only with HUNTERQA_REAL_BROWSER_CI=1 and installed Playwright Chromium.
Never connects to public or third-party targets.
"""
import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from hunterqa.browser_lab_v12 import inspect_owned_browser

pytestmark = pytest.mark.skipif(
    os.environ.get("HUNTERQA_REAL_BROWSER_CI") != "1",
    reason="Real Chromium is an optional isolated owned-loopback integration test",
)


class OwnedHandler(BaseHTTPRequestHandler):
    saw_session_cookie = False
    observed_paths = []
    def log_message(self, *args):
        pass

    def do_GET(self):
        type(self).observed_paths.append(self.path)
        if self.path == "/login":
            html = (
                "<html><head><title>Owned local login fixture</title></head><body>"
                "<form method='post' action='/login'>"
                "<input id='username' name='username'>"
                "<input id='password' name='password' type='password'>"
                "<button type='submit'>Enter local fixture</button>"
                "</form></body></html>"
            ).encode()
        elif self.path == "/account":
            type(self).saw_session_cookie = (
                "lab_session=not-for-publication" in self.headers.get("Cookie", "")
            )
            if not type(self).saw_session_cookie:
                self.send_response(401)
                self.end_headers()
                return
            html = b"""<html><head><title>Private fixture content</title></head>
                <body>Owned lab account<script>
                const a = document.createElement('a'); a.href='/child';
                document.body.appendChild(a);</script></body></html>"""
        elif self.path == "/child":
            if "lab_session=not-for-publication" not in self.headers.get("Cookie", ""):
                self.send_error(403)
                return
            html = b"<html><body><form action='/never-submit' method='post'></form></body></html>"
        elif self.path == "/js":
            html = ("""<html><body><script>setTimeout(() => {
                for (const path of ['/public-child', '/blocked', '/public-child?private=token',
                        'CROSS_PORT']) {
                    const a = document.createElement('a'); a.href=path;
                    document.body.appendChild(a);
                }
                fetch('CROSS_PORT').catch(() => {});
                }, 25);</script></body></html>""".replace(
                    "CROSS_PORT", type(self).redirect_target)).encode()
        elif self.path == "/public-child":
            html = b"<html><body><a href='/end'>end</a><a href='/js#same'>cycle</a></body></html>"
        elif self.path == "/end":
            html = b"<html><body>PRIVATE_OWNED_CONTENT<form method='post' action='/never-submit'></form></body></html>"
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", type(self).redirect_target)
            self.end_headers()
            return
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def do_POST(self):
        if self.path != "/login":
            self.send_error(405)
            return
        size = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(min(2048, size))
        self.send_response(303)
        self.send_header("Location", "/account")
        self.send_header("Set-Cookie", "lab_session=not-for-publication; HttpOnly")
        self.end_headers()


class DisallowedHandler(BaseHTTPRequestHandler):
    hits = 0

    def log_message(self, *args):
        pass

    def do_GET(self):
        type(self).hits += 1
        self.send_response(200)
        self.end_headers()


@pytest.fixture
def owned_http_server(tmp_path, monkeypatch):
    pytest.importorskip("playwright.sync_api")
    guarded = ThreadingHTTPServer(("127.0.0.1", 0), DisallowedHandler)
    guarded_thread = Thread(target=guarded.serve_forever, daemon=True)
    guarded_thread.start()
    DisallowedHandler.hits = 0
    OwnedHandler.saw_session_cookie = False
    OwnedHandler.observed_paths = []
    OwnedHandler.redirect_target = (
        f"http://127.0.0.1:{guarded.server_address[1]}/private"
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), OwnedHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    profile = tmp_path / "scope.json"
    profile.write_text(json.dumps({
        "program": "Ephemeral owned Chromium fixture",
        "platform": "local-lab",
        "authorization_reference": "CI has permission to test its own loopback server",
        "acknowledged_authorization": True,
        "allowed_hosts": ["127.0.0.1"], "allowed_ports": [port],
        "allowed_paths": ["/"], "excluded_paths": ["/blocked"], "methods": ["GET", "HEAD"],
        "max_requests": 12, "interval_seconds": 0.5,
        "lab_mode": True, "allow_private_network": True, "allow_http": True,
    }))
    yield profile, f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()
    thread.join(timeout=3)
    guarded.shutdown()
    guarded.server_close()
    guarded_thread.join(timeout=3)


def test_real_chromium_owned_authenticated_flow(owned_http_server, monkeypatch):
    profile, origin = owned_http_server
    monkeypatch.setenv("HUNTERQA_LAB_USERNAME", "fixture_user_private")
    monkeypatch.setenv("HUNTERQA_LAB_PASSWORD", "fixture_password_private")
    report = inspect_owned_browser(
        profile, origin + "/login", login=True,
        login_post_path="/login", authorized=True,
    )
    assert report["authentication"] == "attempted_unverified"
    assert OwnedHandler.saw_session_cookie, "Owned lab login session cookie was not retained"
    assert report["final_path_sha256"] == hashlib.sha256(b"/account").hexdigest()
    assert report["traffic"]["methods"].get("POST") == 1
    assert report["traffic"]["approved_requests"] >= 3
    assert report["traffic"]["websockets_allowed"] == 0
    assert report["confirmed_zero_days"] == 0
    raw = json.dumps(report)
    for secret in ("fixture_user_private", "fixture_password_private",
                   "not-for-publication", "Owned lab account"):
        assert secret not in raw


def test_real_chromium_cross_port_redirect_is_blocked(owned_http_server):
    profile, origin = owned_http_server
    with pytest.raises(RuntimeError):
        inspect_owned_browser(profile, origin + "/redirect", authorized=True)
    assert DisallowedHandler.hits == 0, "Browser contacted an unapproved local service"


def test_real_chromium_javascript_rendered_crawl(owned_http_server):
    profile, origin = owned_http_server
    report = inspect_owned_browser(profile, origin + "/js", authorized=True,
                                   crawl=True, max_pages=3, max_depth=2, settle_ms=150)
    discovery = report["discovery"]
    assert discovery["pages_visited"] == 3
    assert [r["depth"] for r in discovery["pages"]] == [0, 1, 2]
    assert [r["url_sha256"] for r in discovery["pages"]] == [
        hashlib.sha256((origin + path).encode()).hexdigest()
        for path in ("/js", "/public-child", "/end")]
    assert discovery["pages"][-1]["form_count"] == 1
    assert discovery["links_skipped"] == 3
    assert not discovery["limit_reached"] and not discovery["coverage_complete"]
    assert report["traffic"]["blocked_requests"] >= 1
    assert DisallowedHandler.hits == 0
    assert "/blocked" not in OwnedHandler.observed_paths
    assert "/never-submit" not in OwnedHandler.observed_paths
    assert all("?" not in p for p in OwnedHandler.observed_paths)
    raw = json.dumps(report)
    assert origin not in raw and "PRIVATE_OWNED_CONTENT" not in raw
    assert "private=token" not in raw and "lab_session" not in raw


def test_real_chromium_crawl_reuses_owned_login_session(owned_http_server, monkeypatch):
    profile, origin = owned_http_server
    monkeypatch.setenv("HUNTERQA_LAB_USERNAME", "fixture_user_private")
    monkeypatch.setenv("HUNTERQA_LAB_PASSWORD", "fixture_password_private")
    report = inspect_owned_browser(profile, origin + "/login", login=True,
        login_post_path="/login", authorized=True, crawl=True, max_pages=2, settle_ms=100)
    assert report["discovery"]["pages_visited"] == 2
    assert "/child" in OwnedHandler.observed_paths
    assert report["traffic"]["methods"]["POST"] == 1
    assert report["authentication"] == "attempted_unverified"
    assert not report["discovery"]["authentication_verified"]
    assert report["discovery"]["forms_submitted_by_crawler"] == 0
    assert "fixture_password_private" not in json.dumps(report)


@pytest.mark.parametrize("bounds", [{"max_pages": 1}, {"max_depth": 0}])
def test_real_chromium_crawl_bounds(owned_http_server, bounds):
    profile, origin = owned_http_server
    report = inspect_owned_browser(profile, origin + "/js", authorized=True,
                                   crawl=True, settle_ms=150, **bounds)
    assert report["discovery"]["pages_visited"] == 1
    assert report["discovery"]["limit_reached"]
    assert "/public-child" not in OwnedHandler.observed_paths


def test_real_chromium_crawl_cannot_exceed_shared_request_budget(owned_http_server):
    profile, origin = owned_http_server
    data = json.loads(profile.read_text())
    data["max_requests"] = 2
    profile.write_text(json.dumps(data))
    with pytest.raises(RuntimeError):
        inspect_owned_browser(profile, origin + "/js", authorized=True,
                              crawl=True, max_pages=3, max_depth=2, settle_ms=150)
    assert "/public-child" in OwnedHandler.observed_paths
    assert "/end" not in OwnedHandler.observed_paths
    assert DisallowedHandler.hits == 0
