"""Real Chromium + owned ephemeral loopback server integration test.

Run only with HUNTERQA_REAL_BROWSER_CI=1 and installed Playwright Chromium.
Never connects to public or third-party targets.
"""
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
    def log_message(self, *args):
        pass

    def do_GET(self):
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
            html = b"<html><head><title>Private fixture content</title></head><body>Owned lab account</body></html>"
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
    playwright = pytest.importorskip("playwright.sync_api")
    guarded = ThreadingHTTPServer(("127.0.0.1", 0), DisallowedHandler)
    guarded_thread = Thread(target=guarded.serve_forever, daemon=True)
    guarded_thread.start()
    DisallowedHandler.hits = 0
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
        "allowed_paths": ["/"], "methods": ["GET", "HEAD"],
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
