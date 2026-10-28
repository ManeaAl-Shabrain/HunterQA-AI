"""Mocked owned-browser tests; no Chromium or network required."""
import json
import pytest

from hunterqa.browser_lab_v12 import (
    BrowserRequestGate, inspect_owned_browser, preflight_lab_browser,
    _selector,
)


@pytest.fixture
def profile(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    p = tmp_path / "browser.json"
    p.write_text(json.dumps({
        "program": "Owned local login fixture",
        "platform": "local-lab",
        "authorization_reference": "Owned local login fixture permission",
        "acknowledged_authorization": True,
        "allowed_hosts": ["127.0.0.1"],
        "allowed_paths": ["/"],
        "excluded_paths": ["/admin"],
        "methods": ["GET", "HEAD"],
        "allowed_ports": [49151],
        "lab_mode": True,
        "allow_private_network": True,
        "allow_http": True,
        "max_requests": 4,
        "interval_seconds": 0.5,
    }))
    return p


def policy(profile):
    from hunterqa.bounty import BountyPolicy
    return BountyPolicy.load(profile)


def test_browser_restricted_to_exact_owned_loopback(profile):
    local = policy(profile)
    parts, port = preflight_lab_browser(
        local, "http://127.0.0.1:49151/login", "/login")
    assert parts.scheme == "http"
    assert port == 49151
    for bad in [
        "http://localhost:49151/login",
        "http://127.0.0.1:49152/login",
        "https://evil.example.test/login",
        "http://127.0.0.1:49151/admin",
        "http://127.0.0.1:49151/login?next=https://evil.test",
    ]:
        with pytest.raises(ValueError):
            preflight_lab_browser(local, bad, "/login")


def test_browser_denies_remote_host_and_nonlogin_post(profile):
    gate = BrowserRequestGate(policy(profile), "http://127.0.0.1:49151/login",
                              login_path="/login", sleeper=lambda _: None)
    assert gate.admit("GET", "http://127.0.0.1:49151/login")
    assert not gate.admit("GET", "https://example.com/")
    assert not gate.admit("GET", "http://127.0.0.1:49151/admin")
    assert not gate.admit("POST", "http://127.0.0.1:49151/private")
    assert not gate.admit("PUT", "http://127.0.0.1:49151/login")
    assert gate.admit("POST", "http://127.0.0.1:49151/login")
    assert not gate.admit("POST", "http://127.0.0.1:49151/login")
    assert sum(gate.allowed.values()) == 2
    assert sum(gate.denied.values()) == 5


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_browser_stops_on_denial_or_server_error(profile, status):
    gate = BrowserRequestGate(policy(profile), "http://127.0.0.1:49151/")
    assert gate.admit("GET", "http://127.0.0.1:49151/")
    gate.on_response(status)
    assert not gate.admit("GET", "http://127.0.0.1:49151/next")
    assert gate.allowed["GET"] == 1


def test_browser_budget_is_never_bypassed(profile):
    gate = BrowserRequestGate(policy(profile), "http://127.0.0.1:49151/",
                              sleeper=lambda _: None)
    for _ in range(4):
        assert gate.admit("GET", "http://127.0.0.1:49151/")
    assert not gate.admit("GET", "http://127.0.0.1:49151/")
    assert gate.stop


@pytest.mark.parametrize("bad", ["xpath=//input", "javascript:alert(1)",
                                  "input:nth-child(2)", "button;script", "",
                                  "button >> text=ok"])
def test_browser_rejects_untrusted_selector_dsl(bad):
    with pytest.raises(ValueError):
        _selector(bad)


def test_browser_login_requires_environment_credentials(profile, monkeypatch):
    monkeypatch.delenv("HUNTERQA_LAB_USERNAME", raising=False)
    monkeypatch.delenv("HUNTERQA_LAB_PASSWORD", raising=False)
    with pytest.raises(ValueError, match="HUNTERQA_LAB_USERNAME"):
        inspect_owned_browser(profile, "http://127.0.0.1:49151/login",
                              login=True, login_post_path="/login", authorized=True)


class FakeResponse:
    def __init__(self, status=200, headers=None):
        self.status = status
        self.headers = headers or {}


class FakeRequest:
    def __init__(self, method, url):
        self.method, self.url = method, url


class FakeRoute:
    def __init__(self, method, url):
        self.request = FakeRequest(method, url)
        self.allowed = False
        self.denied = False

    def fetch(self, *, max_redirects, timeout):
        assert max_redirects == 0, "Never allow Playwright to follow a redirect"
        assert timeout <= 8_000
        if self.request.method == "POST":
            return FakeResponse(303, {"location": "/account",
                                      "set-cookie": "session=private; HttpOnly"})
        return FakeResponse()

    def fulfill(self, **kwargs):
        # For a redirect, the browser sees an inert 204, not a 3xx.
        assert kwargs.get("status", 200) not in (301, 302, 303, 307, 308)
        self.allowed = True

    def abort(self, reason):
        self.denied = True


class FakeLocator:
    def __init__(self, page, selector):
        self.page, self.selector = page, selector

    def fill(self, value, timeout=None):
        self.page.values[self.selector] = value

    def click(self, timeout=None):
        assert self.page.perform_request("POST", "http://127.0.0.1:49151/login")

    def count(self):
        return 1


class FakePage:
    def __init__(self, context):
        self.context = context
        self.response_handler = lambda response: None
        self.values = {}
        self.url = "about:blank"

    def on(self, event, handler):
        assert event == "response"
        self.response_handler = handler

    def perform_request(self, method, url):
        route = FakeRoute(method, url)
        self.context.route_handler(route)
        if route.allowed:
            self.response_handler(FakeResponse())
        return route.allowed

    def goto(self, url, **kwargs):
        assert self.perform_request("GET", url)
        self.url = url
        # An unapproved tracking request must never be allowed to leave.
        if url.endswith("/login"):
            assert not self.perform_request("GET", "https://outside.example.test/collect")
        return FakeResponse()

    def wait_for_load_state(self, *a, **kwargs):
        pass

    def locator(self, selector):
        return FakeLocator(self, selector)

    def title(self):
        return "Private authenticated account details"


class FakeContext:
    def __init__(self):
        self.page = FakePage(self)
        self.routes = []
        self.websockets = []

    def route(self, matcher, handler):
        self.routes.append(matcher)
        self.route_handler = handler

    def route_web_socket(self, matcher, handler):
        self.websockets.append(matcher)

    def new_page(self):
        return self.page

    def close(self):
        pass


class FakeBrowser:
    def __init__(self):
        self.context = FakeContext()

    def new_context(self, **kwargs):
        assert kwargs["service_workers"] == "block"
        assert kwargs["accept_downloads"] is False
        assert kwargs["ignore_https_errors"] is False
        assert kwargs["permissions"] == []
        return self.context

    def close(self):
        pass


class FakeDriver:
    class Chromium:
        def __init__(self, parent):
            self.parent = parent

        def launch(self, **kwargs):
            assert kwargs["headless"] is True
            self.parent.browser = FakeBrowser()
            return self.parent.browser

    def __init__(self):
        self.chromium = self.Chromium(self)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def test_mocked_owned_browser_login_never_exports_secrets(profile, monkeypatch):
    monkeypatch.setenv("HUNTERQA_LAB_USERNAME", "private-username")
    monkeypatch.setenv("HUNTERQA_LAB_PASSWORD", "private-password")
    driver = FakeDriver()
    result = inspect_owned_browser(
        profile, "http://127.0.0.1:49151/login", login=True,
        login_post_path="/login", authorized=True,
        browser_provider=lambda: driver,
    )
    assert driver.browser.context.routes == ["**/*"]
    assert driver.browser.context.websockets == ["**/*"]
    assert result["authentication"] == "attempted_unverified"
    assert result["traffic"]["approved_requests"] == 3
    assert result["traffic"]["blocked_requests"] == 1
    assert result["confirmed_vulnerabilities"] == 0
    assert result["confirmed_zero_days"] == 0
    as_json = json.dumps(result)
    for text in ("private-username", "private-password", "Private authenticated",
                 "app.example.test", "account"):
        assert text not in as_json


def test_browser_never_starts_without_explicit_authorization(profile):
    with pytest.raises(PermissionError):
        inspect_owned_browser(profile, "http://127.0.0.1:49151/login")
