"""Non-persistent Playwright browser review of an owned LOOPBACK application.

This is deliberately NOT remote live-site automation. It handles an explicitly
approved login form in a disposable local lab, prevents all page requests to
other origins and methods, and never exports credentials, cookies, URLs, HTML
or screenshots. Playwright interception is not a host firewall; isolate Kali
at OS/network level before testing an untrusted page or JS bundle.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import time
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

from .bounty import BountyPolicy, _approved_file

SELECTOR_RE = re.compile(
    r"""(?:\#[A-Za-z][A-Za-z0-9_-]{0,64}|(?:input|button)(?:\[(?:name|type|id)=['"]?[A-Za-z0-9_-]{1,60}['"]?\])?)"""
)
LOGIN_ENV_USERNAME = "HUNTERQA_LAB_USERNAME"
LOGIN_ENV_PASSWORD = "HUNTERQA_LAB_PASSWORD"


def _selector(value: str) -> str:
    if not isinstance(value, str) or SELECTOR_RE.fullmatch(value) is None:
        raise ValueError("Only simple CSS ID or input/button attribute selectors allowed")
    return value


def preflight_lab_browser(policy: BountyPolicy, start_url: str, login_path=None):
    parts, host, port, _ = policy.authorize_url(start_url, "GET")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("Browser research is restricted to exact loopback IPs") from exc
    if (policy.platform != "local-lab" or not policy.lab_mode or
            not policy.allow_private_network or not ip.is_loopback or
            host != "127.0.0.1" or
            set(policy.allowed_hosts) != {"127.0.0.1"} or
            len(policy.allowed_ports) != 1):
        raise ValueError("Browser research needs an exact 127.0.0.1 owned-lab policy")
    if login_path is not None:
        if not isinstance(login_path, str) or not login_path.startswith("/") or len(login_path) > 120:
            raise ValueError("Invalid approved login form path")
        # Enforces exclusions, no encoded path ambiguity, method and port.
        policy.authorize_url(
            f"{parts.scheme}://127.0.0.1:{port}{login_path}", "GET"
        )
    return parts, port


class BrowserRequestGate:
    """Pure, testable per-request admission gate. No AI can modify these rules."""

    def __init__(self, policy, start_url, *, login_path=None, sleeper=time.sleep,
                 clock=time.monotonic):
        self.parts, self.port = preflight_lab_browser(policy, start_url, login_path)
        self.policy = policy
        self.login_path = login_path
        self.sleeper = sleeper
        self.clock = clock
        self.allowed = Counter()
        self.denied = Counter()
        self.post_used = False
        self.last_request_at = None
        self.stop = False
        self.approved_login_redirect = None
        self.route_failure_type = None
        self.max_requests = min(20, policy.max_requests)

    def admit(self, method: str, url: str) -> bool:
        if self.stop:
            self.denied["stopped"] += 1
            return False
        try:
            if method in ("GET", "HEAD"):
                parts, host, port, _ = self.policy.authorize_url(url, method)
            elif method == "POST" and self.login_path and not self.post_used:
                # One and only one explicitly approved, owned loopback login POST.
                parts, host, port, path = self.policy.authorize_url(url, "GET")
                if path != self.login_path:
                    raise ValueError("POST is permitted only at exact login endpoint")
            else:
                raise ValueError("Request method not on browser allowlist")
            if (host != "127.0.0.1" or port != self.port or
                    parts.scheme != self.parts.scheme):
                raise ValueError("Request origin outside owned loopback service")
            if sum(self.allowed.values()) >= self.max_requests:
                self.stop = True
                raise ValueError("Browser request budget exhausted")
        except (ValueError, TypeError):
            self.denied["policy_or_budget"] += 1
            return False
        now = self.clock()
        if self.last_request_at is not None:
            delay = self.policy.interval_seconds - (now - self.last_request_at)
            if delay > 0:
                self.sleeper(delay)
        self.last_request_at = self.clock()
        if method == "POST":
            self.post_used = True
        self.allowed[method] += 1
        return True

    def on_response(self, status: int) -> None:
        if status in (401, 403, 429) or status >= 500:
            self.stop = True


def inspect_owned_browser(profile_path, start_url, *, authorized=False, login=False,
                          login_post_path=None, username_selector="#username",
                          password_selector="#password", submit_selector="button[type=submit]",
                          browser_provider=None):
    """Read-only visual/structural examination of an owned loopback web app.

    Optional login can submit the one explicit form to the exact local endpoint.
    Credentials must be provided in process environment and are not returned.
    """
    if not authorized:
        raise PermissionError("Playwright lab testing requires --authorized")
    policy = BountyPolicy.load(profile_path)
    preflight_lab_browser(policy, start_url, login_post_path if login else None)
    if login:
        if not login_post_path:
            raise ValueError("Login POST path must be explicitly approved")
        for value in (username_selector, password_selector, submit_selector):
            _selector(value)
        user, secret = os.environ.get(LOGIN_ENV_USERNAME), os.environ.get(LOGIN_ENV_PASSWORD)
        if not user or not secret:
            raise ValueError("Set both HUNTERQA_LAB_USERNAME and HUNTERQA_LAB_PASSWORD")
    else:
        user = secret = None
        if login_post_path is not None:
            raise ValueError("Login path is permitted only with --login")
    gate = BrowserRequestGate(policy, start_url, login_path=login_post_path if login else None)
    if browser_provider is None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError(
                "Install optional Playwright: pip install -e '.[dev,browser]' "
                "and python -m playwright install chromium"
            ) from exc
        provider = sync_playwright
    else:
        provider = browser_provider

    # Credentials enter the browser only after route guards have been registered.
    # New non-persistent context: no cookie jar, download or HAR is saved.
    phase = "start"
    try:
        with provider() as driver:
            browser = driver.chromium.launch(
                headless=True,
                args=["--disable-background-networking", "--disable-sync", "--no-first-run"],
            )
            try:
                context = browser.new_context(
                    service_workers="block", accept_downloads=False,
                    ignore_https_errors=False, permissions=[],
                )
                try:
                    def route_check(route):
                        # Playwright's route.continue_ may allow redirect hops
                        # to bypass another policy interception. Fetch exactly
                        # ONE response with redirect following disabled.
                        request = route.request
                        if not gate.admit(request.method, request.url):
                            route.abort("blockedbyclient")
                            return
                        try:
                            response = route.fetch(max_redirects=0, timeout=8_000)
                            status = int(response.status)
                            gate.on_response(status)
                            if 300 <= status < 400:
                                location = response.headers.get("location")
                                if not location:
                                    raise ValueError("Missing redirect location")
                                next_url = urljoin(request.url, location)
                                # For owned-lab login only: allow a preflighted
                                # GET location; NEVER hand the redirect to
                                # Chromium, which may auto-follow outside scope.
                                if (request.method != "POST" or
                                        not gate.post_used or
                                        gate.approved_login_redirect is not None or
                                        status not in (302, 303)):
                                    raise ValueError("Unexpected browser redirect denied")
                                dest, dest_host, dest_port, _ = gate.policy.authorize_url(
                                    next_url, "GET")
                                if (dest_host != "127.0.0.1" or
                                        dest_port != gate.port or
                                        dest.scheme != gate.parts.scheme):
                                    raise ValueError("Redirect is outside the owned app")
                                gate.approved_login_redirect = next_url
                                # Return an inert 204 with any local session
                                # cookie applied in memory. No Location header
                                # reaches Chromium; the driver later starts a
                                # fresh GET that passes policy interception.
                                cookie = response.headers.get("set-cookie")
                                safe_headers = {"set-cookie": cookie} if cookie else {}
                                route.fulfill(status=204, headers=safe_headers, body="")
                                return
                            if gate.stop:
                                raise ValueError("Rate limit or denial blocked browser run")
                            route.fulfill(response=response)
                        except Exception as exc:
                            gate.route_failure_type = type(exc).__name__
                            gate.stop = True
                            route.abort("blockedbyclient")

                    context.route("**/*", route_check)
                    if not hasattr(context, "route_web_socket"):
                        raise RuntimeError("Playwright >=1.48 is required to block WebSockets")
                    context.route_web_socket("**/*", lambda websocket: websocket.close())
                    page = context.new_page()
                    page.on("response", lambda response: gate.on_response(response.status))
                    phase = "initial_navigation"
                    response = page.goto(
                        start_url, wait_until="domcontentloaded", timeout=12_000
                    )
                    if response is None or gate.stop:
                        raise RuntimeError("Initial lab navigation was denied or blocked")
                    if login:
                        phase = "username_field"
                        page.locator(username_selector).fill(user, timeout=5_000)
                        phase = "password_field"
                        page.locator(password_selector).fill(secret, timeout=5_000)
                        phase = "login_submit"
                        page.locator(submit_selector).click(timeout=8_000)
                        # Follow only the verified, single approved location
                        # as a NEW navigation; no native HTTP redirects.
                        if gate.approved_login_redirect:
                            phase = "approved_login_destination"
                            page.goto(gate.approved_login_redirect,
                                      wait_until="domcontentloaded", timeout=12_000)
                        else:
                            phase = "login_page_state"
                            page.wait_for_load_state("domcontentloaded", timeout=8_000)
                    if gate.stop:
                        raise RuntimeError("Browser session stopped after rejection or rate limit")
                    phase = "final_lab_validation"
                    # Final URL must remain within the same exact origin + allowed paths.
                    gate.policy.authorize_url(page.url, "GET")
                    final_parts = urlsplit(page.url)
                    if final_parts.hostname != "127.0.0.1" or final_parts.port != gate.port:
                        raise RuntimeError("Browser navigated outside explicitly owned loopback")
                    title_digest = hashlib.sha256(page.title().encode("utf-8")).hexdigest()
                    forms = min(100, page.locator("form").count())
                    links = min(200, page.locator("a[href]").count())
                    result = {
                        "schema_version": 1, "engine": "hunterqa_v12_owned_browser_lab",
                        "generated_at": datetime.now(timezone.utc).isoformat(),
                        "program": policy.program, "platform": policy.platform,
                        "policy_sha256": hashlib.sha256(
                            _approved_file(profile_path).read_bytes()).hexdigest(),
                        "initial_url_hash": hashlib.sha256(
                            start_url.encode("utf-8")).hexdigest(),
                        "final_path_sha256": hashlib.sha256(
                            final_parts.path.encode("utf-8")).hexdigest(),
                        "title_sha256": title_digest,
                        "page_structure": {"form_count": forms, "link_count": links},
                        "traffic": {"approved_requests": sum(gate.allowed.values()),
                                    "methods": dict(gate.allowed),
                                    "blocked_requests": sum(gate.denied.values()),
                                    "max_requests": gate.max_requests,
                                    "websockets_allowed": 0},
                        "authentication": ("attempted_unverified" if login else "not_attempted"),
                        "browser_context": "ephemeral_no_storage_export",
                        "review_required": True,
                        "confirmed_vulnerabilities": 0,
                        "confirmed_zero_days": 0,
                        "limitations": "Owned 127.0.0.1 laboratory only. Login submission "
                                       "is NOT proof of successful authentication. No DOM, "
                                       "screenshots, cookies, tokens or credentials exported. "
                                       "Browser interceptors are not a network firewall.",
                    }
                finally:
                    context.close()
            finally:
                browser.close()
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError(
            "Browser lab stopped at " + phase + "; failure type: " +
            type(exc).__name__ + "; request guard: " +
            str(gate.route_failure_type or "not-triggered") +
            ". No private page contents were exported."
        ) from None
    return result



def read_browser_summary(path):
    """Read approved local browser metadata without exposing page data."""
    empty = {"status": "not_configured", "approved_requests": 0,
             "blocked_requests": 0, "login": "not_attempted"}
    if not path:
        return empty
    from .bounty import _read_json
    try:
        report = _read_json(path, 100_000)
        if not isinstance(report, dict) or report.get("engine") != "hunterqa_v12_owned_browser_lab":
            return empty
        stats = report.get("traffic")
        if not isinstance(stats, dict):
            return empty
        approved, blocked = stats.get("approved_requests"), stats.get("blocked_requests")
        login = report.get("authentication")
        if (type(approved) is not int or type(blocked) is not int or
                not 0 <= approved <= 20 or not 0 <= blocked <= 100_000 or
                login not in ("attempted_unverified", "not_attempted")):
            return empty
        return {"status": "ready", "approved_requests": approved,
                "blocked_requests": blocked, "login": login}
    except (OSError, ValueError, UnicodeError, TypeError, KeyError):
        return empty
