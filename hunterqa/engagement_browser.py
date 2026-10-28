"""Narrow remote HTTPS form review with pinned transport and ephemeral cookies.

Only exact start/login URLs are admitted. JavaScript is disabled. A separate
OS/network sandbox is still required; browser interception is not a firewall.
"""
from __future__ import annotations

import os

from .engagement import credentials


def inspect_browser(policy, step, gate, *, transport, browser_provider=None):
    start, login = step["url"], step.get("login_url")
    if login:
        user, secret = credentials()
    # Playwright also starts a Node driver BEFORE Chromium. Remove credential
    # variables before either child starts; this does not change the caller shell.
    for key in ("HUNTERQA_TEST_USERNAME", "HUNTERQA_TEST_PASSWORD",
                "HUNTERQA_LAB_USERNAME", "HUNTERQA_LAB_PASSWORD"):
        os.environ.pop(key, None)
    if browser_provider is None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise RuntimeError("Install the browser extra and Chromium") from None
        browser_provider = sync_playwright
    used_post = False
    blocked = 0
    failure = None
    last_status = None
    # Explicit child environment also excludes any legacy lab credentials.
    child_env = {k: v for k, v in os.environ.items()
                 if k not in {"HUNTERQA_TEST_USERNAME", "HUNTERQA_TEST_PASSWORD",
                              "HUNTERQA_LAB_USERNAME", "HUNTERQA_LAB_PASSWORD"}}
    with browser_provider() as driver:
        browser = driver.chromium.launch(headless=True, env=child_env,
                                        args=["--disable-background-networking", "--disable-sync"])
        try:
            context = browser.new_context(service_workers="block", accept_downloads=False,
                                          ignore_https_errors=False, java_script_enabled=False,
                                          permissions=[])
            try:
                def route_check(route):
                    nonlocal used_post, blocked, failure, last_status
                    request = route.request
                    try:
                        method, url = request.method, request.url
                        gate.check()
                        if method in ("GET", "HEAD") and url == start:
                            body = None
                        elif method == "POST" and login and url == login and not used_post:
                            body = request.post_data_buffer
                            if not isinstance(body, bytes) or len(body) > 8192:
                                raise ValueError("Invalid bounded login body")
                            used_post = True
                        else:
                            blocked += 1
                            route.abort("blockedbyclient")
                            return
                        headers = {k: v for k, v in request.all_headers().items()
                                   if k.lower() in {"cookie", "content-type", "accept"}}
                        if sum(len(k) + len(v) for k, v in headers.items()) > 16_384:
                            raise ValueError("Browser request headers too large")
                        gate.admit()
                        result = transport(policy, url, method, body=body, headers=headers)
                        last_status = result["status"]
                        gate.response(last_status)
                        if gate.stopped:
                            route.abort("blockedbyclient")
                            return
                        # Preserve ephemeral login cookies, remove transport/framing headers.
                        outgoing = {}
                        for key, value in result["headers"]:
                            key = key.lower()
                            if key in {"connection", "transfer-encoding", "content-length"}:
                                continue
                            if key == "set-cookie" and key in outgoing:
                                outgoing[key] += "\n" + value
                            else:
                                outgoing[key] = value
                        route.fulfill(status=last_status, headers=outgoing, body=result["body"])
                    except Exception as exc:
                        failure = type(exc).__name__
                        gate.stopped = True
                        route.abort("blockedbyclient")

                context.route("**/*", route_check)
                context.route_web_socket("**/*", lambda websocket: websocket.close())
                page = context.new_page()
                navigation_failed = False
                try:
                    page.goto(start, wait_until="domcontentloaded", timeout=12_000)
                    if login and not gate.stopped:
                        # Deliberately fixed conventional field names, no arbitrary scripts/actions.
                        page.locator('input[name="username"]').fill(user, timeout=3_000)
                        page.locator('input[name="password"]').fill(secret, timeout=3_000)
                        with page.expect_response(lambda r: r.request.method == "POST" and r.url == login,
                                                  timeout=8_000):
                            page.locator('button[type="submit"]').click(timeout=5_000, no_wait_after=True)
                except Exception:
                    navigation_failed = True
                    gate.stopped = True
                outcome = {"status": last_status, "blocked_requests": blocked,
                           "authentication": "attempted_unverified" if used_post else "not_attempted",
                           "browser_context": "ephemeral_javascript_disabled",
                           "outcome": "stopped" if navigation_failed or gate.stopped else "observed"}
                if failure:
                    outcome["error_type"] = failure
                if not navigation_failed and not gate.stopped:
                    outcome["page_structure"] = {
                        "form_count": min(100, page.locator("form").count()),
                        "link_count": min(200, page.locator("a[href]").count()),
                    }
                if "expected_status" in step and last_status is not None:
                    outcome["expected_status_matches"] = last_status == step["expected_status"]
                return outcome
            finally:
                context.close()
        finally:
            browser.close()
