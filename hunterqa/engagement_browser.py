"""Narrow remote HTTPS form review with pinned transport and ephemeral cookies.

The original form mode admits exact start/login URLs with JavaScript disabled.
The separately approved discovery mode admits scoped same-origin GET resources.
A separate OS/network sandbox is still required; interception is not a firewall.
"""
from __future__ import annotations

import asyncio
import os
from urllib.parse import parse_qsl

from .engagement import credentials


def inspect_browser(policy, step, gate, *, transport, browser_provider=None):
    return asyncio.run(_inspect_browser(policy, step, gate, transport=transport,
                                        browser_provider=browser_provider))


async def _inspect_browser(policy, step, gate, *, transport, browser_provider=None):
    start, login = step["url"], step.get("login_url")
    rendered = step["mode"] == "browser-discovery"
    if login:
        user, secret = credentials()
    # Playwright also starts a Node driver BEFORE Chromium. Remove credential
    # variables before either child starts; this does not change the caller shell.
    for key in ("HUNTERQA_TEST_USERNAME", "HUNTERQA_TEST_PASSWORD",
                "HUNTERQA_LAB_USERNAME", "HUNTERQA_LAB_PASSWORD"):
        os.environ.pop(key, None)
    if browser_provider is None:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            raise RuntimeError("Install the browser extra and Chromium") from None
        browser_provider = async_playwright
    used_post = False
    post_reserved = False
    blocked = 0
    failure = None
    last_status = None
    # Explicit child environment also excludes any legacy lab credentials.
    child_env = {k: v for k, v in os.environ.items()
                 if k not in {"HUNTERQA_TEST_USERNAME", "HUNTERQA_TEST_PASSWORD",
                              "HUNTERQA_LAB_USERNAME", "HUNTERQA_LAB_PASSWORD"}}
    async with browser_provider() as driver:
        browser = await driver.chromium.launch(headless=True, env=child_env,
                                        args=["--disable-background-networking", "--disable-sync"])
        try:
            context = await browser.new_context(service_workers="block", accept_downloads=False,
                                          ignore_https_errors=False, java_script_enabled=rendered,
                                          permissions=[])
            try:
                async def route_check(route):
                    nonlocal used_post, post_reserved, blocked, failure, last_status
                    request = route.request
                    try:
                        method, url = request.method, request.url
                        gate.check()
                        if rendered:
                            from .scoped_rendered_discovery import candidate
                            try:
                                candidate(policy, start, url)
                            except (ValueError, TypeError):
                                blocked += 1
                                await route.abort("blockedbyclient")
                                return
                            # No child frames/popups or unreviewed browser channels.
                            if (request.frame != page.main_frame or request.resource_type not in
                                    {"document", "script", "stylesheet", "fetch", "xhr"}):
                                blocked += 1
                                await route.abort("blockedbyclient")
                                return
                        if method in ("GET", "HEAD") and (url == start or (rendered and method == "GET")):
                            body = None
                        elif method == "POST" and login and url == login and not post_reserved:
                            body = request.post_data_buffer
                            if not isinstance(body, bytes) or len(body) > 8192:
                                raise ValueError("Invalid bounded login body")
                            if rendered:
                                fields = parse_qsl(body.decode("utf-8"), keep_blank_values=True,
                                                   strict_parsing=True, max_num_fields=20)
                                names = [key for key, _ in fields]
                                values = dict(fields)
                                if (len(set(names)) != len(names) or values.get("username") != user
                                        or values.get("password") != secret):
                                    raise ValueError("Rendered login must use the designated account")
                            # Reserve before awaiting headers: parallel script fetches
                            # must not both pass the single-submission check.
                            post_reserved = True
                        else:
                            blocked += 1
                            await route.abort("blockedbyclient")
                            return
                        headers = {k: v for k, v in (await request.all_headers()).items()
                                   if k.lower() in {"cookie", "content-type", "accept"}}
                        if sum(len(k) + len(v) for k, v in headers.items()) > 16_384:
                            raise ValueError("Browser request headers too large")
                        gate.admit()
                        if method == "POST":
                            used_post = True
                        result = transport(policy, url, method, body=body, headers=headers)
                        last_status = result["status"]
                        gate.response(last_status)
                        if gate.stopped:
                            await route.abort("blockedbyclient")
                            return
                        # Preserve ephemeral login cookies, remove transport/framing headers.
                        outgoing = {}
                        for key, value in result["headers"]:
                            key = key.lower()
                            if key in {"connection", "transfer-encoding", "content-length"}:
                                continue
                            if key == "set-cookie" and key in outgoing:
                                outgoing[key] += "\n" + value
                            elif key == "content-security-policy" and key in outgoing:
                                outgoing[key] += ", " + value
                            else:
                                outgoing[key] = value
                        if rendered:
                            # The tool only reads links and executes same-origin/inline
                            # scripts. No frames, workers, images, plugin objects or
                            # arbitrary form submissions are needed for that task.
                            # Keep the site's own CSP: an extra policy may restrict it,
                            # never replace a stricter owner policy.
                            confinement = ("default-src 'none'; script-src 'self' 'unsafe-inline'; "
                                           "style-src 'self' 'unsafe-inline'; connect-src 'self'; "
                                           "form-action 'self'; base-uri 'none'; frame-src 'none'; "
                                           "worker-src 'none'; object-src 'none'")
                            prior = outgoing.get("content-security-policy")
                            outgoing["content-security-policy"] = (prior + ", " if prior else "") + confinement
                        await route.fulfill(status=last_status, headers=outgoing, body=result["body"])
                    except Exception as exc:
                        failure = type(exc).__name__
                        gate.stopped = True
                        await route.abort("blockedbyclient")

                await context.route("**/*", route_check)
                async def close_socket(websocket):
                    await websocket.close()
                await context.route_web_socket("**/*", close_socket)
                page = await context.new_page()
                navigation_failed = False
                discovery = None
                initial_status = None
                try:
                    initial = await page.goto(start, wait_until="domcontentloaded", timeout=12_000)
                    if initial is None:
                        raise RuntimeError("Browser start returned no response")
                    initial_status = initial.status
                    if login and not gate.stopped:
                        # Deliberately fixed conventional field names, no arbitrary scripts/actions.
                        await page.locator('input[name="username"]').fill(user, timeout=3_000)
                        await page.locator('input[name="password"]').fill(secret, timeout=3_000)
                        async with page.expect_response(lambda r: r.request.method == "POST" and r.url == login,
                                                  timeout=8_000):
                            await page.locator('button[type="submit"]').click(timeout=5_000, no_wait_after=True)
                    if rendered and not gate.stopped:
                        from .scoped_rendered_discovery import crawl
                        if login:
                            # expect_response can resolve before the login document
                            # commits. Wait for it before starting a fresh GET.
                            await page.wait_for_url(login, wait_until="domcontentloaded", timeout=8_000)
                            await page.goto(start, wait_until="domcontentloaded", timeout=12_000)
                        discovery = await crawl(page, policy, step, gate)
                except Exception as exc:
                    navigation_failed = True
                    failure = failure or type(exc).__name__
                    gate.stopped = True
                outcome = {"status": last_status, "blocked_requests": blocked,
                           "authentication": "attempted_unverified" if used_post else "not_attempted",
                           "browser_context": ("ephemeral_scoped_javascript" if rendered
                                               else "ephemeral_javascript_disabled"),
                           "outcome": "stopped" if navigation_failed or gate.stopped else "observed"}
                if failure:
                    outcome["error_type"] = failure
                if discovery is not None:
                    outcome["discovery"] = discovery
                if not navigation_failed and not gate.stopped:
                    outcome["page_structure"] = {
                        "form_count": min(100, await asyncio.wait_for(page.locator("form").count(), timeout=3)),
                        "link_count": min(200, await asyncio.wait_for(page.locator("a[href]").count(), timeout=3)),
                    }
                if "expected_status" in step and last_status is not None:
                    outcome["expected_status_matches"] = (initial_status if rendered else last_status) == step["expected_status"]
                return outcome
            finally:
                await asyncio.wait_for(context.close(), timeout=5)
        finally:
            await asyncio.wait_for(browser.close(), timeout=5)
