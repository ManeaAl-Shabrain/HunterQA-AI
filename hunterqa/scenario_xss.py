"""Fixed non-exfiltrating Chromium witnesses in explicitly selected contexts."""
import asyncio
import html
import os
import secrets
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit


def execute(case, runner):
    try:
        return asyncio.run(_execute(case, runner))
    except Exception as error:
        raise RuntimeError("XSS context failed: " + type(error).__name__) from None


async def _execute(case, runner):
    from playwright.async_api import async_playwright
    token = secrets.token_hex(16)
    prefix = {"html": "", "double-attribute": '\">', "single-attribute": "'>", "dom-fragment": ""}[case["context"]]
    payload = prefix + '<svg onload="globalThis.__hunterqa_context=\'' + token + '\'"></svg>'
    inputs = (token, payload, html.escape(payload), payload, token)
    receipts, signals = [], []
    actor = runner.actors.get(case["actor"])
    state = {"cookies": [], "origins": []}
    if actor:
        state["cookies"] = [{**cookie, "domain": urlsplit(actor["origin"]).hostname, "path": "/", "expires": -1} for cookie in actor["cookies"]]
        state["origins"] = [{"origin": actor["origin"], "localStorage": [{"name": k, "value": v} for k, v in actor["local_storage"].items()]}]
    child_env = {k: v for k, v in os.environ.items() if k.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE", "LOCALAPPDATA", "PLAYWRIGHT_BROWSERS_PATH"}}
    async with async_playwright() as driver:
        browser = await driver.chromium.launch(headless=True, env=child_env, args=["--disable-background-networking", "--disable-sync"])
        try:
            for index, value in enumerate(inputs):
                runner.check()
                context = await browser.new_context(storage_state=state, service_workers="block", accept_downloads=False, permissions=[])
                page = await context.new_page()
                seen = set()
                failure = None

                async def close_popup(other):
                    if other != page:
                        runner.stopped = True
                        await other.close()

                context.on("page", close_popup)

                async def intercept(route):
                    nonlocal failure
                    try:
                        request = route.request
                        parts = urlsplit(request.url)
                        clean = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
                        if (request.method != "GET" or request.frame != page.main_frame or clean in seen
                                or not ((clean == case["url"] and request.resource_type == "document")
                                    or (clean in case["script_urls"] and request.resource_type == "script" and not parts.query))):
                            raise PermissionError("XSS request outside the reviewed document/scripts")
                        query = dict(parse_qsl(parts.query, keep_blank_values=True, max_num_fields=1)) if parts.query else None
                        expected = None if case["context"] == "dom-fragment" else {case["parameter"]: value}
                        if clean == case["url"] and query != expected:
                            raise ValueError("XSS input differs from fixed case")
                        seen.add(clean)
                        headers = {k: v for k, v in (await request.all_headers()).items() if k.lower() in {"cookie", "accept"}}
                        response, receipt = runner.request(clean, case["actor"], query=query, headers=headers, cookies=False)
                        receipt.update(context_case=index, document=clean == case["url"])
                        receipts.append(receipt)
                        if response["status"] != 200:
                            raise ValueError("Required XSS document or script unavailable")
                        outgoing = {}
                        for key, header in response.get("headers", []):
                            key = key.lower()
                            if key in {"content-type", "content-security-policy", "set-cookie"}:
                                outgoing[key] = outgoing[key] + "\n" + header if key == "set-cookie" and key in outgoing else header
                        # Preserve the owner's CSP. Additional confinement cannot
                        # loosen a stricter existing policy.
                        restriction = "default-src 'none'; script-src 'self' 'unsafe-inline'; connect-src 'none'; frame-src 'none'; worker-src 'none'; object-src 'none'; base-uri 'none'"
                        outgoing["content-security-policy"] = (outgoing.get("content-security-policy", "") + ", " if outgoing.get("content-security-policy") else "") + restriction
                        await route.fulfill(status=response["status"], headers=outgoing, body=response["body"])
                    except Exception as error:
                        failure = type(error).__name__
                        runner.stopped = True
                        await route.abort("blockedbyclient")

                await context.route("**/*", intercept)

                async def close_socket(websocket):
                    await websocket.close()

                await context.route_web_socket("**/*", close_socket)
                target = case["url"] + ("#" + quote(value, safe="") if case["context"] == "dom-fragment" else "?" + urlencode({case["parameter"]: value}))
                try:
                    response = await page.goto(target, wait_until="load", timeout=10000)
                    if response is None or response.status != 200 or failure:
                        raise ValueError("XSS document unavailable")
                    await page.wait_for_timeout(100)
                    runner.check()
                    signals.append(await page.evaluate("token => globalThis.__hunterqa_context === token", token))
                except Exception as error:
                    return {"state": "inconclusive", "receipts": receipts, "execution_signals": signals,
                        "error_type": failure or type(error).__name__, "customer_vulnerability_confirmed": False}
                finally:
                    await context.close()
        finally:
            await browser.close()
    controls = not any(signals[i] for i in (0, 2, 4))
    stable = signals[1] == signals[3]
    return {"state": "matched" if signals == [False, True, False, True, False] else "not_observed" if controls and stable else "inconclusive",
        "receipts": receipts, "execution_signals": signals, "repeat_consistent": stable,
        "evidence_level": "fixed-browser-context-execution", "customer_vulnerability_confirmed": False}
