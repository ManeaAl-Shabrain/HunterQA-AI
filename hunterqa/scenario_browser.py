"""Reviewed app-origin JS actions using pinned native HTTP and ephemeral state."""
import asyncio
import os
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from .engagement import digest


def validate(case, policy, actor, isolated):
    from .scenario_assessment import fields, scoped, url_origin
    fields(case, {"id", "kind", "owned_test_endpoint", "actor", "url", "allowed_requests", "request_budget", "actions"})
    scoped(policy, case["url"])
    actor(case["actor"], case["url"])
    if not isolated or type(case["request_budget"]) is not int or not 1 <= case["request_budget"] <= 40:
        raise ValueError("Browser actions require isolation attestation and a request budget")
    rules = case["allowed_requests"]
    if not isinstance(rules, list) or not 1 <= len(rules) <= 30:
        raise ValueError("Explicit bounded request rules required")
    seen = set()
    for rule in rules:
        fields(rule, {"url", "method", "query_keys"})
        scoped(policy, rule["url"])
        key = rule["url"], rule["method"]
        if (url_origin(rule["url"]) != url_origin(case["url"]) or rule["method"] not in {"GET", "POST"}
                or key in seen or not isinstance(rule["query_keys"], list) or len(rule["query_keys"]) > 20
                or any(not isinstance(value, str) or not 1 <= len(value) <= 64 for value in rule["query_keys"])):
            raise ValueError("Browser requests must use unique reviewed same-origin rules")
        seen.add(key)
    if (case["url"], "GET") not in seen:
        raise ValueError("Review the initial document request")
    if not isinstance(case["actions"], list) or not 1 <= len(case["actions"]) <= 20:
        raise ValueError("Define bounded browser actions")
    for action in case["actions"]:
        fields(action, {"action", "selector", "value"})
        if (action["action"] not in {"click", "fill", "select", "check", "assert-text", "assert-count"}
                or not isinstance(action["selector"], str) or not 1 <= len(action["selector"]) <= 256
                or not isinstance(action["value"], str) or len(action["value"]) > 1024):
            raise ValueError("Unsupported selector action; arbitrary scripts are not accepted")
        if action["action"] == "assert-count" and action["value"] not in {str(i) for i in range(101)}:
            raise ValueError("Bound assertion count")


def execute(case, runner):
    try:
        return asyncio.run(_execute(case, runner))
    except Exception as error:
        raise RuntimeError("Browser scenario failed: " + type(error).__name__) from None


async def _execute(case, runner):
    from playwright.async_api import async_playwright, expect
    from .scenario_assessment import scoped, url_origin
    receipts, actions, discovered = [], [], set()
    blocked, failed = 0, None
    start_count = runner.count
    actor = runner.actors.get(case["actor"])
    state = {"cookies": [], "origins": []}
    if actor:
        state["cookies"] = [{**cookie, "domain": urlsplit(actor["origin"]).hostname, "path": "/", "expires": -1} for cookie in actor["cookies"]]
        state["origins"] = [{"origin": actor["origin"], "localStorage": [{"name": k, "value": v} for k, v in actor["local_storage"].items()]}]
    child_env = {k: v for k, v in os.environ.items() if k.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE", "LOCALAPPDATA", "PLAYWRIGHT_BROWSERS_PATH"}}
    async with async_playwright() as driver:
        browser = await driver.chromium.launch(headless=True, env=child_env, args=["--disable-background-networking", "--disable-sync"])
        try:
            context = await browser.new_context(storage_state=state, service_workers="block", accept_downloads=False, permissions=[])
            page = await context.new_page()

            async def close_popup(other):
                if other != page:
                    runner.stopped = True
                    await other.close()

            context.on("page", close_popup)

            async def intercept(route):
                nonlocal blocked, failed
                request = route.request
                try:
                    parts = urlsplit(request.url)
                    clean = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
                    scoped(runner.policy, clean)
                    rule = next((row for row in case["allowed_requests"] if row["url"] == clean and row["method"] == request.method), None)
                    query = parse_qsl(parts.query, keep_blank_values=True, max_num_fields=20)
                    if (not rule or request.frame != page.main_frame or url_origin(clean) != url_origin(case["url"])
                            or request.resource_type not in {"document", "script", "stylesheet", "fetch", "xhr"}
                            or len(set(k for k, _ in query)) != len(query) or set(k for k, _ in query) - set(rule["query_keys"])
                            or any(len(v) > 1024 for _, v in query) or runner.count - start_count >= case["request_budget"]):
                        raise PermissionError("Unreviewed browser operation")
                    outgoing = {k: v for k, v in (await request.all_headers()).items() if k.lower() in {"cookie", "content-type", "accept", "origin", "referer"}}
                    response, receipt = runner.request(clean, case["actor"], request.method, query=dict(query) or None,
                        body=request.post_data_buffer, headers=outgoing, cookies=False)
                    receipts.append(receipt)
                    headers = {}
                    for key, value in response.get("headers", []):
                        key = key.lower()
                        if key in {"content-type", "set-cookie", "cache-control", "content-security-policy"}:
                            headers[key] = headers[key] + "\n" + value if key == "set-cookie" and key in headers else value
                    confinement = "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-src 'none'; worker-src 'none'; object-src 'none'; base-uri 'none'"
                    headers["content-security-policy"] = (headers.get("content-security-policy", "") + ", " if headers.get("content-security-policy") else "") + confinement
                    await route.fulfill(status=response["status"], headers=headers, body=response["body"])
                except Exception as error:
                    blocked += 1
                    failed = type(error).__name__
                    runner.stopped = True
                    await route.abort("blockedbyclient")

            await context.route("**/*", intercept)

            async def close_socket(websocket):
                await websocket.close()

            await context.route_web_socket("**/*", close_socket)
            try:
                await page.goto(case["url"], wait_until="networkidle", timeout=10000)
                for action in case["actions"]:
                    runner.check()
                    locator = page.locator(action["selector"])
                    name, value = action["action"], action["value"]
                    if name == "click":
                        await locator.click(timeout=3000)
                    elif name == "fill":
                        await locator.fill(value, timeout=3000)
                    elif name == "select":
                        await locator.select_option(value, timeout=3000)
                    elif name == "check":
                        await locator.check(timeout=3000)
                    elif name == "assert-text":
                        await expect(locator).to_contain_text(value, timeout=3000)
                    elif name == "assert-count":
                        await expect(locator).to_have_count(int(value), timeout=3000)
                    actions.append({"action": name, "selector_sha256": digest(action["selector"]), "completed": True})
                    links = await page.locator("a[href]").evaluate_all("els => els.slice(0,200).map(e=>e.href).filter(v=>v.length<=2048)")
                    for link in links:
                        try:
                            parts = urlsplit(link)
                            clean = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
                            scoped(runner.policy, clean)
                            if url_origin(clean) == url_origin(case["url"]):
                                discovered.add(digest(link))
                        except ValueError:
                            pass
                    runner.check()
                return {"state": "matched", "receipts": receipts, "actions": actions, "discovered_routes_sha256": sorted(discovered),
                    "blocked_requests": blocked, "evidence_level": "reviewed-app-state-transitions", "customer_vulnerability_confirmed": False}
            except Exception as error:
                return {"state": "inconclusive", "receipts": receipts, "actions": actions, "blocked_requests": blocked,
                    "error_type": failed or type(error).__name__, "discovered_routes_sha256": sorted(discovered)}
            finally:
                await context.close()
        finally:
            await browser.close()
