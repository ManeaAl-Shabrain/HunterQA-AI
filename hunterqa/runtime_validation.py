"""Fixed, explicitly approved canary validation; never accepts caller payloads."""
from __future__ import annotations

import asyncio
import hashlib
import html
import os
import re
import secrets

SQL_INPUTS = ("hq_missing", "hq_missing' OR 'hq'='hq' -- ",
              "hq_missing' AND 'hq'='no' -- ", "hq_missing' OR 'hq'='hq' -- ", "hq_missing")
CASE_NAMES = ("baseline", "probe", "negative", "probe-repeat", "baseline-repeat")
EXPECTED_PATTERN = [False, True, False, True, False]


def validate_contract(policy, step, plan):
    contract = step.get("validation")
    sql = step["mode"] == "sql-canary-check"
    fields = {"parameter", "owned_test_endpoint", "canary_marker"} if sql else {"parameter", "owned_test_endpoint"}
    if (not isinstance(contract, dict) or set(contract) != fields
            or contract["owned_test_endpoint"] is not True
            or not isinstance(contract["parameter"], str)
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", contract["parameter"]) is None):
        raise ValueError("Explicit owned endpoint and bounded parameter contract required")
    if sql and (not isinstance(contract["canary_marker"], str)
                or re.fullmatch(r"HUNTERQA_CANARY_[A-Za-z0-9]{16,32}", contract["canary_marker"]) is None):
        raise ValueError("SQL check needs an owner-installed public synthetic canary marker")
    if step["method"] != "GET" or len(plan["steps"]) != 1 or policy.max_requests < 5:
        raise ValueError("Runtime validation requires one GET step and at least five requests")
    parts, host, _, _ = policy.authorize_url(step["url"], "GET")
    if parts.scheme != "https" and not (host == "127.0.0.1" and policy.platform == "local-lab"
                                          and policy.lab_mode and set(policy.allowed_hosts) == {host}):
        raise ValueError("Runtime validation requires HTTPS or an explicitly owned loopback lab")
    if not sql and not plan["browser_isolated"]:
        raise ValueError("XSS execution checks require browser isolation attestation")


def _receipt(name, value, response):
    if (not isinstance(response, dict) or type(response.get("status")) is not int
            or not 100 <= response["status"] <= 599 or not isinstance(response.get("body"), bytes)
            or len(response["body"]) > 1_048_576):
        raise ValueError("Invalid bounded runtime response")
    return {"case": name, "input_sha256": hashlib.sha256(value.encode()).hexdigest(),
            "status": response["status"], "body_sha256": hashlib.sha256(response["body"]).hexdigest(),
            "body_bytes": len(response["body"])}


def _result(kind, receipts, signals, stopped):
    complete = len(receipts) == len(signals) == 5 and not stopped
    controls = complete and not any(signals[i] for i in (0, 2, 4))
    stable = complete and signals[1] == signals[3]
    matched = controls and stable and signals == EXPECTED_PATTERN
    state = "matched" if matched else "not_observed" if controls and stable else "inconclusive"
    return {"validation_kind": kind, "state": state, "receipts": receipts,
            "control_cases_passed": bool(controls), "repeat_consistent": bool(stable),
            "evidence_level": "controlled_sql_behavior" if kind == "sql" else "browser_canary_execution",
            "review_required": True, "customer_vulnerability_confirmed": False,
            "scope": "reviewed owned test endpoint only", "real_world_effectiveness": "unverified"}


def retained_state(validation, kind, stopped):
    """Recompute a result from bounded receipts, not from its saved state label."""
    if (not isinstance(validation, dict) or validation.get("validation_kind") != kind
            or validation.get("customer_vulnerability_confirmed") is not False
            or validation.get("real_world_effectiveness") != "unverified"):
        raise ValueError("Invalid retained validation claims")
    receipts = validation.get("receipts")
    if not isinstance(receipts, list) or len(receipts) > 5:
        raise ValueError("Invalid retained receipt count")
    signals = []
    signal = "canary_present" if kind == "sql" else "execution_observed"
    base = {"case", "input_sha256", "status", "body_sha256", "body_bytes"}
    for index, receipt in enumerate(receipts):
        if (not isinstance(receipt, dict) or set(receipt) not in (base, base | {signal})
                or receipt["case"] != CASE_NAMES[index]
                or type(receipt["status"]) is not int or not 100 <= receipt["status"] <= 599
                or type(receipt["body_bytes"]) is not int or not 0 <= receipt["body_bytes"] <= 1_048_576
                or any(not isinstance(receipt[k], str) or re.fullmatch(r"[0-9a-f]{64}", receipt[k]) is None
                       for k in ("input_sha256", "body_sha256"))):
            raise ValueError("Invalid retained receipt")
        if kind == "sql" and receipt["input_sha256"] != hashlib.sha256(SQL_INPUTS[index].encode()).hexdigest():
            raise ValueError("SQL receipt does not match the fixed input")
        if signal in receipt:
            if type(receipt[signal]) is not bool:
                raise ValueError("Invalid retained witness")
            if receipt[signal] and receipt["body_bytes"] < (31 if kind == "sql" else 1):
                raise ValueError("Witness is inconsistent with the response length")
            signals.append(receipt[signal])
        elif index != len(receipts) - 1 or not stopped:
            raise ValueError("Missing execution witness in completed receipt")
    if kind == "xss" and len(receipts) == 5:
        for first, second in ((0, 4), (1, 3)):
            if receipts[first]["input_sha256"] != receipts[second]["input_sha256"]:
                raise ValueError("XSS repeat input hashes differ")
    expected = _result(kind, receipts, signals, stopped or any(r["status"] != 200 for r in receipts))
    for key in ("state", "control_cases_passed", "repeat_consistent", "evidence_level",
                "review_required", "customer_vulnerability_confirmed", "scope", "real_world_effectiveness"):
        if type(validation.get(key)) is not type(expected[key]) or validation[key] != expected[key]:
            raise ValueError("Retained validation result differs from its receipts")
    return expected["state"]


def check_sql(policy, step, gate, *, transport):
    """Observe a public synthetic canary, never export rows or response contents."""
    receipts, signals = [], []
    marker = step["validation"]["canary_marker"].encode()
    for name, value in zip(CASE_NAMES, SQL_INPUTS):
        try:
            gate.admit()
            response = transport(policy, step["url"], "GET", body=None, headers={},
                                 query={step["validation"]["parameter"]: value})
            receipt = _receipt(name, value, response)
            gate.response(receipt["status"])
            receipt["canary_present"] = marker in response["body"]
            receipts.append(receipt)
            signals.append(receipt["canary_present"])
            if receipt["status"] != 200:
                gate.stopped = True
            if gate.stopped:
                break
        except Exception as exc:
            gate.stopped = True
            result = _result("sql", receipts, signals, True)
            result["error_type"] = type(exc).__name__
            return result
    return _result("sql", receipts, signals, gate.stopped)


def check_xss(policy, step, gate, *, transport):
    for key in ("HUNTERQA_TEST_USERNAME", "HUNTERQA_TEST_PASSWORD", "HUNTERQA_LAB_USERNAME", "HUNTERQA_LAB_PASSWORD"):
        os.environ.pop(key, None)
    return asyncio.run(_check_xss(policy, step, gate, transport=transport))


async def _check_xss(policy, step, gate, *, transport):
    from playwright.async_api import async_playwright
    token = secrets.token_hex(16)
    payload = '<svg onload="globalThis.__hunterqa_runtime=\'' + token + '\'"></svg>'
    inputs = (token, payload, html.escape(payload), payload, token)
    receipts, signals = [], []
    failure = None
    async with async_playwright() as driver:
        browser = await driver.chromium.launch(headless=True,
            args=["--disable-background-networking", "--disable-sync"])
        try:
            for name, value in zip(CASE_NAMES, inputs):
                context = await browser.new_context(service_workers="block", accept_downloads=False,
                    ignore_https_errors=False, permissions=[])
                sent = False
                try:
                    async def route_check(route):
                        nonlocal sent, failure
                        request = route.request
                        if (sent or request.method != "GET" or request.url != step["url"]
                                or request.frame != page.main_frame or request.resource_type != "document"):
                            await route.abort("blockedbyclient")
                            return
                        try:
                            gate.admit()
                            sent = True
                            response = transport(policy, step["url"], "GET", body=None, headers={},
                                                 query={step["validation"]["parameter"]: value})
                            receipts.append(_receipt(name, value, response))
                            gate.response(response["status"])
                            if response["status"] != 200:
                                gate.stopped = True
                            if gate.stopped:
                                await route.abort("blockedbyclient")
                                return
                            headers = {}
                            for key, header in response["headers"]:
                                key = key.lower()
                                if key in {"content-type", "content-encoding", "content-security-policy", "x-content-type-options"}:
                                    headers[key] = headers[key] + ", " + header if key in headers else header
                            extra = ("default-src 'none'; script-src 'unsafe-inline'; "
                                     "connect-src 'none'; form-action 'none'; base-uri 'none'; "
                                     "frame-src 'none'; worker-src 'none'; object-src 'none'")
                            prior = headers.get("content-security-policy")
                            headers["content-security-policy"] = (prior + ", " if prior else "") + extra
                            await route.fulfill(status=200, headers=headers, body=response["body"])
                        except Exception as exc:
                            failure = type(exc).__name__
                            gate.stopped = True
                            await route.abort("blockedbyclient")
                    await context.route("**/*", route_check)
                    async def close_socket(socket):
                        await socket.close()
                    await context.route_web_socket("**/*", close_socket)
                    page = await context.new_page()
                    gate.check()
                    await page.goto(step["url"], wait_until="domcontentloaded", timeout=12_000)
                    await page.wait_for_timeout(100)
                    gate.check()
                    executed = await asyncio.wait_for(page.evaluate(
                        "token => globalThis.__hunterqa_runtime === token", token), timeout=3)
                    if type(executed) is not bool or not sent:
                        raise RuntimeError("Invalid execution witness")
                    signals.append(executed)
                    receipts[-1]["execution_observed"] = executed
                except Exception as exc:
                    failure = failure or type(exc).__name__
                    gate.stopped = True
                finally:
                    await asyncio.wait_for(context.close(), timeout=5)
                if gate.stopped:
                    break
        finally:
            await asyncio.wait_for(browser.close(), timeout=5)
    result = _result("xss", receipts, signals, gate.stopped)
    if failure:
        result["error_type"] = failure
    result["browser_context"] = "fresh_per_case_no_storage_export"
    result["location_query_available_to_page"] = False
    return result
