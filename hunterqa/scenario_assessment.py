"""Fingerprint-approved, bounded test workflows and controlled runtime probes."""
import hashlib
import hmac
import http.client
import math
import re
import time
from urllib.parse import urlencode, urlsplit

from . import assessment_sessions, cloud_transport, shared_quota
from .bounty import BountyPolicy, _approved_file, _decode_json, resolve_pinned
from .engagement import _expiry, digest, utcnow
from .operator_oidc import _Connection, _dial
from .source_files import read_bounded

KINDS = {"workflow", "browser-journey", "xss-context", "sqli-boolean", "sqli-timing", "ssrf-callback", "upload-canary"}
SHA = re.compile(r"[a-f0-9]{64}\Z")
ID = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")


def fields(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("Unknown or missing scenario fields")


def url_origin(url):
    parts = urlsplit(url)
    return parts.scheme + "://" + parts.netloc


def scoped(policy, url):
    if not isinstance(url, str):
        raise ValueError("Expected a reviewed URL")
    clean = url.replace("{canary}", "0" * 32)
    parts, host, _, _ = policy.authorize_url(clean, "GET")
    if parts.scheme != "https" and not (host == "127.0.0.1" and policy.platform == "local-lab" and policy.lab_mode):
        raise ValueError("Use HTTPS or an owned numeric-loopback test lab")
    return clean


def parameters(value):
    if value is None:
        return
    if (not isinstance(value, dict) or len(value) > 20 or any(not isinstance(k, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", k)
            or not isinstance(v, str) or len(v) > 1024 or any(ord(c) < 32 for c in v) for k, v in value.items())):
        raise ValueError("Use bounded reviewed non-secret parameters")


def load(profile_file, plan_file, *, session_file=None, session_key=None):
    profile_raw = read_bounded(_approved_file(profile_file), 65536)
    profile = _decode_json(profile_raw)
    policy = BountyPolicy.from_dict(profile)
    methods = profile.get("scenario_methods", ["GET"])
    if (not isinstance(methods, list) or not 1 <= len(methods) <= 2 or any(value not in {"GET", "POST"} for value in methods)
            or len(set(methods)) != len(methods) or "GET" not in methods):
        raise ValueError("Explicit scenario GET/POST scope required")
    raw = read_bounded(_approved_file(plan_file), 131072)
    plan = _decode_json(raw)
    fields(plan, {"schema_version", "authorization_reference", "expires_at", "timeout_seconds", "max_requests", "browser_isolated", "cases"})
    if (type(plan["schema_version"]) is not int or plan["schema_version"] != 1
            or plan["authorization_reference"] != policy.authorization_reference
            or not 0 < (_expiry(plan["expires_at"]) - utcnow()).total_seconds() <= 86400
            or type(plan["timeout_seconds"]) is not int or not 1 <= plan["timeout_seconds"] <= 300
            or type(plan["max_requests"]) is not int or not 1 <= plan["max_requests"] <= policy.max_requests
            or type(plan["browser_isolated"]) is not bool or not isinstance(plan["cases"], list) or not 1 <= len(plan["cases"]) <= 10):
        raise ValueError("Invalid scenario authorization window or limits")
    if (session_file is None) != (session_key is None):
        raise ValueError("Supply both encrypted session and separate key")
    actors, session_hash = assessment_sessions.load(session_file, session_key) if session_file is not None else ({}, None)
    ids, reserved = set(), 0

    def actor(name, target):
        if name != "anonymous" and (name not in actors or actors[name]["origin"] != url_origin(target)):
            raise ValueError("Actor state is unavailable or belongs to another origin")

    for case in plan["cases"]:
        if (not isinstance(case, dict) or not isinstance(case.get("id"), str) or not ID.fullmatch(case["id"])
                or case["id"] in ids or case.get("kind") not in KINDS or case.get("owned_test_endpoint") is not True):
            raise ValueError("Explicitly owned test endpoint and unique case ID required")
        ids.add(case["id"])
        base = {"id", "kind", "owned_test_endpoint"}
        kind = case["kind"]
        if kind == "workflow":
            fields(case, base | {"steps"})
            if not isinstance(case["steps"], list) or not 1 <= len(case["steps"]) <= 20:
                raise ValueError("Bounded workflow steps required")
            for step in case["steps"]:
                fields(step, {"url", "method", "actor", "query", "form", "expected_status", "expected_body_sha256"})
                scoped(policy, step["url"])
                actor(step["actor"], step["url"])
                parameters(step["query"])
                parameters(step["form"])
                if (step["method"] not in methods or (step["method"] == "GET" and step["form"] is not None)
                        or type(step["expected_status"]) is not int or step["expected_status"] not in {200, 201, 204, 400, 401, 403, 404, 409, 422}
                        or (step["expected_body_sha256"] is not None and (not isinstance(step["expected_body_sha256"], str) or not SHA.fullmatch(step["expected_body_sha256"])))
                        or (step["expected_status"] in {200, 201} and step["expected_body_sha256"] is None)):
                    raise ValueError("Workflow success requires an explicit response fingerprint")
            reserved += len(case["steps"])
        elif kind == "browser-journey":
            from .scenario_browser import validate
            validate(case, policy, actor, plan["browser_isolated"])
            if any(rule["method"] not in methods for rule in case["allowed_requests"]):
                raise ValueError("Browser method is outside explicit scenario scope")
            reserved += case["request_budget"]
        else:
            extras = {"actor", "url", "parameter"}
            if kind == "sqli-boolean":
                extras |= {"context", "canary_marker"}
            elif kind == "xss-context":
                extras |= {"context", "script_urls"}
            elif kind == "sqli-timing":
                extras |= {"dialect", "single_row_fixture"}
            elif kind == "ssrf-callback":
                extras |= {"collector_actor", "receive_url", "read_url"}
            elif kind == "upload-canary":
                extras = {"actor", "url", "resource_url", "cleanup_url"}
            fields(case, base | extras)
            scoped(policy, case["url"])
            actor(case["actor"], case["url"])
            if "parameter" in case and (not isinstance(case["parameter"], str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", case["parameter"])):
                raise ValueError("Invalid probe parameter")
            if kind == "sqli-boolean" and (case["context"] not in {"single-quoted", "double-quoted", "numeric"}
                    or not isinstance(case["canary_marker"], str) or not re.fullmatch(r"HUNTERQA_CANARY_[A-Za-z0-9]{16,32}", case["canary_marker"])):
                raise ValueError("SQL checks require a public owner-installed canary")
            if kind == "xss-context":
                if (not plan["browser_isolated"] or case["context"] not in {"html", "double-attribute", "single-attribute", "dom-fragment"}
                        or not isinstance(case["script_urls"], list) or len(case["script_urls"]) > 5
                        or len(set(case["script_urls"])) != len(case["script_urls"])):
                    raise ValueError("XSS contexts require isolation and reviewed script resources")
                for script_url in case["script_urls"]:
                    scoped(policy, script_url)
                    if url_origin(script_url) != url_origin(case["url"]):
                        raise ValueError("XSS scripts must stay in the test origin")
            if kind == "sqli-timing" and (case["dialect"] not in {"mysql", "postgresql", "mssql"} or case["single_row_fixture"] is not True):
                raise ValueError("Timing checks require an explicit dialect and single-row owned fixture")
            if kind == "ssrf-callback":
                for key in ("receive_url", "read_url"):
                    scoped(policy, case[key])
                actor(case["collector_actor"], case["read_url"])
                if (len(case["receive_url"]) > 160 or url_origin(case["receive_url"]) != url_origin(case["read_url"])
                        or url_origin(case["receive_url"]) == url_origin(case["url"])):
                    raise ValueError("Use a separately scoped owned callback collector origin")
            if kind == "upload-canary":
                if "POST" not in methods:
                    raise ValueError("Uploads require explicit POST scope")
                for key in ("resource_url", "cleanup_url"):
                    scoped(policy, case[key])
                    actor(case["actor"], case[key])
                if "{canary}" not in case["resource_url"]:
                    raise ValueError("Use a unique canary resource path")
            reserved += 3 if kind == "ssrf-callback" else 5 * (1 + len(case["script_urls"])) if kind == "xss-context" else 5
    if reserved > plan["max_requests"]:
        raise ValueError("Scenario reservations exceed the approved budget")
    fingerprint = digest({"profile_sha256": hashlib.sha256(profile_raw).hexdigest(), "plan_sha256": hashlib.sha256(raw).hexdigest(),
        "session_binding": session_hash, "shared_quota": shared_quota.configured_review(), "runtime": runtime_identity()})
    plan["_scope_methods"] = methods
    return policy, plan, actors, fingerprint


def runtime_identity():
    from importlib.metadata import PackageNotFoundError, version
    from .workflow_runner import _runtime_identity
    components = {}
    for name in ("cryptography", "playwright"):
        try:
            components[name] = version(name)
        except PackageNotFoundError:
            components[name] = None
    return digest({"application": _runtime_identity(), "scenario_components": components})


def preflight(profile_file, plan_file, **sessions):
    _, plan, _, fingerprint = load(profile_file, plan_file, **sessions)
    return {"approval_sha256": fingerprint, "network_requests": 0, "max_requests": plan["max_requests"],
        "cases": [{"id": row["id"], "kind": row["kind"]} for row in plan["cases"]], "allowed_methods": plan["_scope_methods"], "review_required": True}


class _HTTP(http.client.HTTPConnection):
    def __init__(self, host, ip, port, end):
        super().__init__(host, port, timeout=5)
        self.ip, self.end = ip, end

    def connect(self):
        end = min(cloud_transport.deadline(), self.end)
        self.sock = cloud_transport.DeadlineSocket(_dial(self.ip, self.port, end), end)


class _TLS(_Connection):
    def __init__(self, host, ip, port, end):
        super().__init__(host, ip, port)
        self.end = end

    def connect(self):
        end = min(cloud_transport.deadline(), self.end)
        self.sock = cloud_transport.finish_tls(_dial(self.ip, self.port, end), self._context, self.host, end)


def transport(policy, url, method, *, body=None, headers=None, query=None, deadline=None):
    parts, host, port, path = policy.authorize_url(url, "GET")
    if method not in {"GET", "POST"}:
        raise ValueError("Unsupported scenario method")
    if query:
        path += "?" + urlencode(query)
    end = min(deadline if deadline is not None else cloud_transport.deadline(), cloud_transport.deadline())
    ip = resolve_pinned(policy, host, port)
    connection = _TLS(host, ip, port, end) if parts.scheme == "https" else _HTTP(host, ip, port, end)
    try:
        connection.request(method, path, body=body, headers={"User-Agent": "HunterQA-owned-scenario", "Accept-Encoding": "identity", "Connection": "close", **(headers or {})})
        response = connection.getresponse()
        response_headers = response.getheaders()
        result = cloud_transport.read_response(response, 1048576)
        result["headers"] = response_headers
        return result
    finally:
        connection.close()


class Runner:
    def __init__(self, profile_file, plan_file, fingerprint, policy, plan, actors, sessions, admission, stop_file, send, sleeper):
        self.inputs = profile_file, plan_file
        self.fingerprint, self.policy, self.plan, self.actors, self.sessions = fingerprint, policy, plan, actors, sessions
        self.admission, self.stop_file, self.send, self.sleeper = admission, stop_file, send, sleeper
        self.end, self.last, self.count, self.stopped = time.monotonic() + plan["timeout_seconds"], None, 0, False
        self.cookies = {}

    def check(self):
        self.admission.ensure_active()
        if (self.stopped or self.stop_file.exists() or time.monotonic() >= self.end
                or load(*self.inputs, **self.sessions)[3] != self.fingerprint):
            self.stopped = True
            raise PermissionError("Scenario stopped, changed or expired")

    def request(self, url, actor="anonymous", method="GET", *, query=None, form=None, body=None, headers=None, cookies=True):
        self.check()
        if method not in self.plan["_scope_methods"]:
            raise PermissionError("Method outside the approved scenario scope")
        if self.count >= self.plan["max_requests"]:
            self.stopped = True
            raise PermissionError("Scenario request budget exhausted")
        if self.last is not None:
            delay = max(0, self.policy.interval_seconds - (time.monotonic() - self.last))
            while delay > 0:
                self.sleeper(min(delay, 0.1))
                self.check()
                delay -= min(delay, 0.1)
        self.check()
        credentials = {} if actor == "anonymous" else self.actors[actor]["headers"]
        if actor != "anonymous" and self.actors[actor]["origin"] != url_origin(url):
            raise PermissionError("Actor origin differs")
        outgoing = dict(headers or {})
        cookie_key = actor, url_origin(url)
        if cookie_key not in self.cookies:
            self.cookies[cookie_key] = {row["name"]: row for row in self.actors.get(actor, {}).get("cookies", [])}
        jar = self.cookies[cookie_key]
        request_path = urlsplit(url).path or "/"
        cookie = "; ".join(name + "=" + row["value"] for name, row in jar.items()
            if (not row["secure"] or url.startswith("https://")) and (request_path == row.get("path", "/")
                or request_path.startswith(row.get("path", "/").rstrip("/") + "/")))
        if actor != "anonymous" and cookies and cookie and not any(key.lower() == "cookie" for key in outgoing):
            outgoing["Cookie"] = cookie
        outgoing.update(credentials)
        if sum(len(key) + len(value) for key, value in outgoing.items()) > 32768:
            raise ValueError("Actor request headers exceed their bound")
        if form is not None:
            body = urlencode(form).encode()
            outgoing["Content-Type"] = "application/x-www-form-urlencoded"
        if body is not None and (not isinstance(body, bytes) or len(body) > 8192):
            raise ValueError("Scenario body exceeds its bound")
        self.count += 1
        self.last = time.monotonic()
        start = time.monotonic()
        end = min(self.end, time.monotonic() + (_expiry(self.plan["expires_at"]) - utcnow()).total_seconds())
        response = self.send(self.policy, url, method, body=body, headers=outgoing, query=query, deadline=end)
        elapsed = time.monotonic() - start
        if (not isinstance(response, dict) or type(response.get("status")) is not int or not 100 <= response["status"] <= 599
                or not isinstance(response.get("body"), bytes) or len(response["body"]) > 1048576 or not math.isfinite(elapsed)):
            raise ValueError("Invalid bounded scenario response")
        from http.cookies import CookieError, SimpleCookie
        for name, value in response.get("headers", []):
            if actor == "anonymous" or name.lower() != "set-cookie" or len(value) > 8192 or any(ord(c) < 32 for c in value):
                continue
            parsed = SimpleCookie()
            try:
                parsed.load(value)
            except CookieError:
                raise ValueError("Invalid actor cookie response") from None
            for name, morsel in parsed.items():
                if not morsel.value or not all(33 <= ord(c) < 127 and c not in ';,"\\' for c in morsel.value):
                    continue
                if morsel["domain"] and morsel["domain"].lstrip(".") != urlsplit(url).hostname:
                    continue
                if name not in jar and len(jar) >= 40:
                    raise ValueError("Actor cookie limit reached")
                if morsel["max-age"] == "0":
                    jar.pop(name, None)
                else:
                    jar[name] = {"value": morsel.value, "secure": bool(morsel["secure"]), "path": morsel["path"] or "/"}
        if sum(len(name) + len(row["value"]) for name, row in jar.items()) > 16384:
            raise ValueError("Actor cookie storage exceeds its bound")
        if response["status"] == 429 or response["status"] >= 500 or 300 <= response["status"] < 400:
            self.stopped = True
        self.check()
        receipt = {"target_sha256": digest(url), "actor": actor, "method": method, "status": response["status"],
            "body_sha256": hashlib.sha256(response["body"]).hexdigest(), "body_bytes": len(response["body"]), "elapsed_ms": round(elapsed * 1000, 3)}
        return response, receipt


def run(profile_file, plan_file, approval, *, authorized=False, session_file=None, session_key=None,
        stop_file="stop", send=transport, sleeper=time.sleep):
    if authorized is not True:
        raise PermissionError("Scenario execution requires --authorized")
    sessions = {"session_file": session_file, "session_key": session_key}
    policy, plan, actors, fingerprint = load(profile_file, plan_file, **sessions)
    if not isinstance(approval, str) or not hmac.compare_digest(approval, fingerprint):
        raise PermissionError("Approve the exact scenario/session/scope fingerprint")
    if not isinstance(stop_file, str) or not ID.fullmatch(stop_file):
        raise ValueError("Use a simple stop filename under the plan directory")
    report = {"engine": "approved-scenario-suite", "schema_version": 1, "approval_sha256": fingerprint,
        "cases": [], "requests": 0, "stopped": False, "review_required": True, "customer_vulnerabilities_confirmed": 0}
    with shared_quota.invocation(plan["max_requests"]) as admission:
        report["shared_quota"] = admission.receipt
        runner = Runner(profile_file, plan_file, fingerprint, policy, plan, actors, sessions, admission,
            _approved_file(plan_file).parent / stop_file, send, sleeper)
        for case in plan["cases"]:
            row = {"id": case["id"], "kind": case["kind"], "state": "inconclusive", "receipts": []}
            try:
                runner.check()
                if case["kind"] == "workflow":
                    row["state"] = "matched"
                    for step in case["steps"]:
                        _, receipt = runner.request(step["url"], step["actor"], step["method"], query=step["query"], form=step["form"])
                        row["receipts"].append(receipt)
                        if receipt["status"] != step["expected_status"] or (step["expected_body_sha256"] is not None and receipt["body_sha256"] != step["expected_body_sha256"]):
                            row["state"] = "different"
                            break
                elif case["kind"] == "browser-journey":
                    from .scenario_browser import execute
                    row.update(execute(case, runner))
                elif case["kind"] == "xss-context":
                    from .scenario_xss import execute
                    row.update(execute(case, runner))
                else:
                    from .scenario_probes import execute
                    row.update(execute(case, runner))
            except (ValueError, TypeError, KeyError, OSError, RuntimeError, http.client.HTTPException) as error:
                row["state"], row["error_type"] = "inconclusive", type(error).__name__
                runner.stopped = True
            report["cases"].append(row)
            if runner.stopped or row["state"] in {"inconclusive", "different"}:
                runner.stopped = True
                break
        report["requests"], report["stopped"] = runner.count, runner.stopped or len(report["cases"]) != len(plan["cases"])
    return report
