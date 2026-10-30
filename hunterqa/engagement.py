"""Expiring, fingerprint-approved assessments. No arbitrary tools or payloads.

Approval is a local operator attestation, not an authenticated permission grant.
Budgets apply per invocation; this module is not a multi-user authorization service.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

from .bounty import (BountyPolicy, MAX_PROFILE, _approved_file, _read_json, _PinnedHTTP,
                     _PinnedHTTPS, resolve_pinned)

ENGINE = "hunterqa_approved_assessment"
MODES = {"observe", "waf-canary", "auth-check", "browser", "browser-discovery"}
FIELDS = {"mode", "url", "method", "expected_status", "login_url", "discovery"}
MAX_PLAN_BYTES = 32_768


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def utcnow():
    return datetime.now(timezone.utc)


def _policy_snapshot(profile_path):
    # Parse and fingerprint the SAME bounded snapshot, including duplicate-key checks.
    with _approved_file(profile_path).open("rb") as stream:
        raw = stream.read(MAX_PROFILE + 1)
    if len(raw) > MAX_PROFILE:
        raise ValueError("Scope profile exceeds size limit")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key rejected")
            result[key] = value
        return result
    return (BountyPolicy.from_dict(json.loads(raw.decode("utf-8"), object_pairs_hook=unique)),
            hashlib.sha256(raw).hexdigest())


def _expiry(value):
    if not isinstance(value, str):
        raise ValueError("An explicit timezone-aware expires_at is required")
    try:
        result = datetime.fromisoformat(value)
        if result.tzinfo is None:
            raise ValueError("Missing timezone")
    except ValueError:
        raise ValueError("Invalid timezone-aware expires_at") from None
    return result


def load_plan(profile_path, plan_path, *, now=None):
    policy, profile_hash = _policy_snapshot(profile_path)
    plan = _read_json(plan_path, MAX_PLAN_BYTES)
    validate_plan(policy, plan, profile_hash, now=now)
    return policy, plan


def validate_plan(policy, plan, profile_hash, *, now=None):
    if len((json.dumps(plan, indent=2) + "\n").encode("utf-8")) > MAX_PLAN_BYTES:
        raise ValueError("Assessment plan exceeds size limit")
    if not isinstance(plan, dict) or set(plan) != {
        "schema_version", "policy_sha256", "expires_at", "authorization_reference",
        "dedicated_test_account", "browser_isolated", "steps",
    }:
        raise ValueError("Unknown or missing assessment plan fields")
    if type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
        raise ValueError("Unsupported assessment plan schema")
    if plan["policy_sha256"] != profile_hash:
        raise ValueError("Plan does not match the exact scope profile")
    if plan["authorization_reference"] != policy.authorization_reference:
        raise ValueError("Plan must retain the profile permission reference")
    for key in ("dedicated_test_account", "browser_isolated"):
        if type(plan[key]) is not bool:
            raise ValueError("Account and isolation attestations must be booleans")
    remaining = _expiry(plan["expires_at"]) - (now or utcnow())
    if not timedelta(0) < remaining <= timedelta(hours=24):
        raise ValueError("Plan must expire within the next 24 hours")
    steps = plan["steps"]
    if not isinstance(steps, list) or not 1 <= len(steps) <= min(20, policy.max_requests):
        raise ValueError("Expected 1..20 steps within the profile budget")
    credentials = 0
    for step in steps:
        if not isinstance(step, dict) or not set(step) <= FIELDS:
            raise ValueError("Unknown assessment step fields")
        mode = step.get("mode")
        if not isinstance(mode, str) or mode not in MODES:
            raise ValueError("Unsupported assessment mode")
        method = step.get("method")
        if method not in ("GET", "HEAD", "POST"):
            raise ValueError("Explicit GET/HEAD/POST method required")
        # POST is an explicit exception for ONE designated-account login only.
        parts, _, _, _ = policy.authorize_url(step.get("url"), "GET" if method == "POST" else method)
        if mode == "auth-check":
            if method != "POST" or not plan["dedicated_test_account"]:
                raise ValueError("auth-check requires POST and a dedicated test account")
            credentials += 1
        elif mode in {"browser", "browser-discovery"}:
            if method != "GET" or len(steps) != 1 or not plan["browser_isolated"] or parts.scheme != "https":
                raise ValueError("Browser must be the only step, HTTPS GET, and isolated")
            if step.get("login_url") is not None:
                login = policy.authorize_url(step["login_url"], "GET")[0]
                if (login.scheme, login.hostname, login.port) != (parts.scheme, parts.hostname, parts.port):
                    raise ValueError("Login must use the exact approved browser origin")
                if not plan["dedicated_test_account"]:
                    raise ValueError("Browser login requires a dedicated test account")
                credentials += 1
        elif method not in ("GET", "HEAD") or (mode == "waf-canary" and method != "GET"):
            raise ValueError("Observation uses HEAD/GET; WAF canary uses GET")
        if mode == "browser-discovery":
            from .scoped_rendered_discovery import validate_options
            validate_options(step.get("discovery"))
        elif "discovery" in step:
            raise ValueError("Discovery bounds apply only to browser-discovery")
        if "login_url" in step and mode not in {"browser", "browser-discovery"}:
            raise ValueError("login_url applies only to browser steps")
        expected = step.get("expected_status")
        if expected is not None and (type(expected) is not int or not 100 <= expected <= 599):
            raise ValueError("Expected status must be an HTTP status code")
        if (mode == "auth-check" or step.get("login_url")) and parts.scheme != "https":
            # Only the legacy browser-lab command supports plaintext lab login.
            raise ValueError("Assessment credentials require HTTPS")
    if credentials > 1:
        raise ValueError("Only one credential submission per assessment invocation")


def create_plan(profile_path, urls, *, mode="observe", method="GET", ttl_minutes=60,
                dedicated_test_account=False, browser_isolated=False, login_url=None,
                expected_status=None, discovery=None):
    if type(ttl_minutes) is not int or not 1 <= ttl_minutes <= 1440:
        raise ValueError("Plan lifetime must be 1..1440 minutes")
    policy, profile_hash = _policy_snapshot(profile_path)
    steps = [{"mode": mode, "url": url, "method": method} for url in urls]
    for step in steps:
        if discovery is not None:
            step["discovery"] = discovery
        elif mode == "browser-discovery":
            step["discovery"] = {"max_pages": 3, "max_depth": 1, "settle_ms": 250}
        if login_url is not None:
            step["login_url"] = login_url
        if expected_status is not None:
            step["expected_status"] = expected_status
    plan = {"schema_version": 1, "policy_sha256": profile_hash,
            "authorization_reference": policy.authorization_reference,
            "expires_at": (utcnow() + timedelta(minutes=ttl_minutes)).isoformat(),
            "dedicated_test_account": dedicated_test_account,
            "browser_isolated": browser_isolated, "steps": steps}
    validate_plan(policy, plan, profile_hash)
    return plan


class RunGate:
    def __init__(self, policy, plan, stop_file, *, sleeper=time.sleep, clock=time.monotonic):
        self.policy, self.plan = policy, plan
        self.stop_file = Path(stop_file)
        raw = os.environ.get("HUNTERQA_APPROVED_ROOTS", "")
        parent = self.stop_file.parent.resolve(strict=True)
        if not self.stop_file.is_absolute() or not any(
            parent.is_relative_to(Path(root).expanduser().resolve(strict=True))
            for root in raw.split(os.pathsep) if root
        ):
            raise ValueError("Stop file must be absolute and under approved roots")
        self.sleeper, self.clock = sleeper, clock
        self.count, self.last, self.stopped = 0, None, False

    def check(self):
        if self.stopped or self.stop_file.exists() or utcnow() >= _expiry(self.plan["expires_at"]):
            raise PermissionError("Assessment stopped or approval expired")

    def admit(self):
        self.check()
        if self.count >= min(20, self.policy.max_requests):
            raise PermissionError("Assessment request budget exhausted")
        if self.last is not None:
            delay = max(0, self.policy.interval_seconds - (self.clock() - self.last))
            # Check cancellation at least every 250 ms while waiting.
            while delay > 0:
                self.sleeper(min(delay, 0.25))
                self.check()
                delay -= min(delay, 0.25)
        self.check()
        self.last = self.clock()
        self.count += 1

    def response(self, status):
        if status in (401, 403, 429) or status >= 500 or 300 <= status < 400:
            self.stopped = True


def credentials():
    user = os.environ.get("HUNTERQA_TEST_USERNAME")
    secret = os.environ.get("HUNTERQA_TEST_PASSWORD")
    if not user or not secret or len(user) > 256 or len(secret) > 1024:
        raise ValueError("Set bounded HUNTERQA_TEST_USERNAME and HUNTERQA_TEST_PASSWORD")
    return user, secret


def pinned_request(policy, url, method, *, body=None, headers=None, query=None):
    """One pinned request; no retries, proxies, redirects, or TLS exceptions."""
    parts, host, port, path = policy.authorize_url(url, "GET" if method == "POST" else method)
    if query is not None:
        if (method != "GET" or not isinstance(query, dict) or len(query) != 1
                or any(not isinstance(k, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", k)
                       or not isinstance(v, str) or not 1 <= len(v) <= 256 for k, v in query.items())):
            raise ValueError("Only one bounded, explicitly reviewed GET query parameter is supported")
        path += "?" + urlencode(query)
    ip = resolve_pinned(policy, host, port)
    cls = _PinnedHTTPS if parts.scheme == "https" else _PinnedHTTP
    connection = cls(host, port, ip, timeout=5)
    try:
        outgoing = {"User-Agent": "HunterQA-AI approved-assessment", "Connection": "close",
                    "Accept-Encoding": "identity"}
        outgoing.update(headers or {})
        connection.request(method, path, body=body, headers=outgoing)
        response = connection.getresponse()
        data = response.read(1_048_577)
        if len(data) > 1_048_576:
            raise ValueError("Response exceeds assessment size limit")
        return {"status": int(response.status), "headers": response.getheaders(), "body": data}
    finally:
        connection.close()


def run_assessment(profile_path, plan_path, approval, stop_file, *, authorized=False,
                   transport=pinned_request, sleeper=time.sleep, browser_provider=None):
    if not authorized:
        raise PermissionError("Assessment requires --authorized")
    policy, plan = load_plan(profile_path, plan_path)
    fingerprint = digest(plan)
    if not isinstance(approval, str) or not hmac.compare_digest(approval, fingerprint):
        raise PermissionError("Approve the exact fingerprint shown by engagement-preflight")
    gate = RunGate(policy, plan, stop_file, sleeper=sleeper)
    observations = []
    for step in plan["steps"]:
        item = {"mode": step["mode"], "target_sha256": digest(step["url"]),
                "verification": "unverified_observation"}
        try:
            gate.check()
            if step["mode"] in {"browser", "browser-discovery"}:
                from .engagement_browser import inspect_browser
                item.update(inspect_browser(policy, step, gate, transport=transport,
                                            browser_provider=browser_provider))
            else:
                headers, body = {}, None
                if step["mode"] == "waf-canary":
                    # Operators configure their own WAF to recognize this benign marker.
                    headers["X-HunterQA-Test"] = "approved-benign-canary"
                if step["mode"] == "auth-check":
                    user, password = credentials()
                    body = urlencode({"username": user, "password": password}).encode()
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                gate.admit()
                result = transport(policy, step["url"], step["method"], body=body, headers=headers)
                status = result["status"]
                gate.response(status)
                item["status"] = status
                if "expected_status" in step:
                    item["expected_status_matches"] = status == step["expected_status"]
                if step["mode"] == "observe":
                    item["body_sha256"] = hashlib.sha256(result["body"]).hexdigest()
                if step["mode"] == "auth-check":
                    item["authentication"] = "attempted_unverified"
        except Exception as exc:
            # Network/browser errors may embed credentials, URLs, or DOM content.
            item["outcome"] = "stopped"
            item["error_type"] = type(exc).__name__
            gate.stopped = True
        observations.append(item)
        if gate.stopped:
            break
    return {"schema_version": 1, "engine": ENGINE, "plan_sha256": fingerprint,
            "policy_sha256": plan["policy_sha256"], "generated_at": utcnow().isoformat(),
            "requests": gate.count, "stopped": gate.stopped, "observations": observations,
            "review_required": True, "claims": {"verified_vulnerabilities": 0,
            "confirmed_zero_days": 0, "cve_ids_created": 0},
            "limitations": "Per-invocation budget. Approval is an operator attestation. "
            "Status matches do not prove WAF coverage, successful login, or a vulnerability. "
            "No retries, credential guessing, evasion, arbitrary exploits or submissions."}


def prepare_package(profile_path, dossier_path, *, kind, reviewed=False, authorized=False,
                    assigned_cve=None):
    """Offline reviewed handoff using the existing validated-case disclosure gate."""
    if not reviewed or not authorized:
        raise PermissionError("Package requires explicit review and authorization")
    if kind not in {"disclosure", "cve-request"}:
        raise ValueError("Unsupported handoff kind")
    if assigned_cve is not None and (kind != "cve-request" or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", assigned_cve)):
        raise ValueError("Invalid externally assigned CVE reference")
    from .verification_v12 import disclosure_draft
    draft = disclosure_draft(profile_path, dossier_path, authorized=True)
    return {"schema_version": 1, "engine": "hunterqa_reviewed_handoff", "kind": kind,
            "state": "prepared_for_manual_submission", "submitted": False,
            "draft": draft, "draft_sha256": hashlib.sha256(draft.encode()).hexdigest(),
            "externally_assigned_cve": assigned_cve, "assignment_verified": False,
            "limitations": "No report sent. CVE references are operator-provided and unverified. "
            "Only authorized numbering authorities assign official CVE IDs."}
