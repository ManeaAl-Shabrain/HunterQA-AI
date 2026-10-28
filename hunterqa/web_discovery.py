"""Bounded same-origin HTML discovery. No JS, sessions or form submissions."""
from __future__ import annotations

import hashlib
import math
import time
from collections import deque
from datetime import timedelta
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

from .bounty import inspect_headers
from .engagement import _policy_snapshot, digest, pinned_request, utcnow
from .workflow_network import NetworkJournal
from .workflow_store import approved_directory, private_write

MAX_PAGES = 20
MAX_URL = 1024
MAX_CANDIDATES = 200
MAX_FORMS = 100


def origin(url):
    parts = urlsplit(url)
    return parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)


def admit_url(policy, value, base, origins):
    if not isinstance(value, str) or not value or len(value) > MAX_URL:
        return None
    # Do not silently turn a captured query into a different request.
    try:
        candidate = urljoin(base, value)
        parts = urlsplit(candidate)
        if parts.query or parts.username is not None or parts.password is not None:
            return None
        candidate = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))
        if len(candidate) > MAX_URL or origin(candidate) not in origins:
            return None
        policy.authorize_url(candidate, "GET")
    except ValueError:
        return None
    return candidate


class PageInventory(HTMLParser):
    """Collect endpoint hints only; never retain field names/values or script."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.forms, self.base = [], [], None
        self.current_form = None
        self.truncated = False

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "base" and self.base is None:
            self.base = values.get("href")
        if tag in ("a", "area") and values.get("href"):
            if len(self.links) < MAX_CANDIDATES:
                self.links.append(values["href"][:MAX_URL + 1])
            else:
                self.truncated = True
        if tag == "form":
            if len(self.forms) < MAX_FORMS:
                method = str(values.get("method", "get")).upper()
                self.current_form = {"action": values.get("action", ""),
                                     "method": method if method in ("GET", "POST", "DIALOG") else "UNKNOWN",
                                     "input_types": [], "field_count": 0}
                self.forms.append(self.current_form)
            else:
                self.current_form = None
                self.truncated = True
        if tag in ("input", "select", "textarea", "button") and self.current_form is not None:
            self.current_form["field_count"] += 1
            kind = str(values.get("type", "text")) if tag == "input" else tag
            if kind not in {"text", "password", "hidden", "email", "number", "checkbox", "radio",
                            "file", "submit", "button", "select", "textarea", "search", "url", "tel"}:
                kind = "other"
            if kind not in self.current_form["input_types"]:
                self.current_form["input_types"].append(kind)

    def handle_endtag(self, tag):
        if tag == "form":
            self.current_form = None


def discover(request, *, transport=pinned_request, sleeper=time.sleep):
    from .bounty import BountyPolicy
    policy = BountyPolicy.from_dict(request["policy"])
    step, binding = request["step"], request["binding"]
    origins = {origin(url) for url in step["targets"]}
    queue = deque((url, 0) for url in step["targets"])
    queued = set(step["targets"])
    visited, pages, endpoints, forms, findings = [], [], {}, [], []
    skipped = 0
    truncated = False
    safety_stop = False
    journal = NetworkJournal(request["network_log"])
    try:
        while queue and len(visited) < step["requests"]:
            url, depth = queue.popleft()
            if visited:
                sleeper(request["interval_seconds"])
            # Check all DNS answers and pin again per request in the transport.
            if admit_url(policy, url, url, origins) != url:
                raise ValueError("Discovery endpoint is no longer within the admitted scope")
            journal.append("intent", url, "GET", target_url=url)
            try:
                response = transport(policy, url, "GET")
            except Exception as exc:
                journal.append("error", url, "GET", error_type=type(exc).__name__)
                raise
            status = response["status"]
            journal.append("response", url, "GET", status=status)
            visited.append(url)
            pages.append({"target_sha256": digest(url), "method": "GET", "status": status,
                          "depth": depth, "body_sha256": hashlib.sha256(response["body"]).hexdigest(),
                          "verification_status": "unverified"})
            # Do not parse denial, redirect or failure bodies for more targets.
            if status in (401, 403, 429) or status >= 500 or 300 <= status < 400:
                safety_stop = True
                break
            for row in inspect_headers({"url": url, "method": "GET", **response}):
                if len(findings) >= 200:
                    truncated = True
                    break
                findings.append({"rule_id": row["id"], "title": row["title"][:300],
                    "severity": "INFO", "source_severity": "informational", "cwe": "CWE-Unknown",
                    "file_path": "external-evidence", "line_start": 1,
                    "target_ref_hash": hashlib.sha256(url.encode()).hexdigest(),
                    "verification_status": "unverified", "engine": "web-discovery"})
            headers = {str(k).lower(): str(v) for k, v in response["headers"]}
            media_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if media_type != "text/html":
                continue
            parser = PageInventory()
            # UTF-8 replacement is explicit; legacy encodings/JS remain uncovered.
            parser.feed(response["body"].decode("utf-8", errors="replace"))
            truncated |= parser.truncated
            base = admit_url(policy, parser.base, url, origins) if parser.base else url
            if base is None:
                skipped += 1
                base = url
            for value in parser.links:
                target = admit_url(policy, value, base, origins)
                if target is None:
                    skipped += 1
                    continue
                if target not in endpoints:
                    if len(endpoints) >= MAX_CANDIDATES:
                        truncated = True
                        continue
                    endpoints[target] = {"url": target, "source_sha256": digest(url),
                                         "provenance": "html-link", "visited": False}
                if target not in queued and depth < binding["max_depth"]:
                    if len(queued) < MAX_CANDIDATES:
                        queued.add(target)
                        queue.append((target, depth + 1))
                    else:
                        truncated = True
                elif target not in queued:
                    truncated = True
            for form in parser.forms:
                if len(forms) >= MAX_FORMS:
                    truncated = True
                    break
                action = admit_url(policy, form["action"] or url, base, origins)
                forms.append({"page_sha256": digest(url), "action_url": action,
                              "action_in_scope": action is not None, "method": form["method"],
                              "field_count": form["field_count"], "input_types": form["input_types"],
                              "submission_enabled": False})
        for endpoint in endpoints.values():
            endpoint["visited"] = endpoint["url"] in visited
        return {"adapter": "web-discovery", "adapter_version": 1, "requests": len(visited),
                "findings": findings, "observations": pages, "forms": forms,
                "assets": [{"url": url, "provenance": "discovery-response", "live_verified": True}
                           for url in visited], "discovered_endpoints": list(endpoints.values()),
                "discovery": {"visited": len(visited), "queued_unvisited": len(queue),
                    "skipped": skipped, "limits_reached": truncated or bool(queue),
                    "max_depth": binding["max_depth"], "safety_stop": safety_stop},
                "safety_stop": safety_stop, "verification_status": "unverified",
                "limitations": ["Unauthenticated seed-origin HTML links only; JavaScript is never executed",
                                "No queries, credential forwarding, session storage, subresources or form submissions",
                                "Unvisited endpoints and depth/queue limits are not completed coverage",
                                "Header/cookie observations are informational candidates, not exploit proofs"]}
    finally:
        journal.close()


def setup_discovery(profile, seeds, out_dir, *, max_pages=5, max_depth=1, authorized=False):
    from .workflow_runner import execution_plan
    from .workflow_protocol import _integer, _strings
    if not authorized:
        raise PermissionError("Discovery planning requires --authorized")
    policy, fingerprint = _policy_snapshot(profile)
    _strings(seeds, 1, MAX_PAGES, "seeds")
    _integer(max_pages, len(seeds), min(MAX_PAGES, policy.max_requests), "max_pages")
    _integer(max_depth, 0, 3, "max_depth")
    for seed in seeds:
        policy.authorize_url(seed, "GET")
        if admit_url(policy, seed, seed, {origin(seed)}) != seed or urlsplit(seed).path == "":
            raise ValueError("Seed must be canonical, have an explicit path and at most 1024 characters")
    timeout = max(60, math.ceil(max_pages * 5 + (max_pages - 1) * policy.interval_seconds + 10))
    if timeout > 300:
        raise ValueError("Reduce page budget; discovery must fit a 300-second worker reservation")
    destination = Path(out_dir).expanduser().absolute()
    approved_directory(destination.parent)
    now = utcnow()
    steps = [{"id": "discover", "tool": "web-discovery", "depends_on": [], "targets": seeds,
              "requests": max_pages, "timeout_seconds": timeout, "approval_required": True}]
    for step_id, parent, tool in (("evidence", "discover", "evidence-index"), ("report", "evidence", "report-draft")):
        steps.append({"id": step_id, "tool": tool, "depends_on": [parent], "targets": seeds,
                      "requests": 0, "timeout_seconds": 10, "approval_required": False})
    protocol = {"schema_version": 1, "policy_sha256": fingerprint,
        "authorization_reference": policy.authorization_reference,
        "starts_at": now.isoformat(), "expires_at": (now + timedelta(hours=1)).isoformat(),
        "targets": seeds, "limits": {"max_requests": max_pages,
            "interval_seconds": policy.interval_seconds, "concurrency": 1,
            "timeout_seconds": timeout + 30 + math.ceil((max_pages - 1) * policy.interval_seconds)},
        "stop_file": "emergency-stop", "steps": steps}
    destination.mkdir(mode=0o700)
    private_write(destination / "protocol.json", protocol)
    private_write(destination / "bindings.json", {"schema_version": 1, "steps": {
        "discover": {"max_depth": max_depth}, "evidence": {}, "report": {}}})
    plan = execution_plan(profile, destination / "protocol.json", destination / "bindings.json")
    private_write(destination / "execution-plan.json", plan)
    return plan
