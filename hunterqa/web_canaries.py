"""Two fixed non-executing query probes; candidates require independent review."""
from __future__ import annotations

import hashlib
import re
import time
from html.parser import HTMLParser

from .bounty import BountyPolicy, _read_json
from .engagement import digest, pinned_request
from .workflow_network import NetworkJournal
from .workflow_protocol import ID, _fields, _integer

KINDS = ("markup-reflection", "sql-error")
SQL_ERRORS = ("sqlite3.operationalerror", "unclosed quotation mark", "unterminated quoted string",
              "ora-01756", "you have an error in your sql syntax")


def validate_canaries(data, policy):
    _fields(data, ("schema_version", "checks"), "canary manifest")
    _integer(data["schema_version"], 1, 1, "schema_version")
    checks = data["checks"]
    if not isinstance(checks, list) or not 1 <= len(checks) <= 10:
        raise ValueError("Select 1..10 exact canary checks")
    ids = set()
    for check in checks:
        _fields(check, ("id", "kind", "url", "parameter"), "canary check")
        if not isinstance(check["id"], str) or not ID.fullmatch(check["id"]) or check["id"] in ids:
            raise ValueError("Canary IDs must be unique")
        ids.add(check["id"])
        if check["kind"] not in KINDS:
            raise ValueError("Unsupported fixed canary kind")
        if not isinstance(check["parameter"], str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", check["parameter"]):
            raise ValueError("Invalid reviewed query parameter name")
        policy.authorize_url(check["url"], "GET")
    return data


def variants(check):
    nonce = digest(check)[:16]
    baseline = "HQ-" + nonce
    probe = (f'<hunterqa-canary data-hunterqa="{nonce}"></hunterqa-canary>'
             if check["kind"] == "markup-reflection" else "'" + baseline)
    return [("baseline", {check["parameter"]: baseline}), ("probe", {check["parameter"]: probe})]


def request_digest(url, query):
    return digest({"url": url, "method": "GET", "query": query})


class _Markup(HTMLParser):
    def __init__(self, nonce):
        super().__init__(convert_charrefs=True)
        self.nonce, self.found = nonce, False
        self.raw = None

    def handle_starttag(self, tag, attrs):
        if self.raw:
            return
        if tag in ("textarea", "title", "script", "style", "noscript", "xmp", "iframe", "noembed", "noframes", "plaintext"):
            self.raw = tag
            return
        if tag == "hunterqa-canary" and dict(attrs).get("data-hunterqa") == self.nonce:
            self.found = True

    def handle_endtag(self, tag):
        if tag == self.raw and tag != "plaintext":
            self.raw = None

    def handle_startendtag(self, tag, attrs):
        # HTML ignores a self-closing slash on these non-void elements.
        self.handle_starttag(tag, attrs)


def _cue(check, response):
    text = response["body"].decode("utf-8", errors="replace")
    if check["kind"] == "sql-error":
        lowered = text.lower()
        return any(error in lowered for error in SQL_ERRORS)
    content_types = [v for k, v in response["headers"] if k.lower() == "content-type"]
    if not any(v.split(";", 1)[0].strip().lower() == "text/html" for v in content_types):
        return False
    parser = _Markup(digest(check)[:16])
    parser.feed(text)
    return parser.found


def execute_canaries(request, *, transport=pinned_request, sleeper=time.sleep):
    policy = BountyPolicy.from_dict(request["policy"])
    binding, step = request["binding"], request["step"]
    manifest = validate_canaries(_read_json(binding["file"], 65_536), policy)
    if 2 * len(manifest["checks"]) > step["requests"] or not {c["url"] for c in manifest["checks"]} <= set(step["targets"]):
        raise ValueError("Canary checks exceed reviewed request reservation or targets")
    journal = NetworkJournal(request["network_log"])
    observations, findings = [], []
    stopped = False
    try:
        for check in manifest["checks"]:
            cues = []
            for variant, query in variants(check):
                if observations:
                    sleeper(request["interval_seconds"])
                target = check["url"]
                request_hash = request_digest(target, query)
                journal.append("intent", target, "GET", request_sha256=request_hash)
                try:
                    response = transport(policy, target, "GET", query=query)
                except Exception as exc:
                    journal.append("error", target, "GET", error_type=type(exc).__name__)
                    raise
                status = response["status"]
                journal.append("response", target, "GET", status=status)
                cues.append(_cue(check, response))
                observations.append({"case": check["id"], "kind": check["kind"], "variant": variant,
                    "target_sha256": digest(target), "request_sha256": request_hash,
                    "status": status, "body_sha256": hashlib.sha256(response["body"]).hexdigest(),
                    "verification_status": "unverified"})
                if status in (401, 403, 429) or 300 <= status < 400 or status >= 500:
                    stopped = True
                    break
            eligible = 200 <= status < 300 or (check["kind"] == "sql-error" and status >= 500)
            if len(cues) == 2 and cues == [False, True] and eligible:
                markup = check["kind"] == "markup-reflection"
                findings.append({"rule_id": "web.markup-reflection-review" if markup else "web.sql-error-review",
                    "title": "Inert markup reflected as HTML; script execution is unproven" if markup else "SQL error cue appeared only after a fixed quote probe; injection is unproven",
                    "severity": "WARNING", "cwe": "CWE-20" if markup else "CWE-89",
                    "file_path": "external-evidence", "line_start": 1, "case": check["id"],
                    "target_ref_hash": hashlib.sha256(check["url"].encode()).hexdigest(), "verification_status": "unverified"})
            if stopped:
                break
        return {"adapter": "web-canary-check", "adapter_version": 1, "requests": len(observations),
            "observations": observations, "findings": findings, "safety_stop": stopped,
            "canary_summary": {"checks_selected": len(manifest["checks"]),
                "pairs_observed": sum(o["variant"] == "probe" for o in observations)},
            "limitations": ["Only fixed inert markup and quote/error comparisons; no scripts, data extraction, time delays or bypass payloads",
                "Reflection is not confirmed XSS, and a new database error is not confirmed SQL injection",
                "No blind/OOB SQLi, DOM/stored XSS, SSRF, file upload or traversal validation"]}
    finally:
        journal.close()
