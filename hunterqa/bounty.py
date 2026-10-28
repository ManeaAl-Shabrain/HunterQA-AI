"""HunterQA AI 1.1: bounded, explicitly authorized HTTP assessment.

This module is deliberately NOT an unrestricted exploitation framework:
no crawling, no fuzz payloads, no authentication bypass, no redirects, no
state-changing requests, no implicit proxy, and no out-of-scope traffic.
DNS is resolved and checked, then the validated IP is pinned for the
outbound TLS connection so hostname rebinding cannot change its destination.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$", re.ASCII)
MAX_PROFILE = 32_768
MAX_TARGET_LIST = 64_000
MAX_BODY = 65_536
MAX_REPORT_ITEMS = 40
SENSITIVE_HEADERS = {"set-cookie", "cookie", "authorization", "proxy-authorization",
                     "www-authenticate", "location", "x-api-key"}
VISIBLE_HEADERS = {"strict-transport-security", "content-security-policy",
                   "x-frame-options", "x-content-type-options", "referrer-policy",
                   "permissions-policy", "content-type", "cache-control"}
METHOD_CATALOG = [
    {"domain": "Web headers and cookies", "mode": "bounded_observation"},
    {"domain": "API contracts and auth declarations", "mode": "offline_openapi"},
    {"domain": "Source injection and insecure patterns", "mode": "offline_semgrep"},
    {"domain": "Dependencies and published CVE aliases", "mode": "offline_osv"},
    {"domain": "Memory safety and unknown bug hypotheses", "mode": "isolated_afl_asan"},
    {"domain": "IDOR/BOLA and business logic", "mode": "manual_authorized_review"},
    {"domain": "SQLi/XSS/SSRF/SSTI/XXE", "mode": "manual_authorized_review"},
    {"domain": "Cloud, identity and containers", "mode": "local_config_review"},
]


def _approved_file(path: str | Path) -> Path:
    raw = os.environ.get("HUNTERQA_APPROVED_ROOTS", "")
    if not raw:
        raise ValueError("Set HUNTERQA_APPROVED_ROOTS before running bounty research")
    candidate = Path(path).expanduser()
    if candidate.is_symlink():
        raise ValueError("Symlinked evidence file rejected")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError("Expected an existing local evidence file")
    for segment in raw.split(os.pathsep):
        if not segment:
            continue
        root = Path(segment).expanduser().resolve(strict=True)
        if not root.is_dir() or not resolved.is_relative_to(root):
            continue
        parent = root
        for part in resolved.relative_to(root).parts:
            parent = parent / part
            if parent.is_symlink():
                raise ValueError("Symlinked path component rejected")
        return resolved
    raise ValueError("Evidence file is outside explicitly approved local roots")


def _read_json(path, maximum):
    p = _approved_file(path)
    if p.stat().st_size > maximum:
        raise ValueError("Local evidence exceeds size limit")
    with p.open("rb") as handle:
        raw = handle.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("Local evidence exceeds size limit")
    def reject_duplicate_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key rejected")
            result[key] = value
        return result
    return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)


def _host(value: str) -> str:
    if not isinstance(value, str) or len(value) > 253:
        raise ValueError("Invalid host")
    host = value.lower().rstrip(".")
    if (not HOST_RE.fullmatch(host) or ".." in host or
            any(not label or len(label) > 63 for label in host.split("."))):
        raise ValueError("Hosts must be exact ASCII DNS names or IPv4 addresses")
    if any(label.startswith("-") or label.endswith("-") for label in host.split(".")):
        raise ValueError("Invalid DNS hostname label")
    return host


def _names(value, *, maximum=40) -> tuple[str, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        raise ValueError("A bounded list of exact allowed hosts is required")
    return tuple(dict.fromkeys(_host(x) for x in value))


def _prefixes(value, *, default):
    if value is None:
        value = default
    if not isinstance(value, list) or len(value) > 40:
        raise ValueError("Invalid path prefixes")
    items = []
    for x in value:
        if (not isinstance(x, str) or not x.startswith("/") or len(x) > 200
                or "%" in x or "\\" in x or "?" in x or "#" in x
                or "//" in x or ".." in x.split("/")):
            raise ValueError("Unsafe path prefix")
        items.append(x)
    return tuple(items)


@dataclass(frozen=True)
class BountyPolicy:
    program: str
    platform: str
    authorization_reference: str
    allowed_hosts: tuple[str, ...]
    excluded_hosts: tuple[str, ...]
    allowed_paths: tuple[str, ...]
    excluded_paths: tuple[str, ...]
    methods: tuple[str, ...]
    allowed_ports: tuple[int, ...]
    max_requests: int
    interval_seconds: float
    lab_mode: bool
    allow_private_network: bool
    allow_http: bool

    @classmethod
    def from_dict(cls, value: dict):
        if not isinstance(value, dict):
            raise ValueError("Program profile must be a JSON object")
        if value.get("acknowledged_authorization") is not True:
            raise ValueError("Explicit authorization acknowledgement required")
        program = value.get("program")
        reference = value.get("authorization_reference")
        platform = value.get("platform")
        if not isinstance(program, str) or not 1 <= len(program) <= 100:
            raise ValueError("Invalid program name")
        if platform not in {"hackerone", "bugcrowd", "private", "local-lab"}:
            raise ValueError("Unsupported program platform")
        if not isinstance(reference, str) or not 8 <= len(reference) <= 300:
            raise ValueError("Record the exact authorization/policy reference")
        hosts = _names(value.get("allowed_hosts"))
        excluded_raw = value.get("excluded_hosts", [])
        if not isinstance(excluded_raw, list):
            raise ValueError("Excluded hosts must be a list")
        excluded = tuple(_host(h) for h in excluded_raw)
        if len(excluded) > 40:
            raise ValueError("Too many excluded hosts")
        ports = value.get("allowed_ports", [443])
        if not isinstance(ports, list) or not 1 <= len(ports) <= 10 or any(
            type(p) is not int or not 1 <= p <= 65535 for p in ports
        ):
            raise ValueError("Explicit allowed port list required")
        methods = value.get("methods", ["HEAD"])
        if (not isinstance(methods, list) or not 1 <= len(methods) <= 2 or
                any(x not in ("HEAD", "GET") for x in methods)):
            raise ValueError("Only safe-method HEAD/GET observation is implemented")
        budget = value.get("max_requests", 10)
        interval = value.get("interval_seconds", 1.0)
        if type(budget) is not int or not 1 <= budget <= MAX_REPORT_ITEMS:
            raise ValueError("Request budget must be between 1 and 40")
        if (type(interval) not in (float, int) or
                not 0.5 <= float(interval) <= 60):
            raise ValueError("Minimum interval is 0.5 seconds")
        lab = value.get("lab_mode", False)
        private = value.get("allow_private_network", False)
        http = value.get("allow_http", False)
        if any(type(x) is not bool for x in (lab, private, http)):
            raise ValueError("Lab/network switches must be booleans")
        if private and not lab:
            raise ValueError("Private-network targets require explicit local lab mode")
        return cls(
            program, platform, reference, hosts, excluded,
            _prefixes(value.get("allowed_paths"), default=["/"]),
            _prefixes(value.get("excluded_paths"), default=[]),
            tuple(dict.fromkeys(methods)), tuple(dict.fromkeys(ports)),
            budget, float(interval), lab, private, http,
        )

    @classmethod
    def load(cls, path: str | Path):
        return cls.from_dict(_read_json(path, MAX_PROFILE))

    def authorize_url(self, url: str, method="HEAD"):
        if not isinstance(url, str) or not 1 <= len(url) <= 2048:
            raise ValueError("Invalid URL")
        if any(ord(ch) < 33 or ord(ch) > 126 for ch in url):
            raise ValueError("URL must be printable ASCII without spaces")
        parts = urlsplit(url)
        if parts.scheme not in (("https", "http") if self.allow_http else ("https",)):
            raise ValueError("Scheme is not authorized")
        if parts.username is not None or parts.password is not None:
            raise ValueError("Embedded credentials are prohibited")
        if not parts.netloc or not parts.hostname:
            raise ValueError("Missing URL authority")
        host = _host(parts.hostname)
        if host not in self.allowed_hosts or host in self.excluded_hosts:
            raise ValueError("Host is outside exact program scope")
        try:
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError as e:
            raise ValueError("Invalid port") from e
        if port not in self.allowed_ports:
            raise ValueError("Port outside program scope")
        path = parts.path or "/"
        if (parts.query or parts.fragment or "%" in path or "\\" in path or
                "//" in path or ";" in path or ".." in path.split("/")):
            raise ValueError("Queries, fragments and ambiguous paths prohibited")
        if not any(path == p or p == "/" or path.startswith(p.rstrip("/") + "/")
                   for p in self.allowed_paths):
            raise ValueError("Path is not within an allowed prefix")
        if any(path == p or path.startswith(p.rstrip("/") + "/")
               for p in self.excluded_paths):
            raise ValueError("Path explicitly excluded by program")
        if method not in self.methods:
            raise ValueError("HTTP method not authorized in this program")
        return parts, host, port, path


def resolve_pinned(policy: BountyPolicy, host: str, port: int):
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips = sorted({item[4][0] for item in infos})
    if not ips:
        raise ValueError("DNS did not resolve the authorized host")
    for raw in ips:
        ip = ipaddress.ip_address(raw)
        if (ip.is_unspecified or ip.is_multicast or ip.is_link_local or
                ip.is_reserved or
                (not ip.is_global and not (policy.lab_mode and policy.allow_private_network))):
            raise ValueError("Unsafe DNS answer, refusing the entire host")
    return ips[0]


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, ip, timeout):
        super().__init__(host, port=port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, ip, timeout):
        super().__init__(host, port=port, timeout=timeout,
                         context=ssl.create_default_context())
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def read_only_probe(policy: BountyPolicy, url: str, method="HEAD", *, resolver=resolve_pinned):
    parts, host, port, path = policy.authorize_url(url, method)
    ip = resolver(policy, host, port)  # Entire DNS result set checked, then pinned.
    cls = _PinnedHTTPS if parts.scheme == "https" else _PinnedHTTP
    conn = cls(host, port, ip, timeout=5)
    try:
        conn.request(method, path, headers={
            "Host": host if port in (80, 443) else f"{host}:{port}",
            "User-Agent": "HunterQA-AI/1.1 authorized-readonly",
            "Accept": "text/html,application/json,*/*",
            "Connection": "close",
        })
        response = conn.getresponse()
        status = int(response.status)
        headers = response.getheaders()
        body = response.read(MAX_BODY + 1) if method == "GET" else b""
        return {"url": f"{parts.scheme}://{parts.netloc}{path}", "method": method,
                "status": status, "headers": headers,
                "body_sha256": hashlib.sha256(body[:MAX_BODY]).hexdigest() if body else None,
                "body_truncated": len(body) > MAX_BODY}
    finally:
        conn.close()


def inspect_headers(result: dict) -> list[dict]:
    """Observations only: no automatically confirmed vulnerabilities or CVEs."""
    headers = {}
    cookies = []
    for name, val in result.get("headers", [])[:150]:
        key = str(name).lower()
        if key == "set-cookie":
            cookies.append(str(val)[:2000])
        elif key in VISIBLE_HEADERS:
            headers[key] = str(val)[:300]
    url = result["url"]
    findings = []
    def add(rule, title, level="informational"):
        findings.append({"id": rule, "title": title, "severity": level,
                         "source_url": url, "verification": "manual_review_required",
                         "confirmed": False, "zero_day_confirmed": False, "cve_id": None})
    if url.startswith("https://") and "strict-transport-security" not in headers:
        add("header.hsts.absent", "HSTS not observed (check endpoint/host policy)")
    if "x-content-type-options" not in headers:
        add("header.nosniff.absent", "X-Content-Type-Options not observed")
    if (result.get("method") == "GET" and
            "text/html" in headers.get("content-type", "").lower() and
            "content-security-policy" not in headers):
        add("header.csp.absent", "CSP not observed on HTML response")
    for cookie in cookies[:20]:
        bits = [x.strip().lower() for x in cookie.split(";")]
        name = cookie.split("=", 1)[0][:40]
        if url.startswith("https://") and "secure" not in bits:
            add("cookie.secure.absent", f"Cookie {name!r} lacks Secure flag")
        if "httponly" not in bits:
            add("cookie.httponly.absent", f"Cookie {name!r} lacks HttpOnly flag")
    return findings[:100]


def assess(profile_path, targets_path, *, authorized=False, method="HEAD",
           transport=read_only_probe, sleeper=time.sleep):
    if not authorized:
        raise PermissionError("Bounty testing requires explicit --authorized acknowledgement")
    policy = BountyPolicy.load(profile_path)
    target_text = _approved_file(targets_path).read_bytes()
    if len(target_text) > MAX_TARGET_LIST:
        raise ValueError("Target list exceeds size limit")
    targets = [line.strip() for line in target_text.decode("utf-8").splitlines()
               if line.strip() and not line.lstrip().startswith("#")]
    if not targets or len(targets) > policy.max_requests:
        raise ValueError("Target list empty or beyond approved request budget")
    # Preflight ALL targets: an out-of-scope target aborts before any network I/O.
    for url in targets:
        policy.authorize_url(url, method)
    observations, findings = [], []
    for index, url in enumerate(targets):
        if index:
            sleeper(policy.interval_seconds)
        try:
            result = transport(policy, url, method=method)
            observations.append({
                "url": result["url"], "method": method, "status": result["status"],
                "body_sha256": result.get("body_sha256"),
                "body_truncated": bool(result.get("body_truncated", False)),
                "response_headers": {
                    str(k).lower(): str(v)[:300] for k, v in result.get("headers", [])
                    if str(k).lower() in VISIBLE_HEADERS
                },
                "cookie_count": sum(str(k).lower() == "set-cookie" for k, _ in result.get("headers", [])),
            })
            findings.extend(inspect_headers(result))
            if result["status"] == 429:
                break  # Do not continue sending traffic against rate-limited endpoints.
        except (OSError, ValueError, ssl.SSLError, http.client.HTTPException) as error:
            observations.append({"url": url, "status": "request_failed",
                                 "reason": type(error).__name__})
            break  # Fail closed rather than retry unboundedly.
    return {
        "schema_version": 1,
        "engine": "hunterqa_authorized_bounty_observation",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "program": policy.program, "platform": policy.platform,
        "policy_sha256": hashlib.sha256(_approved_file(profile_path).read_bytes()).hexdigest(),
        "scope": {"authorized_hosts": len(policy.allowed_hosts),
                  "request_budget": policy.max_requests, "method": method},
        "observations": observations,
        "findings": findings,
        "manual_research_catalog": METHOD_CATALOG,
        "claims": {"verified_vulnerabilities": 0, "confirmed_zero_days": 0,
                   "cve_ids_created": 0, "false_positive_free": False},
        "limitations": "Header findings are informational candidates. No payload exploitation, "
                       "authenticated testing, fuzzing, crawling, or automatic CVE assignment.",
    }



def read_bounty_report(path: str | Path | None) -> dict:
    """Read-only, local administrator-selected report; never user URL input."""
    empty = {"status": "unavailable", "program": None,
             "observations": [], "findings": [], "scope": {}}
    if not path:
        return empty
    try:
        data = _read_json(path, 1_000_000)
        if (not isinstance(data, dict) or
                data.get("engine") != "hunterqa_authorized_bounty_observation" or
                not isinstance(data.get("observations"), list) or
                not isinstance(data.get("findings"), list) or
                len(data["observations"]) > MAX_REPORT_ITEMS or
                len(data["findings"]) > 100):
            return empty
        observations = []
        for item in data["observations"]:
            if isinstance(item, dict):
                observations.append({
                    "url": str(item.get("url") or "")[:350],
                    "status": str(item.get("status") or "")[:40],
                    "method": str(item.get("method") or "")[:8],
                })
        findings = []
        for item in data["findings"]:
            if isinstance(item, dict):
                findings.append({
                    "id": str(item.get("id") or "")[:100],
                    "title": str(item.get("title") or "")[:300],
                    "source_url": str(item.get("source_url") or "")[:350],
                    "verification": "manual_review_required",
                })
        return {"status": "ready", "program": str(data.get("program") or "")[:100],
                "scope": {"request_budget": len(observations)},
                "observations": observations, "findings": findings}
    except (OSError, ValueError, UnicodeError, TypeError, KeyError, json.JSONDecodeError):
        return empty



def import_har(profile_path, har_path, *, authorized=False):
    """Offline passive review of already-authorized HAR responses.

    Does NOT replay requests, store cookies, parse request bodies or store HAR
    headers wholesale. Out-of-scope captures are skipped and counted.
    """
    if not authorized:
        raise PermissionError("Importing program evidence requires --authorized")
    policy = BountyPolicy.load(profile_path)
    data = _read_json(har_path, 2_000_000)
    log = data.get("log") if isinstance(data, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list) or len(entries) > 300:
        raise ValueError("HAR must contain up to 300 entries")
    observations, findings = [], []
    skipped = 0
    for entry in entries:
        if not isinstance(entry, dict):
            skipped += 1
            continue
        request, response = entry.get("request"), entry.get("response")
        if not isinstance(request, dict) or not isinstance(response, dict):
            skipped += 1
            continue
        raw_url = request.get("url")
        if not isinstance(raw_url, str):
            skipped += 1
            continue
        try:
            parts = urlsplit(raw_url)
            # HAR may contain credentials in query strings; never copy them.
            safe_url = parts._replace(query="", fragment="").geturl()
            policy.authorize_url(safe_url, "HEAD" if "HEAD" in policy.methods else "GET")
        except ValueError:
            skipped += 1
            continue
        status = response.get("status")
        if type(status) is not int or status < 100 or status > 599:
            skipped += 1
            continue
        raw_headers = response.get("headers", [])
        headers = [(str(h["name"])[:100], str(h["value"])[:2000])
                   for h in raw_headers[:100] if isinstance(h, dict)
                   and isinstance(h.get("name"), str)
                   and isinstance(h.get("value"), str)] if isinstance(raw_headers, list) else []
        observation = {"url": safe_url, "method": "HAR", "status": status,
                       "response_headers": {str(k).lower(): str(v)[:300] for k, v in headers
                                            if str(k).lower() in VISIBLE_HEADERS},
                       "cookie_count": sum(str(k).lower() == "set-cookie" for k, _ in headers)}
        observations.append(observation)
        findings.extend(inspect_headers({"url": safe_url,
                                          "method": str(request.get("method") or "")[:8],
                                          "headers": headers, "status": status}))
        if len(observations) >= MAX_REPORT_ITEMS:
            break
    return {
        "schema_version": 1,
        "engine": "hunterqa_authorized_bounty_observation",
        "mode": "offline_har_import",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "program": policy.program, "platform": policy.platform,
        "policy_sha256": hashlib.sha256(_approved_file(profile_path).read_bytes()).hexdigest(),
        "scope": {"authorized_hosts": len(policy.allowed_hosts), "method": "OFFLINE"},
        "observations": observations,
        "findings": findings[:100],
        "skipped_out_of_scope_or_invalid": skipped,
        "claims": {"verified_vulnerabilities": 0, "confirmed_zero_days": 0,
                   "cve_ids_created": 0, "false_positive_free": False},
        "limitations": "Offline HAR import does not replay traffic or confirm exploitability. "
                       "Cookie and auth values are discarded.",
    }


def bounty_markdown(report):
    """Prepare a human-editable finding draft, not an auto-submitted bounty claim."""
    if not isinstance(report, dict) or report.get("engine") != "hunterqa_authorized_bounty_observation":
        raise ValueError("Not a HunterQA bounty evidence report")
    program = str(report.get("program") or "Unspecified")[:100].replace("\n", " ")
    lines = [
        f"# HunterQA Bug Bounty Research — {program}",
        "",
        "**Status:** Unverified observations requiring manual security review.",
        "**Submission:** Draft only; do not submit without reproduction and impact.",
        "",
        "## Scope & methodology",
        "Authorized program scope, bounded read-only responses and/or offline HAR import.",
        "No exploit payloads, mutation or unauthorized scanning were performed by this engine.",
        "",
        "## Findings for analyst review",
    ]
    findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    for i, finding in enumerate(findings[:100], 1):
        if not isinstance(finding, dict):
            continue
        title = str(finding.get("title") or "Unverified observation")[:200].replace("\n", " ")
        url = str(finding.get("source_url") or "")[:350].replace("\n", " ")
        lines.extend([f"### {i}. {title}", f"- Source: {url}",
                      "- Impact: Not established",
                      "- Reproduction: Must be independently verified",
                      "- CWE / CVE: Not assigned",
                      "- Remediation: Review the relevant configuration and intended policy",
                      ""])
    if not findings:
        lines.append("No reportable findings established by this research run.")
    lines.extend(["", "## Evidence handling",
                  "HTTP bodies, cookies, tokens and private HAR content are not included.",
                  "This draft must be checked against the program's disclosure rules."])
    return "\n".join(lines) + "\n"
