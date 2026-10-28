"""Offline Nuclei JSONL and ZAP traditional JSON adapters; no scanners launched."""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit

from .bounty import _approved_file
from .engagement import _policy_snapshot, utcnow
from .source_files import read_bounded

MAX_BYTES = 2_000_000
MAX_ROWS = 2000
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate imported JSON field")
        value[key] = item
    return value


def _nuclei(raw):
    lines = [line for line in raw.splitlines() if line.strip()]
    if len(lines) > MAX_ROWS:
        raise ValueError("Nuclei input exceeds row limit")
    for line in lines:
        row = json.loads(line, object_pairs_hook=_unique)
        if not isinstance(row, dict):
            raise ValueError("Nuclei JSONL rows must be objects")
        info = row.get("info") if isinstance(row.get("info"), dict) else {}
        classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
        cwes = classification.get("cwe-id", [])
        cwe = next((value for value in cwes if isinstance(value, str) and re.fullmatch(r"CWE-[0-9]{1,6}", value)),
                   "CWE-Unknown") if isinstance(cwes, list) else "CWE-Unknown"
        yield {"url": row.get("matched-at") or row.get("url"), "rule": row.get("template-id"),
               "severity": info.get("severity"), "cwe": cwe, "supported": row.get("type") == "http"}


def _zap(raw):
    data = json.loads(raw, object_pairs_hook=_unique)
    sites = data.get("site") if isinstance(data, dict) else None
    if not isinstance(sites, list) or len(sites) > 40:
        raise ValueError("Expected bounded ZAP traditional JSON site array")
    count = 0
    for site in sites:
        if not isinstance(site, dict) or not isinstance(site.get("alerts"), list) or len(site["alerts"]) > 500:
            raise ValueError("Invalid ZAP site alerts")
        for alert in site["alerts"]:
            if not isinstance(alert, dict) or not isinstance(alert.get("instances"), list):
                raise ValueError("Invalid ZAP alert instances")
            if len(alert["instances"]) > MAX_ROWS:
                raise ValueError("ZAP alert exceeds instance limit")
            for instance in alert["instances"]:
                count += 1
                if count > MAX_ROWS:
                    raise ValueError("ZAP input exceeds instance limit")
                if not isinstance(instance, dict):
                    raise ValueError("Invalid ZAP instance")
                code = str(alert.get("riskcode"))
                cwe = alert.get("cweid")
                cwe = "CWE-" + str(cwe) if re.fullmatch(r"[0-9]{1,6}", str(cwe)) else "CWE-Unknown"
                yield {"url": instance.get("uri"), "rule": alert.get("pluginid"), "cwe": cwe,
                       "severity": {"0": "info", "1": "low", "2": "medium", "3": "high"}.get(code),
                       "supported": True}


def import_external(profile_path, file_path, tool, *, authorized=False):
    if not authorized:
        raise PermissionError("Offline evidence import requires --authorized")
    if tool not in ("nuclei", "zap"):
        raise ValueError("Supported offline formats are nuclei and zap")
    policy, policy_hash = _policy_snapshot(profile_path)
    raw = read_bounded(_approved_file(file_path), MAX_BYTES)
    source_hash = hashlib.sha256(raw).hexdigest()
    findings, seen = [], set()
    skipped = duplicates = received = 0
    for row in (_nuclei(raw) if tool == "nuclei" else _zap(raw)):
        received += 1
        rule, url = row["rule"], row["url"]
        if not row["supported"] or not isinstance(rule, str) or not ID.fullmatch(rule) or not isinstance(url, str):
            skipped += 1
            continue
        try:
            parts = urlsplit(url)
            if parts.username is not None or parts.password is not None:
                raise ValueError("Embedded credentials")
            # Scope-check the endpoint only; never forward captured queries or payloads.
            safe_url = parts._replace(query="", fragment="").geturl()
            policy.authorize_url(safe_url, "GET" if "GET" in policy.methods else "HEAD")
        except ValueError:
            skipped += 1
            continue
        target = hashlib.sha256(safe_url.encode()).hexdigest()
        identity = (rule, target)
        if identity in seen:
            duplicates += 1
            continue
        seen.add(identity)
        if len(findings) >= 500:
            raise ValueError("Imported candidate limit exceeded; split the source report")
        reported = row["severity"] if row["severity"] in ("info", "low", "medium", "high", "critical") else "unknown"
        severity = "ERROR" if reported in ("high", "critical") else "WARNING" if reported in ("low", "medium") else "INFO"
        findings.append({"rule_id": f"external.{tool}.{rule}",
            "title": f"Imported {tool} candidate: {rule}", "severity": severity,
            "source_severity": reported, "cwe": row["cwe"], "file_path": "external-evidence",
            "line_start": 1, "line_end": 1, "message": "Scanner assertion imported offline; independent authorized reproduction required.",
            "engine": f"offline-{tool}-import", "verification_status": "unverified",
            "target_ref_hash": target, "confirmed_vulnerability": False, "zero_day_confirmed": False})
    return {"schema_version": 1, "engine": "hunterqa_external_evidence", "tool": tool,
            "generated_at": utcnow().isoformat(), "policy_sha256": policy_hash,
            "source_sha256": source_hash, "findings": findings,
            "summary": {"received": received, "accepted": len(findings), "skipped": skipped, "duplicates": duplicates},
            "network_requests": 0, "review_required": True,
            "limitations": "HTTP endpoint scope only; input authenticity and scan permissions are operator attestations. "
            "Raw requests, responses, extracted values, payloads, and free-text template names are omitted. "
            "Source severity is not verified impact. No scanner is installed, launched or replayed."}
