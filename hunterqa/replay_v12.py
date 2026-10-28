"""Authorization-gated read-only HEAD replay of previously sanitized HAR evidence.

Replay intentionally strips credentials and only sends a HEAD request to each
exact, preflighted endpoint. No request bodies, query strings, cookies, login,
third-party hosts, retries or "stealth" behavior.
"""
from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone

from .bounty import (
    BountyPolicy, MAX_REPORT_ITEMS, VISIBLE_HEADERS, _approved_file, _read_json,
    read_only_probe,
)


def replay_har_head(profile_path, imported_har_path, *, authorized=False,
                    transport=read_only_probe, sleeper=time.sleep):
    if not authorized:
        raise PermissionError("HEAD evidence replay requires explicit --authorized")
    policy = BountyPolicy.load(profile_path)
    if "HEAD" not in policy.methods:
        raise ValueError("HEAD replay is not allowed by the program profile")
    evidence = _read_json(imported_har_path, 1_000_000)
    if (not isinstance(evidence, dict) or
            evidence.get("engine") != "hunterqa_authorized_bounty_observation" or
            evidence.get("mode") != "offline_har_import" or
            not isinstance(evidence.get("observations"), list)):
        raise ValueError("Only sanitized HunterQA offline HAR imports can be replayed")
    profile_hash = hashlib.sha256(_approved_file(profile_path).read_bytes()).hexdigest()
    if (evidence.get("policy_sha256") != profile_hash or
            evidence.get("program") != policy.program or
            evidence.get("platform") != policy.platform):
        raise ValueError("HAR evidence is not from the exact approved program policy")
    observations = evidence["observations"]
    if not observations or len(observations) > MAX_REPORT_ITEMS:
        raise ValueError("HAR observations are empty or exceed the safety budget")
    # Reject all invalid/out-of-scope URLs BEFORE sending any traffic.
    targets = []
    seen = set()
    for item in observations:
        if not isinstance(item, dict) or not isinstance(item.get("url"), str):
            raise ValueError("Invalid HAR evidence observation")
        url = item["url"]
        policy.authorize_url(url, "HEAD")
        if url in seen:
            continue
        seen.add(url)
        status = item.get("status")
        if type(status) is not int or not 100 <= status <= 599:
            raise ValueError("Invalid HAR baseline status")
        targets.append((url, status))
    if len(targets) > min(policy.max_requests, 20):
        raise ValueError("Replay request list exceeds the explicit program budget")

    comparisons = []
    for index, (url, baseline_status) in enumerate(targets):
        if index:
            sleeper(policy.interval_seconds)
        key = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]
        try:
            result = transport(policy, url, method="HEAD")
            status = result["status"]
            if type(status) is not int or not 100 <= status <= 599:
                raise ValueError("Replay returned invalid status")
            # Store no cookies, headers, bodies, tokens, query strings or raw URLs.
            allowed_header_names = sorted({
                str(k).lower() for k, _ in result.get("headers", [])
                if str(k).lower() in VISIBLE_HEADERS
            })
            comparisons.append({
                "target_hash": key, "baseline_status": baseline_status,
                "observed_status": status, "status_changed": status != baseline_status,
                "observed_header_names": allowed_header_names,
                "verification": "manual_review_required",
                "confirmed_vulnerability": False,
            })
            if status in (401, 403, 405, 429) or status >= 500:
                break  # Fail closed; no retry, identity switching, or throttling evasion.
        except (OSError, ValueError, TimeoutError) as exc:
            comparisons.append({
                "target_hash": key, "status": "request_failed",
                "error_type": type(exc).__name__,
                "confirmed_vulnerability": False,
            })
            break
    return {
        "schema_version": 1, "engine": "hunterqa_v12_controlled_head_replay",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "program": policy.program, "platform": policy.platform,
        "policy_sha256": profile_hash,
        "source_evidence_sha256":
            hashlib.sha256(_approved_file(imported_har_path).read_bytes()).hexdigest(),
        "method": "HEAD", "outbound_headers": ["Accept", "Connection", "Host", "User-Agent"],
        "summary": {"authorized_targets": len(targets),
                    "requests_attempted": len(comparisons),
                    "status_differences": sum(
                        1 for entry in comparisons if entry.get("status_changed")),
                    "confirmed_vulnerabilities": 0, "confirmed_zero_days": 0},
        "comparisons": comparisons,
        "limitations": "HEAD-only, credentials-free baseline comparison. HAR baseline "
                       "may originate from an authenticated GET and is NOT equivalent to "
                       "authenticated replay. No payloads or CVE confirmation.",
    }
