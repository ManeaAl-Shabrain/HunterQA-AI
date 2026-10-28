"""Offline repeatability review for two strictly policy-matched HEAD replay runs.

No networking or arbitrary URL access. HTTP response stability is *not* proof of
a vulnerability, exploit, authentication bypass, or a newly discovered CVE.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

from .bounty import BountyPolicy, _approved_file, _read_json

ENGINE = "hunterqa_v12_head_repeatability"
REPLAY_ENGINE = "hunterqa_v12_controlled_head_replay"
SHA64 = re.compile(r"[a-f0-9]{64}\Z")
HASH24 = re.compile(r"[a-f0-9]{24}\Z")


def _read_replay(path, policy, policy_hash):
    obj = _read_json(path, 100_000)
    if (not isinstance(obj, dict) or obj.get("engine") != REPLAY_ENGINE
            or obj.get("program") != policy.program
            or obj.get("platform") != policy.platform
            or obj.get("policy_sha256") != policy_hash):
        raise ValueError("HEAD report is not bound to the authorized program")
    source_hash = obj.get("source_evidence_sha256")
    if not isinstance(source_hash, str) or not SHA64.fullmatch(source_hash):
        raise ValueError("HEAD report has no validated source HAR hash")
    comparisons = obj.get("comparisons")
    if not isinstance(comparisons, list) or not 1 <= len(comparisons) <= 20:
        raise ValueError("Invalid bounded HEAD comparison list")
    results = {}
    for case in comparisons:
        if not isinstance(case, dict):
            raise ValueError("Malformed HEAD replay record")
        ref = case.get("target_hash")
        if not isinstance(ref, str) or not HASH24.fullmatch(ref) or ref in results:
            raise ValueError("Invalid or duplicate target fingerprint")
        baseline, observed = case.get("baseline_status"), case.get("observed_status")
        if (type(baseline) is not int or not 100 <= baseline <= 599
                or type(observed) is not int or not 100 <= observed <= 599
                or case.get("confirmed_vulnerability") is not False):
            raise ValueError("Only nonconfirmed complete status comparisons are supported")
        results[ref] = {"baseline": baseline, "status": observed}
    return obj, source_hash, results


def compare_head_replays(profile_path, first_path, second_path, *, authorized=False):
    if not authorized:
        raise PermissionError("Offline repeatability requires --authorized")
    policy = BountyPolicy.load(profile_path)
    profile_hash = hashlib.sha256(_approved_file(profile_path).read_bytes()).hexdigest()
    if _approved_file(first_path) == _approved_file(second_path):
        raise ValueError("Use two distinct replay artifacts")
    a, source_a, first = _read_replay(first_path, policy, profile_hash)
    b, source_b, second = _read_replay(second_path, policy, profile_hash)
    if source_a != source_b:
        raise ValueError("HEAD runs originate from different sanitized HAR inputs")
    common = sorted(first.keys() & second.keys())
    if not common:
        raise ValueError("No shared approved target fingerprints")
    checks = []
    for ref in common:
        left, right = first[ref], second[ref]
        if left["baseline"] != right["baseline"]:
            raise ValueError("Conflicting original HAR status for shared target")
        checks.append({
            "target_hash": ref, "baseline_status": left["baseline"],
            "first_status": left["status"], "second_status": right["status"],
            "same_observed_status": left["status"] == right["status"],
            "manual_review_required": True, "confirmed_vulnerability": False,
        })
    return {
        "schema_version": 1, "engine": ENGINE,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "program": policy.program, "policy_sha256": profile_hash,
        "source_evidence_sha256": source_a,
        "replay_document_sha256": [
            hashlib.sha256(_approved_file(path).read_bytes()).hexdigest()
            for path in (first_path, second_path)
        ],
        "summary": {
            "matched_targets": len(checks),
            "stable_status_observations": sum(x["same_observed_status"] for x in checks),
            "different_status_observations": sum(
                not x["same_observed_status"] for x in checks),
            "confirmed_vulnerabilities": 0, "confirmed_zero_days": 0,
        },
        "checks": checks,
        "limitations": "This is a comparison of two local evidence reports, not "
                       "an additional network request or vulnerability verification. "
                       "Repeated response codes can be normal and require human impact review.",
    }
