"""Read-only, allowlisted assessment summaries and same-plan comparisons."""
from __future__ import annotations

import re

from .bounty import _read_json
from .engagement import ENGINE, MODES, digest

SHA = re.compile(r"[a-f0-9]{64}\Z")


def _hash(value):
    return isinstance(value, str) and SHA.fullmatch(value) is not None


def load_assessment(path):
    """Project only bounded known fields; never pass imported report text to UI."""
    data = _read_json(path, 100_000)
    if not isinstance(data, dict) or data.get("engine") != ENGINE or type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        raise ValueError("Expected an approved assessment report")
    if not _hash(data.get("plan_sha256")) or not _hash(data.get("policy_sha256")):
        raise ValueError("Missing assessment provenance")
    requests, stopped, rows = data.get("requests"), data.get("stopped"), data.get("observations")
    if type(requests) is not int or not 0 <= requests <= 20 or type(stopped) is not bool:
        raise ValueError("Invalid assessment traffic metadata")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 20 or data.get("review_required") is not True:
        raise ValueError("Invalid assessment observations")
    claims = data.get("claims")
    if not isinstance(claims, dict) or any(type(claims.get(key)) is not int or claims[key] != 0
        for key in ("verified_vulnerabilities", "confirmed_zero_days", "cve_ids_created")):
        raise ValueError("Unsupported assessment claims")
    observations = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or not isinstance(row.get("mode"), str) or row["mode"] not in MODES:
            raise ValueError("Invalid assessment mode")
        if not _hash(row.get("target_sha256")) or row.get("verification") != "unverified_observation":
            raise ValueError("Invalid assessment observation identity")
        status = row.get("status")
        if status is not None and (type(status) is not int or not 100 <= status <= 599):
            raise ValueError("Invalid HTTP status")
        if "body_sha256" in row and not _hash(row["body_sha256"]):
            raise ValueError("Invalid body fingerprint")
        if "expected_status_matches" in row and type(row["expected_status_matches"]) is not bool:
            raise ValueError("Invalid expected-status observation")
        item = {"index": index + 1, "mode": row["mode"], "target_sha256": row["target_sha256"],
                "status": status, "body_sha256": row.get("body_sha256"),
                "expected_status_matches": row.get("expected_status_matches"),
                "outcome": "stopped" if row.get("outcome") == "stopped" else "observed",
                "verification": "unverified_observation"}
        if "authentication" in row:
            if row["authentication"] not in ("attempted_unverified", "not_attempted"):
                raise ValueError("Unsupported authentication claim")
            item["authentication"] = row["authentication"]
        observations.append(item)
    return {"status": "ready", "plan_sha256": data["plan_sha256"],
            "policy_sha256": data["policy_sha256"], "content_sha256": digest(data),
            "requests": requests, "stopped": stopped, "observations": observations,
            "review_required": True}


def compare_assessments(first_path, second_path):
    first, second = load_assessment(first_path), load_assessment(second_path)
    if (first["plan_sha256"], first["policy_sha256"]) != (second["plan_sha256"], second["policy_sha256"]):
        raise ValueError("Compare only reports from the same exact approved plan and policy")
    comparisons = []
    for left, right in zip(first["observations"], second["observations"]):
        if (left["mode"], left["target_sha256"]) != (right["mode"], right["target_sha256"]):
            raise ValueError("Assessment step identities or order differ")
        both_statuses = left["status"] is not None and right["status"] is not None
        both_bodies = left["body_sha256"] is not None and right["body_sha256"] is not None
        comparisons.append({"index": left["index"], "mode": left["mode"],
            "target_sha256": left["target_sha256"], "before_status": left["status"],
            "after_status": right["status"],
            "status_changed": left["status"] != right["status"] if both_statuses else None,
            "body_changed": left["body_sha256"] != right["body_sha256"] if both_bodies else None})
    return {"schema_version": 1, "engine": "hunterqa_assessment_comparison",
            "plan_sha256": first["plan_sha256"], "policy_sha256": first["policy_sha256"],
            "first_content_sha256": first["content_sha256"], "second_content_sha256": second["content_sha256"],
            "comparisons": comparisons, "status_changes": sum(row["status_changed"] is True for row in comparisons),
            "body_changes": sum(row["body_changed"] is True for row in comparisons),
            "coverage_equal": len(first["observations"]) == len(second["observations"]),
            "first_stopped": first["stopped"], "second_stopped": second["stopped"],
            "review_required": True, "network_requests": 0,
            "limitations": "Same-plan observations only. Missing status/body data is unknown, not unchanged. "
            "Content fingerprints are consistency markers, not signatures. Changes or absence of changes "
            "do not establish authentication, a vulnerability, remediation, or WAF coverage."}


def dashboard_evidence(path=None, baseline=None):
    empty = {"status": "not_configured", "report": None, "comparison": None,
             "comparison_status": "not_configured"}
    if not path:
        return empty
    try:
        report = load_assessment(path)
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        return {**empty, "status": "unavailable_or_invalid"}
    result = {**empty, "status": "ready", "report": report}
    if baseline:
        try:
            result["comparison"] = compare_assessments(baseline, path)
            result["comparison_status"] = "ready"
        except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
            result["comparison_status"] = "unavailable_or_incompatible"
    return result
