"""Read-only longitudinal analysis for verified HunterQA campaign snapshots.

Campaigns are grouped by their recorded local source project. Findings are
research *records*, not unique vulnerabilities; changes are observations,
not exploitability or regression confirmations.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

MAX_RUNS = 40
MAX_PROJECTS = 15
MAX_SAMPLES = 8


def _static_key(record: dict) -> tuple | None:
    """Conservative key for scanner findings only, not AI hypotheses."""
    if not isinstance(record, dict) or record.get("source") != "scan":
        return None
    file_name, title = record.get("file"), record.get("title")
    if not isinstance(file_name, str) or not isinstance(title, str):
        return None
    file_name, title = file_name.strip(), " ".join(title.casefold().split())
    if not (0 < len(file_name) <= 400 and 0 < len(title) <= 300):
        return None
    line = record.get("line")
    if type(line) is not int or line < 1:
        return None
    cwe = record.get("cwe_candidate") or ""
    if not isinstance(cwe, str):
        cwe = ""
    return (file_name, line, title, cwe[:60])


def _static_index(campaign: dict) -> dict[tuple, dict]:
    index = {}
    for finding in campaign.get("_records", [])[:1600]:
        key = _static_key(finding)
        if key is not None:
            index.setdefault(key, finding)
    return index


def _preview(records: dict, keys: set) -> list[dict]:
    result = []
    for key in sorted(keys)[:MAX_SAMPLES]:
        finding = records[key]
        result.append({
            "file": key[0][:400],
            "line": key[1],
            "title": str(finding.get("title") or "")[:300],
            "cwe_candidate": str(finding.get("cwe_candidate") or "")[:60],
        })
    return result


def _safe_run(campaign: dict) -> dict:
    records = [r for r in campaign.get("_records", []) if isinstance(r, dict)]
    counts = Counter(str(r.get("source") or "unknown")[:50] for r in records)
    return {
        "id": campaign["id"],
        "started_at": campaign["started_at"],
        "finished_at": campaign["finished_at"],
        "manifest_sha256": campaign["manifest_sha256"],
        "records": campaign["records"],
        "static_records": counts.get("scan", 0),
        "ai_records": counts.get("ai", 0),
        "other_records": sum(v for k, v in counts.items() if k not in ("scan", "ai")),
        "scan_stage": campaign["stages"].get("scan"),
        "ai_stage": campaign["stages"].get("ai"),
    }


def _comparison(before: dict, after: dict) -> dict:
    """Only comparable scans can produce static candidate differences."""
    result: dict[str, Any] = {
        "from": before["id"],
        "to": after["id"],
        "comparison": "not_comparable",
        "explanation": "Static scan results are unavailable, partial or failed in one run",
        "new_static_candidates": None,
        "no_longer_observed": None,
        "persisting_static_candidates": None,
        "new_candidate_examples": [],
        "evidence_not_confirmation": True,
    }
    if before["stages"].get("scan") != "completed" or after["stages"].get("scan") != "completed":
        return result
    previous, current = _static_index(before), _static_index(after)
    prev_set, curr_set = set(previous), set(current)
    added = curr_set - prev_set
    missing = prev_set - curr_set
    retained = prev_set & curr_set
    result.update({
        "comparison": "scan_records_comparable_with_caveats",
        "explanation": (
            "Two completed static scans of the same recorded project. "
            "Rule versions, source revisions and scan coverage may still differ."
        ),
        "new_static_candidates": len(added),
        "no_longer_observed": len(missing),
        "persisting_static_candidates": len(retained),
        "new_candidate_examples": _preview(current, added),
    })
    return result


def build_campaign_trends(history: dict) -> dict:
    """Use only integrity-checked campaign reports; never open new paths.

    Output excludes raw finding objects and never executes saved code.
    """
    campaigns = history.get("campaigns", [])[:MAX_RUNS]
    if history.get("status") != "ready":
        return {
            "status": "unavailable", "projects": [],
            "excluded_unverified": 0, "zero_days_confirmed": 0,
        }
    valid = []
    excluded = 0
    for row in campaigns:
        if not isinstance(row, dict) or row.get("integrity") != "hashes_match":
            excluded += 1
            continue
        if not isinstance(row.get("project"), str) or not row["project"]:
            excluded += 1
            continue
        if not isinstance(row.get("_records"), list):
            excluded += 1
            continue
        valid.append(row)
    grouped = defaultdict(list)
    for item in valid:
        grouped[item["project"]].append(item)

    projects = []
    # Stable, deterministic ordering across requests.
    for project in sorted(grouped)[:MAX_PROJECTS]:
        series = sorted(
            grouped[project],
            key=lambda r: (r.get("started_at") or "", r.get("id") or ""),
        )
        public_runs = [_safe_run(r) for r in series]
        maximum = max((r["records"] for r in public_runs), default=0)
        for row in public_runs:
            row["record_bar_percent"] = (
                round(100 * row["records"] / maximum, 1) if maximum else 0.0
            )
        transitions = [
            _comparison(series[i - 1], series[i])
            for i in range(1, len(series))
        ]
        projects.append({
            "project": project[:400],
            "campaign_count": len(series),
            "runs": public_runs,
            "transitions": transitions,
            "latest_static_delta": (
                transitions[-1]["new_static_candidates"] if transitions else None
            ),
        })

    return {
        "status": "ready",
        "projects": projects,
        "verified_campaigns": len(valid),
        "excluded_unverified": excluded,
        "project_groups_truncated": len(grouped) > MAX_PROJECTS,
        "zero_days_confirmed": 0,
        "limitations": (
            "Records and candidate fingerprints are not confirmed vulnerabilities. "
            "A newly observed scanner record is not proof of a security regression; "
            "a missing record is not proof of remediation. Changed source, rule "
            "versions or engine coverage can change results. Hash matching means "
            "consistency with the manifest, not independent authenticity."
        ),
    }
