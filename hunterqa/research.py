"""Read-only, evidence-based normalization of legacy and integrated research JSON."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from .evidence import correlate_evidence, valid_sha256

MAX_REPORT_SIZE = 1024 * 1024
MAX_FINDINGS = 100
MAX_DIAGNOSTICS = 100


def safe_text(value: Any, limit: int = 300) -> str:
    return str(value if value is not None else "")[:limit]


def _positive_int(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= 10_000_000 else None


def get_crash_signal(crash: dict) -> int | None:
    value = crash.get("signal")
    if type(value) is int and 1 <= value <= 64:
        return value
    for attempt in crash.get("attempts", []) if isinstance(crash.get("attempts"), list) else []:
        if not isinstance(attempt, dict):
            continue
        value = attempt.get("signal")
        if type(value) is int and 1 <= value <= 64:
            return value
        rc = attempt.get("return_code")
        if type(rc) is int and -64 <= rc < 0:
            return -rc
    return None


def empty_report(error: str | None = None) -> dict:
    return {"project": "HunterQA AI", "model": "Local AI", "findings": [],
            "sanitizer_evidence": [], "integration_version": None,
            "summary": {"total_crashes": 0, "sanitizer_diagnostics": 0,
                        "zero_days_confirmed": 0, "review_required": False}, "error": error}


def normalize_research_report(report: Any) -> dict:
    if not isinstance(report, dict):
        return empty_report("Invalid research report structure")
    raw_findings = report.get("findings", [])
    raw_diagnostics = report.get("sanitizer_evidence", [])
    if not isinstance(raw_findings, list) or len(raw_findings) > MAX_FINDINGS:
        return empty_report("Invalid findings list")
    if not isinstance(raw_diagnostics, list) or len(raw_diagnostics) > MAX_DIAGNOSTICS:
        return empty_report("Invalid sanitizer evidence list")

    findings = []
    for row in raw_findings:
        if not isinstance(row, dict):
            continue
        # Legacy shape: {crash:{...}, ai_analysis:{...}}
        # Integrated shape: flat {filename, sha256, attempts, ...}
        crash = row.get("crash") if isinstance(row.get("crash"), dict) else row
        ai = row.get("ai_analysis") if isinstance(row.get("ai_analysis"), dict) else {}
        validation = ai.get("evidence_validation") if isinstance(ai.get("evidence_validation"), dict) else {}
        first_attempt = next((a for a in crash.get("attempts", [])
                              if isinstance(a, dict)), {}) if isinstance(crash.get("attempts"), list) else {}
        classification = first_attempt.get("classification") if isinstance(first_attempt.get("classification"), dict) else {}
        digest = crash.get("sha256")
        binary = crash.get("binary_sha256")
        findings.append({
            "filename": safe_text(crash.get("filename"), 200),
            "signal": get_crash_signal(crash),
            "input_size": _positive_int(crash.get("input_size")),
            "sha256": digest.lower() if valid_sha256(digest) else None,
            "binary_sha256": binary.lower() if valid_sha256(binary) else None,
            "reproducible": row.get("reproducible") is True or crash.get("reproducible") is True,
            "classification": safe_text(row.get("category") or classification.get("category") or crash.get("classification") or "unclassified", 100),
            "root_cause": safe_text(ai.get("root_cause") or "Source review required", 2000),
            "cwe_candidate": safe_text(row.get("cwe_candidate") or classification.get("cwe_candidate") or ai.get("cwe"), 100) or None,
            "validation_status": safe_text(validation.get("status") or "not_validated", 100),
            "verification_status": safe_text(row.get("verification_status") or "requires_human_review", 100),
            "ai_recommendation_unverified": safe_text(ai.get("recommended_fix"), 2000),
            "zero_day_confirmed": False,
        })

    sanitized = []
    for item in raw_diagnostics:
        if not isinstance(item, dict):
            continue
        source = item.get("source_locations")
        source = source[:40] if isinstance(source, list) else []
        locations = []
        for loc in source:
            if isinstance(loc, dict):
                locations.append({"file": safe_text(loc.get("file"), 300),
                                  "line": _positive_int(loc.get("line")),
                                  "column": _positive_int(loc.get("column"))})
        input_hash = item.get("input_sha256")
        binary_hash = item.get("binary_sha256")
        sanitized.append({
            "sanitizer": safe_text(item.get("sanitizer") or "Unknown", 100),
            "category": safe_text(item.get("category") or "unclassified", 100),
            "cwe_candidate": safe_text(item.get("cwe_candidate"), 100) or None,
            "summary": safe_text(item.get("summary"), 2000),
            "source_locations": locations,
            "evidence_confirmed": item.get("evidence_confirmed") is True,
            "security_impact": safe_text(item.get("security_impact") or "requires_human_review", 100),
            "input_sha256": input_hash.lower() if valid_sha256(input_hash) else None,
            "binary_sha256": binary_hash.lower() if valid_sha256(binary_hash) else None,
            "zero_day_confirmed": False,
        })
    correlated = correlate_evidence(findings, sanitized)
    for finding, match in zip(findings, correlated):
        finding["correlation_status"] = match["correlation_status"]
        finding["matched_diagnostics_count"] = len(match["matched_diagnostics"])
        finding["candidate_diagnostics_count"] = match["candidate_diagnostics_count"]

    return {
        "project": "HunterQA AI",
        "source_project_name": safe_text(report.get("project"), 100),
        "model": safe_text(report.get("model") or "Local AI", 100),
        "integration_version": safe_text(report.get("integration_version"), 30),
        "findings": findings,
        "sanitizer_evidence": sanitized,
        "summary": {"total_crashes": len(findings), "sanitizer_diagnostics": len(sanitized),
                    "zero_days_confirmed": 0, "review_required": bool(findings or sanitized)},
        "error": None,
    }


def load_research_report(report_path: str | Path) -> dict:
    path = Path(report_path)
    try:
        if path.is_symlink() or not path.is_file():
            return empty_report("Research report missing or unsafe file")
        with path.open("rb") as stream:
            raw = stream.read(MAX_REPORT_SIZE + 1)
        if len(raw) > MAX_REPORT_SIZE:
            return empty_report("Research report exceeds size limit")
        return normalize_research_report(json.loads(raw.decode("utf-8")))
    except (OSError, ValueError, UnicodeError, TypeError):
        return empty_report("Invalid research report")
