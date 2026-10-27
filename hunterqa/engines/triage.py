
"""HunterQA AI — Unified, read-only vulnerability triage."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from hunterqa.evidence import correlate_evidence
from hunterqa.research import normalize_research_report

MAX_REPORT_BYTES = 2_000_000
MAX_ITEMS = 300


def load_report(path):
    path = Path(path).expanduser()

    if path.is_symlink() or not path.is_file():
        raise ValueError("Missing or unsafe report file")

    path = path.resolve(strict=True)

    approved = os.environ.get(
        "HUNTERQA_APPROVED_ROOTS", ""
    ).split(os.pathsep)

    if not any(
        path.is_relative_to(
            Path(root).expanduser().resolve(strict=True)
        )
        for root in approved if root
    ):
        raise ValueError("Report outside approved roots")

    with path.open("rb") as handle:
        raw = handle.read(MAX_REPORT_BYTES + 1)

    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("Report exceeds size limit")

    data = json.loads(raw.decode("utf-8"))

    if not isinstance(data, dict):
        raise ValueError("Invalid JSON report structure")

    return data, hashlib.sha256(raw).hexdigest()


def rows(data, field):
    value = data.get(field, [])
    if not isinstance(value, list):
        raise ValueError(f"Invalid {field} collection")
    return [v for v in value[:MAX_ITEMS] if isinstance(v, dict)]


def triage_reports(sources):
    """Combine findings without claiming unrelated evidence matches."""
    loaded = {}
    fingerprints = {}

    for kind, path in sources.items():
        if path is None:
            continue
        data, digest = load_report(path)
        loaded[kind] = data
        fingerprints[kind] = digest

    findings = []

    def add(kind, title, status, **details):
        number = len(findings)
        identity = hashlib.sha256(
            f"{kind}:{fingerprints[kind]}:{number}".encode()
        ).hexdigest()[:16]

        findings.append({
            "id": identity,
            "source": kind,
            "title": str(title or "Untitled")[:300],
            "status": status,
            "source_report_sha256": fingerprints[kind],
            "human_review_required": True,
            "zero_day_confirmed": False,
            "cvss_score": None,
            **details,
        })

    if "scan" in loaded:
        for item in rows(loaded["scan"], "findings"):
            add(
                "scan",
                item.get("title"),
                "unverified_static_finding",
                file=item.get("file_path"),
                line=item.get("line_start"),
                cwe_candidate=item.get("cwe"),
                scanner_severity=item.get("severity"),
                remediation="Review source and trust boundary",
            )

    if "ai" in loaded:
        for item in rows(loaded["ai"], "hypotheses"):
            add(
                "ai",
                item.get("potential_weakness"),
                "unverified_ai_hypothesis",
                file=item.get("file"),
                line=item.get("line"),
                evidence=item.get("source_basis"),
                cwe_candidate=None,
                remediation=item.get("remediation_idea"),
            )

    if "graph" in loaded:
        for item in rows(loaded["graph"], "review_paths"):
            operation = item.get("operation") or {}
            if not isinstance(operation, dict):
                continue

            add(
                "graph",
                operation.get("kind"),
                "unverified_call_path",
                route=item.get("route"),
                call_chain=item.get("call_chain"),
                file=operation.get("file"),
                line=operation.get("line"),
                cwe_candidate=operation.get("cwe_candidate"),
                taint_flow_confirmed=False,
                remediation="Verify input propagation and controls",
            )

    crash_rows = []

    if "replay" in loaded:
        normalized = normalize_research_report(loaded["replay"])

        if normalized.get("error"):
            raise ValueError(normalized["error"])

        crash_rows = normalized["findings"]

        for item in crash_rows:
            reproduced = item.get("reproducible") is True

            add(
                "replay",
                item.get("filename"),
                (
                    "reproducible_crash_requires_review"
                    if reproduced else "unverified_crash"
                ),
                file=item.get("filename"),
                signal=item.get("signal"),
                input_sha256=item.get("sha256"),
                binary_sha256=item.get("binary_sha256"),
                cwe_candidate=item.get("cwe_candidate"),
                correlation_status=item.get(
                    "correlation_status", "not_established"
                ),
                remediation="Inspect source and crash root cause",
            )

    if "sanitizer" in loaded:
        item = loaded["sanitizer"]
        confirmed = item.get("evidence_confirmed") is True

        matches = correlate_evidence(crash_rows, [item])
        linked = [
            crash_rows[i].get("filename")
            for i, result in enumerate(matches)
            if result["correlation_status"]
            == "matched_input_and_binary"
        ]

        add(
            "sanitizer",
            item.get("category"),
            (
                "sanitizer_diagnostic_requires_impact_review"
                if confirmed else "unverified_sanitizer_diagnostic"
            ),
            cwe_candidate=item.get("cwe_candidate"),
            evidence_confirmed=confirmed,
            source_locations=item.get("source_locations", []),
            linked_crashes=linked,
            correlation_status=(
                "matched_input_and_binary"
                if linked else "not_established"
            ),
            remediation="Review lifetime, bounds and ownership",
        )

    counts = dict(
        Counter(item["status"] for item in findings)
    )

    return {
        "schema_version": 1,
        "project": "HunterQA AI",
        "engine": "unified_evidence_triage",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_reports": fingerprints,
        "summary": {
            "total_records": len(findings),
            "by_status": counts,
            "zero_days_confirmed": 0,
            "human_review_required": bool(findings),
        },
        "findings": findings,
        "limitations": (
            "Different reports may cover different source projects. "
            "No cross-project merging or automatic severity claims. "
            "Sanitizer/crash links require matching input and binary "
            "SHA-256 identifiers."
        ),
    }


def main():
    parser = argparse.ArgumentParser(
        description="HunterQA local evidence triage"
    )

    for name in ("scan", "ai", "graph", "replay", "sanitizer"):
        parser.add_argument(f"--{name}")

    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    sources = {
        name: getattr(args, name)
        for name in ("scan", "ai", "graph", "replay", "sanitizer")
        if getattr(args, name) is not None
    }

    if not sources:
        parser.error("At least one evidence report is required")

    report = triage_reports(sources)

    output = Path(args.out).expanduser()

    if output.is_symlink():
        raise ValueError("Output cannot be a symlink")

    approved = [
        Path(root).expanduser().resolve(strict=True)
        for root in os.environ.get(
            "HUNTERQA_APPROVED_ROOTS", ""
        ).split(os.pathsep) if root
    ]

    parent = output.parent.resolve(strict=True)
    if not any(parent.is_relative_to(root) for root in approved):
        raise ValueError("Output outside approved roots")

    if output.resolve() in {
        Path(p).expanduser().resolve()
        for p in sources.values()
    }:
        raise ValueError("Cannot overwrite a source report")

    output.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print("[HunterQA] Triage report saved:", output)
    print("[HunterQA] Records:", report["summary"]["total_records"])
    print("[HunterQA] Confirmed zero-days: 0")


if __name__ == "__main__":
    main()
