
"""Read-only HunterQA unified triage dashboard loader."""

import json
from collections import Counter
from pathlib import Path

MAX_BYTES = 3_000_000
MAX_RECORDS = 1600

SOURCES = {"scan", "ai", "graph", "replay", "sanitizer"}


def _text(value, limit=300):
    return str(value if value is not None else "")[:limit]


def read_triage_report(path):
    empty = {
        "status": "missing",
        "findings": [],
        "total_records": 0,
        "by_source": {},
        "by_status": {},
        "zero_days_confirmed": 0,
    }

    path = Path(path).expanduser()

    if path.is_symlink() or not path.is_file():
        return empty

    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_BYTES + 1)

        if len(raw) > MAX_BYTES:
            raise ValueError("Oversized report")

        document = json.loads(raw.decode("utf-8"))

        if not isinstance(document, dict):
            raise ValueError("Invalid report")

        if document.get("engine") != "unified_evidence_triage":
            raise ValueError("Unsupported report engine")

        records = document.get("findings")

        if not isinstance(records, list):
            raise ValueError("Invalid findings")

        if len(records) > MAX_RECORDS:
            raise ValueError("Too many records")

        findings = []

        for item in records:
            if not isinstance(item, dict):
                continue

            source = item.get("source")

            if source not in SOURCES:
                continue

            linked = item.get("linked_crashes", [])

            if not isinstance(linked, list):
                linked = []

            line = item.get("line")

            if type(line) is not int or line < 1:
                line = None

            findings.append({
                "id": _text(item.get("id"), 100),
                "source": source,
                "title": _text(item.get("title"), 300),
                "status": _text(item.get("status"), 100),
                "file": _text(item.get("file"), 400),
                "line": line,
                "cwe": _text(
                    item.get("cwe_candidate"), 60
                ),
                "evidence": _text(
                    item.get("evidence"), 1200
                ),
                "remediation": _text(
                    item.get("remediation"), 1200
                ),
                "source_hash": _text(
                    item.get("source_report_sha256"), 64
                ),
                "linked_crashes": [
                    _text(value, 200)
                    for value in linked[:20]
                ],
                "verification_required": True,
                "zero_day_confirmed": False,
            })

        return {
            "status": "ready",
            "findings": findings,
            "total_records": len(findings),
            "by_source": dict(
                Counter(x["source"] for x in findings)
            ),
            "by_status": dict(
                Counter(x["status"] for x in findings)
            ),
            "zero_days_confirmed": 0,
        }

    except (ValueError, TypeError, UnicodeError, OSError):
        return {**empty, "status": "invalid"}
