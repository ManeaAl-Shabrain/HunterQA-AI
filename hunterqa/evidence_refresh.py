"""Atomic read-only research snapshot for dashboard polling and JSON export."""
from __future__ import annotations
import json
from pathlib import Path
from .evidence import evidence_sha256
from .research import MAX_REPORT_SIZE, normalize_research_report


def load_evidence_snapshot(report_path):
    path = Path(report_path)
    try:
        if path.is_symlink() or not path.is_file():
            return {"status": "missing", "sha256": None, "report": None}
        with path.open("rb") as stream:
            raw = stream.read(MAX_REPORT_SIZE + 1)
        if len(raw) > MAX_REPORT_SIZE:
            raise ValueError("Report too large")
        report = normalize_research_report(json.loads(raw.decode("utf-8")))
        if report["error"]:
            raise ValueError(report["error"])
        return {"status": "ready", "sha256": evidence_sha256(raw), "report": report}
    except (OSError, ValueError, UnicodeError, TypeError):
        return {"status": "invalid", "sha256": None, "report": None}
