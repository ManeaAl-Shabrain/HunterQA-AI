from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ExistingAgentReportAdapter:
    """Safely imports JSON output from an existing agent without executing it.

    Point ``report_path`` at JSON created by ``src/agent.py``. This adapter reads
    data only; it intentionally never imports the module or launches a command.
    """

    def load(self, report_path: Path) -> list[dict[str, Any]]:
        resolved = report_path.expanduser().resolve(strict=True)
        if resolved.suffix.lower() != ".json" or not resolved.is_file():
            raise ValueError("The agent report must be an existing JSON file.")
        if resolved.stat().st_size > 20 * 1024 * 1024:
            raise ValueError("The agent report is too large.")
        payload = json.loads(resolved.read_text(encoding="utf-8"))
        rows = payload.get("findings", payload) if isinstance(payload, dict) else payload
        if not isinstance(rows, list):
            raise ValueError("Expected a JSON array or an object with a findings array.")
        return [self._normalize(row) for row in rows if isinstance(row, dict)]

    @staticmethod
    def _normalize(row: dict[str, Any]) -> dict[str, Any]:
        location = row.get("location") if isinstance(row.get("location"), dict) else {}
        return {
            "rule_id": str(row.get("rule_id") or row.get("id") or "agent.finding")[:200],
            "title": str(row.get("title") or row.get("message") or "Agent finding")[:300],
            "severity": str(row.get("severity") or "INFO").upper()[:20],
            "cwe": str(row.get("cwe") or "CWE-Unknown")[:100],
            "file_path": str(row.get("file_path") or row.get("path") or location.get("path") or "unknown")[:1000],
            "line_start": int(row.get("line_start") or location.get("line") or 1),
            "line_end": int(row.get("line_end") or location.get("line") or 1),
            "message": str(row.get("message") or row.get("description") or "")[:10000],
            "code": str(row.get("code") or "")[:20000],
        }

