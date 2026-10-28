from __future__ import annotations

import json
import threading
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask

from .db import connect
from .local_ai import generate
from .orchestrator import scan_local_source, normalize_semgrep, deduplicate


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ScanService:
    def __init__(self, app: Flask):
        self.app = app
        self._active: set[int] = set()
        self._lock = threading.Lock()
        self._slot = threading.BoundedSemaphore(1)

    def submit(self, scan_id: int) -> None:
        with self._lock:
            if scan_id in self._active:
                return
            self._active.add(scan_id)
        thread = threading.Thread(target=self._run_guarded, args=(scan_id,), daemon=True)
        thread.start()

    def _run_guarded(self, scan_id: int) -> None:
        try:
            with self._slot:
                self.run(scan_id)
        except Exception as exc:  # boundary: report errors, never kill the web app
            self._update(scan_id, status="failed", stage="Scan failed", error=str(exc)[:2000], progress=100, finished_at=utc_now())
        finally:
            with self._lock:
                self._active.discard(scan_id)

    def _update(self, scan_id: int, **values: Any) -> None:
        allowed = {"status", "stage", "error", "progress", "started_at", "finished_at"}
        safe = {key: value for key, value in values.items() if key in allowed}
        assignments = ", ".join(f"{key} = ?" for key in safe)
        with connect(self.app.config["DATABASE"]) as db:
            # Column names come exclusively from the fixed allowlist above; values are bound.
            db.execute(f"UPDATE scans SET {assignments} WHERE id = ?", (*safe.values(), scan_id))  # nosec B608

    def run(self, scan_id: int) -> None:
        with connect(self.app.config["DATABASE"]) as db:
            row = db.execute(
                "SELECT scans.id, projects.path FROM scans JOIN projects ON projects.id = scans.project_id WHERE scans.id = ?",
                (scan_id,),
            ).fetchone()
        if row is None:
            raise ValueError("Scan does not exist.")

        # Re-check the scope at execution time, not only when the scan was queued.
        with self.app.app_context():
            from .security import validate_project_path
            project_path = validate_project_path(row["path"])
        rules_path = Path(self.app.config["SEMGREP_RULES"]).resolve(strict=True)
        self._update(scan_id, status="running", stage="Running local Semgrep rules", progress=12, started_at=utc_now())

        scanned = scan_local_source(project_path, rules_path, timeout=self.app.config["SCAN_TIMEOUT_SECONDS"])
        findings = scanned["findings"]
        self._update(scan_id, stage="Inventorying dependencies", progress=54)
        dependencies = scanned["dependencies"]
        self._update(scan_id, stage="Saving normalized findings", progress=58)
        with connect(self.app.config["DATABASE"]) as db:
            db.executemany("INSERT INTO dependency_items(scan_id, ecosystem, name, version, source) VALUES (?, ?, ?, ?, ?)",
                           [(scan_id, d["ecosystem"], d["name"], d["version"], d["source"]) for d in dependencies])
            db.executemany(
                """INSERT INTO findings
                   (scan_id, rule_id, title, severity, cwe, file_path, line_start, line_end, message, code, engine, verification_status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (scan_id, f["rule_id"], f["title"], f["severity"], f["cwe"], f["file_path"],
                     f["line_start"], f["line_end"], f["message"], f["code"], f.get("engine", "semgrep"), f.get("verification_status", "unverified"))
                    for f in findings
                ],
            )

        self._update(scan_id, stage="Generating local AI report", progress=72)
        report = self._create_report(findings)
        with connect(self.app.config["DATABASE"]) as db:
            db.execute(
                "INSERT OR REPLACE INTO reports (scan_id, model, content) VALUES (?, ?, ?)",
                (scan_id, self.app.config["OLLAMA_MODEL"], report),
            )
        self._update(scan_id, status="completed", stage="Completed", progress=100, finished_at=utc_now())

    _deduplicate = staticmethod(deduplicate)
    _normalize_semgrep = staticmethod(normalize_semgrep)

    def _create_report(self, findings: list[dict[str, Any]]) -> str:
        summary = [
            {key: finding[key] for key in ("rule_id", "severity", "cwe", "file_path", "line_start", "message")}
            for finding in findings[:100]
        ]
        prompt = (
            "You are a defensive application-security reviewer. Analyze only the supplied static-analysis findings. "
            "Do not propose exploits, payloads, commands, or executable code. Clearly distinguish findings from verified vulnerabilities; never claim a zero-day or assign an unsupported CVSS score. Write concise Markdown with: executive "
            "summary, prioritized remediation, false-positive review guidance, and verification steps.\n\nFindings:\n"
            + json.dumps(summary, ensure_ascii=False)
        )
        payload = {
            "model": self.app.config["OLLAMA_MODEL"],
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1, "num_predict": 1200},
        }
        try:
            result = generate(payload, endpoint=self.app.config["OLLAMA_URL"].rstrip("/") + "/api/generate",
                              timeout=120, max_response=512_000)
            text = result.get("response")
            if isinstance(text, str) and text.strip():
                return text.strip()
        except (OSError, urllib.error.URLError, TimeoutError, ValueError, UnicodeError):
            pass
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
        count_text = ", ".join(f"{key}: {value}" for key, value in sorted(counts.items())) or "No findings"
        return (
            "# Local analysis summary\n\n"
            f"Local analysis produced **{len(findings)} unverified findings** ({count_text}).\n\n"
            "The local Ollama model was unavailable, so this deterministic summary was generated instead. "
            "Review each finding in source context. Scanner severity is a triage cue, not a verified impact rating. "
            "Apply the smallest appropriate fix and rerun the scan."
        )

