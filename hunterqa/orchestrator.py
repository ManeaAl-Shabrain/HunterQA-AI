"""Single entry point for bounded, authorized LOCAL source analysis.

Active engines: bundled offline Semgrep, deterministic configuration/OpenAPI
checks, dependency inventory. Runtime fuzzing is deliberately separate and
requires explicit CLI authorization and a VM; never launched from Flask.
"""
from __future__ import annotations
import json
import subprocess
from pathlib import Path
from .engines.config_audit import audit_project
from .engines.openapi import audit_openapi
from .engines.dependencies import inventory


def normalize_semgrep(item: dict, root: Path) -> dict:
    extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
    meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
    raw_path = Path(str(item.get("path") or "unknown"))
    try:
        path = str(raw_path.resolve().relative_to(root.resolve()))
    except (ValueError, OSError):
        path = raw_path.name
    cwe = meta.get("cwe") or "CWE-Unknown"
    if isinstance(cwe, list):
        cwe = ", ".join(map(str, cwe))
    msg = str(extra.get("message") or item.get("check_id") or "Semgrep finding")
    return {
        "rule_id": str(item.get("check_id") or "semgrep.finding")[:200],
        "title": msg.splitlines()[0][:300],
        "severity": str(extra.get("severity") or "INFO").upper()[:20],
        "cwe": str(cwe)[:100], "file_path": path[:1000],
        "line_start": max(1, int((item.get("start") or {}).get("line") or 1)),
        "line_end": max(1, int((item.get("end") or {}).get("line") or 1)),
        "message": msg[:10000], "code": str(extra.get("lines") or "")[:20000],
        "engine": "semgrep", "verification_status": "unverified",
    }


def deduplicate(findings: list[dict]) -> list[dict]:
    seen = set()
    rows = []
    for f in findings:
        key = (f.get("rule_id"), f.get("file_path"), f.get("line_start"))
        if key not in seen:
            rows.append(f)
            seen.add(key)
    return rows


def scan_local_source(project: Path, rules: Path, timeout: int = 900) -> dict:
    project = project.resolve(strict=True)
    rules = rules.resolve(strict=True)
    if not project.is_dir() or not rules.is_file():
        raise ValueError("Invalid local directory or rule file")
    command = ["semgrep", "scan", "--json", "--quiet", "--metrics=off",
               "--exclude", ".venv", "--exclude", "node_modules", "--exclude", ".git",
               "--config", str(rules), str(project)]
    completed = subprocess.run(command, shell=False, capture_output=True, text=True,
                               timeout=max(30, min(int(timeout), 1800)), check=False)
    if completed.returncode not in (0, 1):
        raise RuntimeError((completed.stderr or completed.stdout or "Semgrep failed")[:2000])
    if len(completed.stdout) > 15_000_000:
        raise RuntimeError("Semgrep report too large")
    payload = json.loads(completed.stdout or "{}")
    if payload.get("errors"):
        raise RuntimeError("Semgrep reported errors; verify rule syntax and project files")
    semgrep_findings = [normalize_semgrep(row, project) for row in payload.get("results", [])[:1000]
                             if isinstance(row, dict)]
    local_findings = audit_project(project) + audit_openapi(project)
    return {"findings": deduplicate(semgrep_findings + local_findings)[:1000],
            "dependencies": inventory(project),
            "engines": {"semgrep": "completed", "config_audit": "completed",
                        "openapi_contract": "completed", "dependency_inventory": "completed"},
            "claims": {"zero_days_confirmed": 0, "verification": "unverified"}}
