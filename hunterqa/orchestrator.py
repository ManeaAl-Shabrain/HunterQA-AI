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
from .source_files import positive_line
from .web_review import review_project


def normalize_semgrep(item: dict, root: Path) -> dict:
    extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
    meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
    raw_path = Path(str(item.get("path") or "unknown"))
    try:
        candidate = raw_path if raw_path.is_absolute() else root / raw_path
        path = str(candidate.resolve().relative_to(root.resolve()))
    except (ValueError, OSError):
        path = raw_path.name
    cwe = meta.get("cwe") or "CWE-Unknown"
    if isinstance(cwe, list):
        cwe = ", ".join(map(str, cwe))
    msg = str(extra.get("message") or item.get("check_id") or "Semgrep finding")
    start = item.get("start") if isinstance(item.get("start"), dict) else {}
    end = item.get("end") if isinstance(item.get("end"), dict) else {}
    first_line = positive_line(start.get("line"))
    return {
        "rule_id": str(item.get("check_id") or "semgrep.finding")[:200],
        "title": msg.splitlines()[0][:300],
        "severity": str(extra.get("severity") or "INFO").upper()[:20],
        "cwe": str(cwe)[:100], "file_path": path[:1000],
        "line_start": first_line,
        "line_end": max(first_line, positive_line(end.get("line"), first_line)),
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
               "--disable-version-check", "--no-rewrite-rule-ids",
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
    web_review = review_project(project)
    local_findings = audit_project(project) + audit_openapi(project) + web_review.pop("findings")
    return {"findings": deduplicate(semgrep_findings + local_findings)[:1000],
            "web_review": web_review,
            "dependencies": inventory(project),
            "engines": {"semgrep": "completed", "config_audit": "completed",
                        "openapi_contract": "completed", "dependency_inventory": "completed",
                        "web_source_review": "partial"},
            "claims": {"zero_days_confirmed": 0, "verification": "unverified"}}
