"""Offline dependency inventory. Known vulnerabilities require a user-provided advisory snapshot."""
from __future__ import annotations
import json
import re
from pathlib import Path

MAX_MANIFEST_BYTES = 1_000_000


def _entry(ecosystem: str, name: str, version: str, source: str) -> dict:
    return {"ecosystem": ecosystem, "name": name, "version": version, "source": source}


def inventory(root: Path) -> list[dict]:
    root = root.resolve(strict=True)
    rows = []
    for p in sorted(root.rglob("*")):
        if p.is_symlink() or not p.is_file() or p.name not in {"requirements.txt", "package.json", "composer.json"}:
            continue
        if any(part in {".git", ".venv", "node_modules", "vendor", "__pycache__"} for part in p.relative_to(root).parts):
            continue
        if p.stat().st_size > MAX_MANIFEST_BYTES:
            continue
        rel = str(p.relative_to(root))
        try:
            if p.name == "requirements.txt":
                for line in p.read_text(encoding="utf-8").splitlines():
                    # Only report pinned versions; do not infer installed versions.
                    match = re.match(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)(?:\s|$)", line.strip())
                    if match:
                        rows.append(_entry("PyPI", match[1].lower().replace("_", "-"), match[2], rel))
            else:
                payload = json.loads(p.read_text(encoding="utf-8"))
                if not isinstance(payload, dict):
                    continue
                eco = "npm" if p.name == "package.json" else "Packagist"
                for section in ("dependencies", "devDependencies") if eco == "npm" else ("require", "require-dev"):
                    deps = payload.get(section, {})
                    if not isinstance(deps, dict):
                        continue
                    for name, constraint in deps.items():
                        if not isinstance(constraint, str):
                            continue
                        # Constraint is not a resolved package version.
                        rows.append(_entry(eco, str(name)[:160], constraint[:120], rel))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if len(rows) >= 2000:
            break
    return rows[:2000]


def match_local_advisories(dependencies: list[dict], advisories: list[dict]) -> list[dict]:
    """Only exact pinned package/version matches; no network calls or speculative CVEs."""
    results = []
    for pkg in dependencies:
        for a in advisories[:5000]:
            if not isinstance(a, dict):
                continue
            if (str(a.get("ecosystem", "")).lower() == pkg["ecosystem"].lower()
                    and a.get("package") == pkg["name"]
                    and a.get("version") == pkg["version"]
                    and pkg["version"] and pkg["version"][0].isdigit()):
                results.append({
                    "rule_id": "hunterqa.dependency.local-advisory", "severity": "WARNING",
                    "title": f"Local advisory match: {pkg['name']}",
                    "cwe": str(a.get("cwe") or "CWE-Unknown")[:100],
                    "file_path": pkg["source"], "line_start": 1, "line_end": 1,
                    "message": f"Offline advisory {str(a.get('id','unknown'))[:100]} matches exact declared version {pkg['version']}; confirm installed version and vendor scope.",
                    "code": "", "engine": "offline-advisory",
                    "verification_status": "requires_human_review",
                })
    return results[:500]
