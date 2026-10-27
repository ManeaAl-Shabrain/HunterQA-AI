"""Read-only import adapter for SARIF 2.1.0 produced by CodeQL or other analyzers."""
from __future__ import annotations
import json
from pathlib import Path


def import_sarif(path: Path) -> list[dict]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 5_000_000:
        raise ValueError("SARIF path must be an existing, small regular file")
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
        raise ValueError("Invalid SARIF structure")
    findings=[]
    for run in doc["runs"][:10]:
        if not isinstance(run, dict):
            continue
        for result in run.get("results", [])[:200]:
            if not isinstance(result, dict):
                continue
            locations = result.get("locations", [])
            first = locations[0] if isinstance(locations, list) and locations else {}
            physical = first.get("physicalLocation", {}) if isinstance(first, dict) else {}
            artifact = physical.get("artifactLocation", {}) if isinstance(physical, dict) else {}
            region = physical.get("region", {}) if isinstance(physical, dict) else {}
            props = result.get("properties", {}) or {}
            message = result.get("message", {}) or {}
            findings.append({
                "rule_id": str(result.get("ruleId") or "sarif.finding")[:200],
                "title": str(message.get("text") or "SARIF finding")[:300],
                "severity": "WARNING" if result.get("level") in {"warning", "error"} else "INFO",
                "cwe": "CWE-Unknown", "file_path": str(artifact.get("uri") or "unknown")[:500],
                "line_start": int(region.get("startLine") or 1),
                "line_end": int(region.get("endLine") or region.get("startLine") or 1),
                "message": str(message.get("text") or "")[:2000], "code": "",
                "engine": "sarif-import", "verification_status": "unverified",
            })
    return findings[:500]
