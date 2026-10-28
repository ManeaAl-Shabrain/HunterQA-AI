"""Read-only import adapter for SARIF 2.1.0 produced by CodeQL or other analyzers."""
from __future__ import annotations
import json
from pathlib import Path
from ..source_files import positive_line, read_bounded


def import_sarif(path: Path) -> list[dict]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 5_000_000:
        raise ValueError("SARIF path must be an existing, small regular file")
    doc = json.loads(read_bounded(path, 5_000_000).decode("utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
        raise ValueError("Invalid SARIF structure")
    findings=[]
    for run in doc["runs"][:10]:
        if not isinstance(run, dict):
            continue
        results = run.get("results", [])
        if not isinstance(results, list):
            continue
        for result in results[:200]:
            if not isinstance(result, dict):
                continue
            locations = result.get("locations", [])
            first = locations[0] if isinstance(locations, list) and locations else {}
            physical = first.get("physicalLocation", {}) if isinstance(first, dict) else {}
            artifact = physical.get("artifactLocation", {}) if isinstance(physical, dict) else {}
            region = physical.get("region", {}) if isinstance(physical, dict) else {}
            artifact = artifact if isinstance(artifact, dict) else {}
            region = region if isinstance(region, dict) else {}
            message = result.get("message")
            message = message if isinstance(message, dict) else {}
            start = positive_line(region.get("startLine"))
            end = max(start, positive_line(region.get("endLine"), start))
            findings.append({
                "rule_id": str(result.get("ruleId") or "sarif.finding")[:200],
                "title": str(message.get("text") or "SARIF finding")[:300],
                "severity": "ERROR" if result.get("level") == "error" else (
                    "WARNING" if result.get("level") == "warning" else "INFO"),
                "cwe": "CWE-Unknown", "file_path": str(artifact.get("uri") or "unknown")[:500],
                "line_start": start, "line_end": end,
                "message": str(message.get("text") or "")[:2000], "code": "",
                "engine": "sarif-import", "verification_status": "unverified",
            })
    return findings[:500]
