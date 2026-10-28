"""Offline JSON OpenAPI policy hints; does not test live APIs."""
from __future__ import annotations
import json
from pathlib import Path
from ..source_files import read_bounded


def audit_openapi(root: Path) -> list[dict]:
    root = root.resolve(strict=True)
    findings = []
    for name in ("openapi.json", "swagger.json"):
        p = root / name
        if p.is_symlink() or not p.is_file() or p.stat().st_size > 512_000:
            continue
        try:
            doc = json.loads(read_bounded(p, 512_000).decode("utf-8"))
        except (ValueError, OSError, UnicodeError):
            continue
        if not isinstance(doc, dict) or not isinstance(doc.get("paths"), dict):
            continue
        global_security = doc.get("security")
        for url, operations in doc["paths"].items():
            if not isinstance(operations, dict):
                continue
            for method, operation in operations.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete"} or not isinstance(operation, dict):
                    continue
                if "security" not in operation and not global_security:
                    findings.append({
                        "rule_id": "hunterqa.openapi.no-declared-security", "title": "OpenAPI operation has no declared security requirement",
                        "severity": "INFO", "cwe": "CWE-306", "file_path": name,
                        "line_start": 1, "line_end": 1, "code": "",
                        "message": f"{method.upper()} {str(url)[:120]}: schema omits a security requirement; check whether public access is intentional.",
                        "engine": "openapi-contract", "verification_status": "unverified",
                    })
                if len(findings) >= 100:
                    return findings
    return findings
