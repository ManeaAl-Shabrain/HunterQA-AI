"""Bounded local source/configuration analysis with conservative candidate findings."""
from __future__ import annotations
import re
from pathlib import Path

MAX_FILES = 1500
MAX_BYTES = 256 * 1024

# These are intentionally low-noise observations, not exploitation proofs.
RULES = (
    ("hunterqa.docker.root-user", "WARNING", "CWE-250", "Dockerfile", r"(?im)^\s*USER\s+(?:root|0)\s*(?:#.*)?$", "Container configured to run as root; review least privilege."),
    ("hunterqa.docker.latest-tag", "INFO", "CWE-1104", "Dockerfile", r"(?im)^\s*FROM\s+\S+:latest(?:\s|$)", "Mutable image tag; pin an approved digest."),
    ("hunterqa.terraform.public-s3", "WARNING", "CWE-284", ".tf", r'(?im)\bacl\s*=\s*"public-read(?:-write)?"', "Potentially public storage ACL; verify exposure and intended policy."),
    ("hunterqa.k8s.privileged", "WARNING", "CWE-250", ".yaml", r'(?im)^\s*privileged\s*:\s*true\s*(?:#.*)?$', "Privileged container configuration; review necessity."),
    ("hunterqa.k8s.privileged", "WARNING", "CWE-250", ".yml", r'(?im)^\s*privileged\s*:\s*true\s*(?:#.*)?$', "Privileged container configuration; review necessity."),
)


def _interesting(path: Path) -> bool:
    return path.name == "Dockerfile" or path.suffix.lower() in {".tf", ".yaml", ".yml"}


def audit_project(root: Path) -> list[dict]:
    root = root.resolve(strict=True)
    results = []
    visited = 0
    for p in sorted(root.rglob("*")):
        if visited >= MAX_FILES:
            break
        # No symlink following and no analysis outside root.
        if p.is_symlink() or not p.is_file() or not _interesting(p):
            continue
        if any(part in {".git", ".venv", "node_modules", "vendor", "__pycache__"} for part in p.relative_to(root).parts):
            continue
        visited += 1
        try:
            if p.stat().st_size > MAX_BYTES:
                continue
            content = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for rule_id, severity, cwe, marker, pattern, message in RULES:
            if marker != "Dockerfile" and p.suffix.lower() != marker:
                continue
            if marker == "Dockerfile" and p.name != marker:
                continue
            for match in list(re.finditer(pattern, content))[:25]:
                line = content.count("\n", 0, match.start()) + 1
                results.append({
                    "rule_id": rule_id, "title": message[:300], "severity": severity,
                    "cwe": cwe, "file_path": str(p.relative_to(root)),
                    "line_start": line, "line_end": line, "message": message,
                    "code": content.splitlines()[line-1][:300],
                    "engine": "config-audit", "verification_status": "unverified",
                })
    return results[:500]
