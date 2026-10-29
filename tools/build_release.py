"""Offline repository-source release builder.

Run inside a clean, fully-tested local checkout. Excludes Git, local evidence,
credentials, databases, runtime data and symlinks. Never contacts remote hosts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import zipfile
import tomllib
from pathlib import Path

EXCLUDED_DIRS = {
    ".git", ".venv", "venv", "__pycache__", ".pytest_cache",
    "instance", "reports", "fuzz-output", "fuzz-output-v2",
    "fuzz-output-v3", ".mypy_cache", ".ruff_cache",
}
EXCLUDED_EXTS = {
    ".db", ".sqlite", ".sqlite3", ".pyc", ".pyo", ".core", ".log",
    ".pem", ".key", ".p12", ".pfx", ".bin", ".gz", ".zip", ".tar",
}
EXCLUDED_FILES = {".env", ".env.local", ".env.production", "id_rsa", "id_ed25519"}
ALLOW_ROOTS = {".github", "hunterqa", "zeroscope", "tests", "docs", "examples", "tools", "labs"}
PUBLIC_TEMPLATES = {
    "README.md", "HunterQA-scope-template.json", "HunterQA-targets-template.txt",
    "HunterQA-first-configuration-review.md", "01-scope-and-approval-notes.md",
    "02-plan-and-run-checklist.md", "03-findings-and-report.md", "04-retest-record.md",
    "05-web-application-review.md", "06-auth-identity-review.md",
    "HunterQA-identity-review-template.json",
    "HunterQA-ad-review-template.json", "07-active-directory-review.md",
    "HunterQA-wireless-review-template.json", "08-wireless-review.md",
    "HunterQA-cloud-review-template.json", "09-cloud-review.md",
    "HunterQA-mobile-review-template.json", "10-mobile-review.md",
    "HunterQA-iot-review-template.json", "11-iot-embedded-review.md",
    "HunterQA-infrastructure-review-template.json", "12-infrastructure-review.md",
}
ALLOW_FILES = {
    ".gitignore", "README.md", "RELEASE_NOTES.md", "LICENSE", "SECURITY.md", "pyproject.toml", "action.yml",
    "requirements.txt", "requirements-dev.txt", "run.py", "scripts-migrate.sh", "zero to start.md",
}


def tracked_files(repo: Path):
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=repo).split(b"\0")
    for raw in names:
        if not raw:
            continue
        name = os.fsdecode(raw)
        rel = Path(name)
        if rel.is_absolute() or ".." in rel.parts:
            raise ValueError("Invalid repository path")
        public_template = (len(rel.parts) == 2 and rel.parts[0] == "templates"
                           and rel.name in PUBLIC_TEMPLATES)
        if not public_template and rel.parts[0] not in ALLOW_ROOTS and name not in ALLOW_FILES:
            continue
        if any(part in EXCLUDED_DIRS for part in rel.parts):
            continue
        if rel.suffix.lower() in EXCLUDED_EXTS or rel.name in EXCLUDED_FILES:
            continue
        if rel.parts[0] == "labs" and rel.suffix.lower() not in {".py", ".c", ".h", ".sh", ".md", ".yml", ".yaml", ".toml"}:
            continue  # Lab evidence and arbitrary data files are not publishable source.
        if any(part.startswith(".env") for part in rel.parts):
            continue
        file = repo / rel
        if any(part.is_symlink() for part in (repo / Path(*rel.parts[:i]) for i in range(1, len(rel.parts)+1))):
            continue
        if not file.is_file() or file.stat().st_size > 2_000_000:
            continue
        yield rel, file


def build(repo: Path, output: Path) -> dict:
    repo = repo.resolve(strict=True)
    output = output.expanduser().absolute()
    if output.exists():
        raise FileExistsError("Use a new output ZIP filename")
    output.parent.mkdir(parents=True, exist_ok=True)
    metadata = tomllib.loads((repo / "pyproject.toml").read_text(encoding="utf-8"))
    version = metadata["project"]["version"]
    if not isinstance(version, str) or not version or any(c in version for c in " /\\"):
        raise ValueError("Invalid package version in pyproject.toml")
    manifest = {"project": "HunterQA AI", "release": version, "files": []}
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for rel, file in sorted(tracked_files(repo), key=lambda r: r[0].as_posix()):
            content = file.read_bytes()
            # Windows checkouts may convert tracked shell scripts to CRLF.
            # Hash the packaged LF bytes so Linux receives runnable scripts
            # without modifying the operator's checkout or immutable releases.
            if rel.suffix == ".sh":
                content = content.replace(b"\r\n", b"\n")
            name = "HunterQA-AI/" + rel.as_posix()
            archive.writestr(name, content)
            manifest["files"].append({
                "path": rel.as_posix(),
                "sha256": hashlib.sha256(content).hexdigest(),
                "bytes": len(content),
            })
        archive.writestr(
            "HunterQA-AI/RELEASE_MANIFEST.json",
            json.dumps(manifest, indent=2) + "\n",
        )
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    manifest = build(Path(args.repo), Path(args.out))
    print("Release package ready:", args.out)
    print("Tracked source files:", len(manifest["files"]))


if __name__ == "__main__":
    main()
