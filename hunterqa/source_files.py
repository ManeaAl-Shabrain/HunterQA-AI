"""Shared bounded, deterministic local file enumeration and reads.

These checks reduce accidental traversal/resource use; they are not an OS sandbox
against another process replacing files during an assessment.
"""
from __future__ import annotations

import os
from pathlib import Path

SKIP = {".git", ".venv", "venv", "node_modules", "vendor", "__pycache__",
        "instance", "secrets", ".pytest_cache", "dist", "build"}


def project_files(root: Path, *, max_entries=20_000):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Expected a source directory")
    visited = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        base = Path(directory)
        visited += len(dirs) + len(files)
        if visited > max_entries:
            raise ValueError("Source enumeration limit exceeded; choose a smaller approved project")
        dirs[:] = sorted(name for name in dirs if name not in SKIP
                         and not (base / name).is_symlink())
        for name in sorted(files):
            path = base / name
            if path.is_symlink() or name.startswith(".env") or not path.is_file():
                continue
            yield path


def read_bounded(path: Path, maximum: int) -> bytes:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("Expected a regular non-symlink file")
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("Local file exceeds size limit")
    return raw


def positive_line(value, default=1):
    """Normalize untrusted analyzer coordinates without executing conversions."""
    if type(value) is int and 1 <= value <= 10_000_000:
        return value
    if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 8:
        parsed = int(value)
        if 1 <= parsed <= 10_000_000:
            return parsed
    return default
