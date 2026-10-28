"""Offline, bounded dependency lockfile inventory.

Only recorded package versions are returned. Lockfile presence is NOT proof
of installation, authenticity, reachability or exploitability.
The project scanner enforces approved-root scope before invoking this module.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from ..source_files import read_bounded

MAX_LOCK_BYTES = 4_000_000
MAX_PACKAGES_PER_FILE = 1500
NAME_LIMIT = 160
VERSION_LIMIT = 120
ALLOWED = {"package-lock.json", "npm-shrinkwrap.json", "composer.lock", "poetry.lock", "uv.lock"}
PYPINAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$", re.ASCII)
VERSION = re.compile(r"^[vV]?[0-9][A-Za-z0-9_.+!:-]{0,119}$", re.ASCII)
NPMNAME = re.compile(r"^(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+$", re.ASCII)
COMPOSERNAME = re.compile(r"^[a-z0-9_.-]+/[a-z0-9_.-]+$", re.ASCII)


def _record(ecosystem: str, name: str, version: str, source: str, *,
            scope: str = "unknown", registry: str = "unverified") -> dict | None:
    if not isinstance(name, str) or not isinstance(version, str):
        return None
    name = name.strip()
    version = version.strip()
    pattern = PYPINAME if ecosystem == "PyPI" else (
        NPMNAME if ecosystem == "npm" else COMPOSERNAME
    )
    if not pattern.fullmatch(name) or not VERSION.fullmatch(version):
        return None
    if ecosystem == "PyPI":
        name = re.sub(r"[-_.]+", "-", name).lower()
    elif ecosystem == "Packagist":
        name = name.lower()
    return {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "source": source[:300],
        "resolution": "lockfile_resolved",
        "scope": scope,
        "registry": registry,
    }


def _npm_name(path: str, entry: dict) -> str | None:
    # v2/v3 package maps key each package by its install location. Nested
    # packages are allowed; aliases may supply their canonical name.
    if not isinstance(path, str) or "node_modules/" not in path:
        return None
    if entry.get("link") is True:
        return None
    reported = entry.get("name")
    if isinstance(reported, str) and NPMNAME.fullmatch(reported):
        return reported
    location = path.rsplit("node_modules/", 1)[-1]
    if location.startswith("@"):
        pieces = location.split("/")
        return "/".join(pieces[:2]) if len(pieces) >= 2 else None
    return location.split("/")[0] or None


def parse_lockfile(path: Path, relative: str) -> list[dict]:
    """Return exact version declarations from supported lockfile formats.

    No package installations, imports from untrusted source, network calls,
    dependency resolution or code execution. Unsupported entries are skipped.
    """
    if path.name not in ALLOWED or path.is_symlink() or not path.is_file():
        return []
    if path.stat().st_size > MAX_LOCK_BYTES:
        return []
    try:
        raw = read_bounded(path, MAX_LOCK_BYTES)
        data = tomllib.loads(raw.decode("utf-8")) if path.suffix == ".lock" and path.name in {
            "poetry.lock", "uv.lock"
        } else json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, tomllib.TOMLDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    result = []
    if path.name in {"package-lock.json", "npm-shrinkwrap.json"}:
        if data.get("lockfileVersion") not in (2, 3):
            return []  # npm v1 doesn't provide reliably resolved install paths
        packages = data.get("packages")
        if not isinstance(packages, dict) or len(packages) > MAX_PACKAGES_PER_FILE:
            return []
        for location, info in packages.items():
            if not isinstance(info, dict):
                continue
            name = _npm_name(location, info)
            if name:
                entry = _record("npm", name, info.get("version"), f"{relative}::{location}",
                                scope="dev" if info.get("dev") else "unknown",
                                registry="unverified")
                if entry:
                    result.append(entry)
    elif path.name == "composer.lock":
        for section in ("packages", "packages-dev"):
            packages = data.get(section, [])
            if not isinstance(packages, list) or len(packages) > MAX_PACKAGES_PER_FILE:
                continue
            for info in packages:
                if not isinstance(info, dict):
                    continue
                entry = _record("Packagist", info.get("name"), info.get("version"),
                                relative, scope="dev" if section.endswith("-dev") else "production")
                if entry:
                    result.append(entry)
    elif path.name in {"poetry.lock", "uv.lock"}:
        packages = data.get("package", [])
        if not isinstance(packages, list) or len(packages) > MAX_PACKAGES_PER_FILE:
            return []
        for info in packages:
            if not isinstance(info, dict):
                continue
            source = info.get("source")
            registry = "unverified"
            if isinstance(source, dict):
                if "git" in source or "directory" in source or "editable" in source or "url" in source:
                    continue
                if path.name == "uv.lock":
                    if not isinstance(source.get("registry"), str):
                        continue
                    registry = str(source["registry"])[:150]
                elif source.get("type") in ("git", "path", "directory"):
                    continue
                elif source.get("type") not in (None, "legacy"):
                    continue
            elif path.name == "uv.lock":
                continue
            entry = _record("PyPI", info.get("name"), info.get("version"),
                            relative, registry=registry)
            if entry:
                result.append(entry)
    return result[:MAX_PACKAGES_PER_FILE]
