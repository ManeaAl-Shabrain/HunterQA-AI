"""Conservative offline CVE intelligence from OSV-format advisory snapshots.

No network calls, vulnerability exploitation, AI claims, or automatic CVE assignment.
Exact affected versions only; ecosystem/GIT/SEMVER ranges are NOT guessed.
An exact match is an advisory correlation, NOT a confirmed vulnerable installation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .dependencies import inventory

MAX_SNAPSHOT_BYTES = 4_000_000
MAX_REPORT_BYTES = 2_000_000
MAX_ADVISORIES = 5000
MAX_MATCHES = 500
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.ASCII)
HASH_PATTERN = re.compile(r"^[a-f0-9]{64}$", re.ASCII)
PACKAGE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$", re.ASCII)


def _roots():
    raw = os.environ.get("HUNTERQA_APPROVED_ROOTS") or os.environ.get(
        "ZEROSCOPE_APPROVED_ROOTS", ""
    )
    results = []
    for part in raw.split(os.pathsep):
        if not part:
            continue
        path = Path(part).expanduser()
        if path.is_symlink():
            continue
        resolved = path.resolve(strict=True)
        if resolved.is_dir():
            results.append(resolved)
    if not results:
        raise ValueError("No approved local roots are configured")
    return results


def approved_file(path: str | Path) -> Path:
    """Accept only regular files below preapproved local directories."""
    candidate = Path(path).expanduser()
    if candidate.is_symlink():
        raise ValueError("Symlinked evidence file rejected")
    resolved = candidate.resolve(strict=True)
    roots = _roots()
    if not resolved.is_file() or not any(resolved.is_relative_to(r) for r in roots):
        raise ValueError("Evidence file outside authorized roots")
    for root in roots:
        if resolved.is_relative_to(root):
            current = root
            for piece in resolved.relative_to(root).parts:
                current /= piece
                if current.is_symlink():
                    raise ValueError("Symlink traversal in evidence file")
            break
    return resolved


def _read_json(path: str | Path, byte_limit: int):
    file = approved_file(path)
    if file.stat().st_size > byte_limit:
        raise ValueError("Evidence size limit exceeded")
    with file.open("rb") as handle:
        raw = handle.read(byte_limit + 1)
    if len(raw) > byte_limit:
        raise ValueError("Evidence size limit exceeded")
    obj = json.loads(raw.decode("utf-8"))
    return obj, hashlib.sha256(raw).hexdigest(), file.name


def _normalize_package(ecosystem: str, package: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", package).lower()
    return package


def _versions(affected: dict) -> set[str]:
    values = affected.get("versions")
    if not isinstance(values, list) or len(values) > 3000:
        return set()
    return {v for v in values if isinstance(v, str) and 0 < len(v) < 128}


def _cves(advisory: dict) -> list[str]:
    candidates = [advisory.get("id")]
    if isinstance(advisory.get("aliases"), list):
        candidates.extend(advisory["aliases"][:100])
    return sorted({s for s in candidates if isinstance(s, str)
                   and CVE_PATTERN.fullmatch(s)})


def _resolved_declaration(pkg: dict) -> bool:
    """Current inventory only gives trustworthy exact declarations for PyPI.

    npm/package.json and composer.json contain constraints, not lockfile versions.
    """
    return (
        pkg.get("ecosystem") == "PyPI"
        and isinstance(pkg.get("name"), str)
        and bool(PACKAGE_PATTERN.fullmatch(pkg["name"]))
        and isinstance(pkg.get("version"), str)
        and bool(re.fullmatch(r"[0-9][A-Za-z0-9_.+!-]{0,100}", pkg["version"]))
    )


def match_snapshot(dependencies: list[dict], advisories: list[dict],
                   *, snapshot_sha256: str = "") -> dict:
    """Match only explicit OSV affected.versions to pinned declared package versions."""
    if not isinstance(advisories, list) or len(advisories) > MAX_ADVISORIES:
        raise ValueError("OSV snapshot list is invalid or too large")
    matches = []
    seen = set()
    coverage = Counter()
    ignored = 0
    for row in dependencies[:2000]:
        if not isinstance(row, dict):
            continue
        if not _resolved_declaration(row):
            coverage["not_exactly_resolved"] += 1
            continue
        ecosystem = row["ecosystem"]
        name = _normalize_package(ecosystem, row["name"])
        version = row["version"]
        coverage["exact_declarations_checked"] += 1
        had_related = False
        for advisory in advisories:
            if not isinstance(advisory, dict):
                ignored += 1
                continue
            if advisory.get("withdrawn"):
                continue
            ident = advisory.get("id")
            affected = advisory.get("affected")
            if not isinstance(ident, str) or len(ident) > 100 or not isinstance(affected, list):
                continue
            for entry in affected[:100]:
                if not isinstance(entry, dict):
                    continue
                package = entry.get("package")
                if not isinstance(package, dict):
                    continue
                eco = package.get("ecosystem")
                pn = package.get("name")
                if not isinstance(eco, str) or not isinstance(pn, str):
                    continue
                if eco != ecosystem or _normalize_package(eco, pn) != name:
                    continue
                had_related = True
                listed = _versions(entry)
                if not listed:
                    coverage["related_advisories_without_explicit_versions"] += 1
                    continue
                if version not in listed:
                    # Do not claim "not vulnerable"; another OSV range may apply.
                    continue
                identity = (ecosystem, name, version, ident)
                if identity in seen:
                    continue
                seen.add(identity)
                cves = _cves(advisory)
                matches.append({
                    "advisory_id": ident,
                    "cve_ids": cves,
                    "ecosystem": ecosystem,
                    "package": name,
                    "declared_version": version,
                    "dependency_source": str(row.get("source") or "")[:300],
                    "summary": str(advisory.get("summary") or "")[:400],
                    "assessment": "published_advisory_exact_declared_version_match",
                    "verification_status": "requires_installed_version_and_context_review",
                    "evidence_method": "OSV affected.versions exact enumeration",
                    "snapshot_sha256": snapshot_sha256,
                    "confirmed_vulnerability": False,
                    "zero_day_confirmed": False,
                })
                if len(matches) >= MAX_MATCHES:
                    coverage["truncated_match_limit"] += 1
                    break
            if len(matches) >= MAX_MATCHES:
                break
        if had_related:
            coverage["declarations_with_related_advisory"] += 1
        if len(matches) >= MAX_MATCHES:
            break

    return {
        "matches": matches,
        "coverage": {
            "dependencies_in_inventory": len(dependencies[:2000]),
            **dict(coverage),
            "matched_advisory_records": len(matches),
            "snapshot_advisories": len(advisories),
            "malformed_advisory_entries_seen": ignored,
        },
        "limitations": (
            "Only exact declared PyPI versions and OSV affected.versions lists "
            "are evaluated. npm/Composer constraints, range-only advisories, "
            "installed-package discrepancies, vendored software and unknown "
            "vulnerabilities are NOT assessed. An exact published advisory match "
            "is not a confirmed exploitable vulnerability. No CVE is invented."
        ),
    }


def run_cve_check(project: str | Path, snapshot_path: str | Path) -> dict:
    roots = _roots()
    candidate = Path(project).expanduser()
    if candidate.is_symlink():
        raise ValueError("Symlinked project rejected")
    root = candidate.resolve(strict=True)
    if not root.is_dir() or not any(root.is_relative_to(p) for p in roots):
        raise ValueError("Project outside approved roots")
    for approved in roots:
        if root.is_relative_to(approved):
            partial = approved
            for segment in root.relative_to(approved).parts:
                partial /= segment
                if partial.is_symlink():
                    raise ValueError("Symlinked project component")
            break
    payload, digest, filename = _read_json(snapshot_path, MAX_SNAPSHOT_BYTES)
    if isinstance(payload, dict):
        advisories = payload.get("vulns")
    else:
        advisories = payload
    if not isinstance(advisories, list):
        raise ValueError("Expected an OSV advisory array or a 'vulns' array")
    dependencies = inventory(root)
    report = match_snapshot(dependencies, advisories, snapshot_sha256=digest)
    return {
        "schema_version": 1,
        "engine": "hunterqa_offline_cve_intelligence",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": str(root),
        "snapshot_file": filename,
        "snapshot_sha256": digest,
        "matches": report["matches"],
        "coverage": report["coverage"],
        "limitations": report["limitations"],
        "claims": {"confirmed_vulnerabilities": 0, "zero_days_confirmed": 0,
                   "false_positive_free": False, "complete_discovery": False},
    }


def read_cve_report(path: str | Path) -> dict:
    empty = {"status": "unavailable", "matches": [], "coverage": {}, "error": None}
    try:
        data, digest, _ = _read_json(path, MAX_REPORT_BYTES)
        if (not isinstance(data, dict) or
                data.get("engine") != "hunterqa_offline_cve_intelligence" or
                not isinstance(data.get("matches"), list) or
                len(data["matches"]) > MAX_MATCHES):
            raise ValueError("Invalid CVE report schema")
        if not isinstance(data.get("coverage"), dict):
            raise ValueError("Missing coverage data")
        entries = []
        for item in data["matches"]:
            if not isinstance(item, dict):
                continue
            raw_ids = item.get("cve_ids", [])
            if not isinstance(raw_ids, list):
                raw_ids = []
            entries.append({
                "advisory_id": str(item.get("advisory_id") or "")[:100],
                "cve_ids": [v for v in raw_ids[:20] if isinstance(v, str)
                            and CVE_PATTERN.fullmatch(v)],
                "ecosystem": str(item.get("ecosystem") or "")[:50],
                "package": str(item.get("package") or "")[:160],
                "declared_version": str(item.get("declared_version") or "")[:100],
                "dependency_source": str(item.get("dependency_source") or "")[:300],
                "summary": str(item.get("summary") or "")[:400],
                "verification_status": "requires_installed_version_and_context_review",
                "confirmed_vulnerability": False,
            })
        return {
            "status": "ready", "matches": entries,
            "coverage": {
                str(k)[:80]: v for k, v in data["coverage"].items()
                if isinstance(v, int) and type(v) is int
            },
            "snapshot_sha256": str(data.get("snapshot_sha256") or "")[:64],
            "report_sha256": digest,
            "limitations": str(data.get("limitations") or "")[:1000],
            "error": None,
        }
    except (OSError, ValueError, UnicodeError, TypeError, json.JSONDecodeError):
        return empty
