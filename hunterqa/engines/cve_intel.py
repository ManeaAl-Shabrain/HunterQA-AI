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
from .cve_ranges import affected_entry
from .advisory_quality import audit_snapshot

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
        pkg.get("resolution") != "unresolved_manifest_constraint"
        and (pkg.get("resolution") == "lockfile_resolved" or pkg.get("ecosystem") == "PyPI")
        and pkg.get("ecosystem") in {"PyPI", "npm", "Packagist"}
        and isinstance(pkg.get("name"), str)
        and bool(PACKAGE_PATTERN.fullmatch(pkg["name"]))
        and isinstance(pkg.get("version"), str)
        and bool(re.fullmatch(r"[0-9][A-Za-z0-9_.+!-]{0,100}", pkg["version"]))
    )




def group_cve_matches(matches: list[dict]) -> list[dict]:
    """Deduplicate aliases per package/version, retaining every advisory source."""
    grouped = {}
    for item in matches:
        if not isinstance(item, dict):
            continue
        ecosystem = str(item.get("ecosystem") or "")[:60]
        package = str(item.get("package") or "")[:160]
        version = str(item.get("declared_version") or "")[:120]
        ids = item.get("cve_ids")
        if not isinstance(ids, list):
            ids = []
        valid = sorted({s for s in ids if isinstance(s, str) and CVE_PATTERN.fullmatch(s)})
        # Advisory-only records retain a separate identity; never equate different
        # GHSA and PYSEC advisories without a common, supplied CVE alias.
        if not valid:
            valid = [None]
        for cve in valid:
            advisory_id = str(item.get("advisory_id") or "")[:100]
            key = (ecosystem, package, version, cve or f"advisory:{advisory_id}")
            if key not in grouped:
                grouped[key] = {
                    "ecosystem": ecosystem, "package": package,
                    "declared_version": version, "cve_id": cve,
                    "advisory_ids": [], "confirmation_status": "requires_human_review",
                    "confirmed_vulnerability": False, "zero_day_confirmed": False,
                }
            if advisory_id and advisory_id not in grouped[key]["advisory_ids"]:
                grouped[key]["advisory_ids"].append(advisory_id)
    result = list(grouped.values())
    for row in result:
        row["advisory_ids"].sort()
    return sorted(result, key=lambda x: (
        x["ecosystem"], x["package"], x["declared_version"],
        x["cve_id"] or "", tuple(x["advisory_ids"]),
    ))


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
                matched, evidence_method, unsupported = affected_entry(version, ecosystem, entry)
                if unsupported:
                    coverage["unassessed_range_entries"] += 1
                if not matched:
                    if not _versions(entry):
                        coverage["related_advisories_without_explicit_versions"] += 1
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
                    "dependency_resolution": str(row.get("resolution") or "legacy_declaration")[:80],
                    "summary": str(advisory.get("summary") or "")[:400],
                    "assessment": "published_advisory_exact_declared_version_match",
                    "verification_status": "requires_installed_version_and_context_review",
                    "evidence_method": evidence_method,
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

    groups = group_cve_matches(matches)
    return {
        "matches": matches,
        "cve_groups": groups,
        "coverage": {
            "dependencies_in_inventory": len(dependencies[:2000]),
            **dict(coverage),
            "matched_advisory_records": len(matches),
            "unique_cve_package_groups": len(groups),
            "snapshot_advisories": len(advisories),
            "malformed_advisory_entries_seen": ignored,
        },
        "limitations": (
            "Pinned PyPI declarations and supported lockfile-resolved packages are evaluated against OSV affected.versions and "
            "supported PyPI ECOSYSTEM / strict SEMVER ranges; unsupported ranges remain "
            "unassessed. Manifest declarations are not installed package attestations. "
            "No matches guarantee safety or exploitability. CVE aliases are not created."
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
    eligible, quality = audit_snapshot(payload)
    dependencies = inventory(root)
    report = match_snapshot(dependencies, eligible, snapshot_sha256=digest)
    return {
        "schema_version": 1,
        "engine": "hunterqa_offline_cve_intelligence",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": str(root),
        "snapshot_file": filename,
        "snapshot_sha256": digest,
        "matches": report["matches"],
        "cve_groups": report["cve_groups"],
        "coverage": report["coverage"],
        "advisory_quality": quality,
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
                "dependency_resolution": str(item.get("dependency_resolution") or "")[:80],
                "summary": str(item.get("summary") or "")[:400],
                "verification_status": "requires_installed_version_and_context_review",
                "confirmed_vulnerability": False,
            })
        return {
            "status": "ready", "matches": entries,
            "advisory_quality": data.get("advisory_quality", {}),
            "cve_groups": group_cve_matches(entries),
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
