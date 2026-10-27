"""Read-only, integrity-checked local campaign history and comparisons.

Never runs binaries or model output and never accepts paths from browser input.
These hashes demonstrate that artifacts match their manifests, not authenticity:
an adversary who can rewrite both manifest and artifact can forge both hashes.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

MAX_MANIFEST = 150_000
MAX_ARTIFACT = 2_000_000
MAX_CAMPAIGNS = 40
MAX_DISCOVERED = 1000
STAGES = ("scan", "graph", "ai", "replay", "sanitizer", "triage")
STATUSES = {"completed", "partial", "failed", "skipped"}
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _read_json(path: Path, limit: int) -> tuple[dict, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Not a regular evidence file")
    if path.stat().st_size > limit:
        raise ValueError("Evidence too large")
    with path.open("rb") as handle:
        payload = handle.read(limit + 1)
    if len(payload) > limit:
        raise ValueError("Evidence too large")
    result = json.loads(payload)
    if not isinstance(result, dict):
        raise ValueError("Invalid JSON object")
    return result, hashlib.sha256(payload).hexdigest()


def _root(path: str | Path, approved_roots) -> Path | None:
    requested = Path(path).expanduser()
    if requested.is_symlink() or not requested.is_dir():
        return None
    resolved = requested.resolve(strict=True)
    allowed = approved_roots.split(":") if isinstance(approved_roots, str) else approved_roots
    for candidate in allowed or ():
        try:
            permitted = Path(candidate).expanduser()
            if permitted.is_symlink():
                continue
            permitted = permitted.resolve(strict=True)
            if resolved.is_relative_to(permitted):
                return resolved
        except (OSError, ValueError):
            continue
    return None


def _artifact(directory: Path, kind: str, declared) -> tuple[str, dict | None]:
    if not isinstance(declared, dict) or declared.get("file") != f"{kind}.json":
        return "invalid_manifest", None
    digest = declared.get("sha256")
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        return "invalid_manifest", None
    try:
        data, actual = _read_json(directory / f"{kind}.json", MAX_ARTIFACT)
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError):
        return "missing_or_invalid", None
    if actual != digest:
        return "sha256_mismatch", None
    return "hash_matched", data


def _load(directory: Path) -> dict | None:
    if directory.is_symlink() or not directory.is_dir():
        return None
    try:
        data, manifest_hash = _read_json(directory / "manifest.json", MAX_MANIFEST)
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError):
        return None
    if data.get("engine") != "hunterqa_authorized_local_campaign" or data.get("schema_version") != 1:
        return None
    stages = data.get("stages")
    artifacts = data.get("artifacts")
    if not isinstance(stages, dict) or not isinstance(artifacts, dict):
        return None
    statuses = {}
    checks = {}
    integrity = True
    artifact_data = {}
    for stage in STAGES:
        detail = stages.get(stage, {})
        status = detail.get("status") if isinstance(detail, dict) else None
        if status not in STATUSES:
            integrity = False
            status = "invalid"
        statuses[stage] = status
        declared = artifacts.get(stage)
        if status in {"completed", "partial"}:
            verification, content = _artifact(directory, stage, declared)
            checks[stage] = verification
            if verification != "hash_matched":
                integrity = False
            else:
                if detail.get("sha256") != declared["sha256"]:
                    integrity = False
                    checks[stage] = "stage_hash_mismatch"
                elif stage == "triage" and content.get("engine") == "unified_evidence_triage":
                    artifact_data[stage] = content
        else:
            if declared is not None:
                integrity = False
                checks[stage] = "unexpected_artifact"
            else:
                checks[stage] = "not_applicable"
    triage = artifact_data.get("triage", {})
    findings = triage.get("findings", []) if integrity else []
    if not isinstance(findings, list) or len(findings) > 1600:
        findings = []
        integrity = False
    summaries = data.get("summary", {})
    if not isinstance(summaries, dict):
        summaries = {}
    records = len(findings) if integrity else None
    if records is not None and records != summaries.get("research_records"):
        integrity = False
        records = None
        findings = []
    return {
        "id": directory.name,
        "project": str(data.get("project") or "")[:400],
        "started_at": str(data.get("started_at") or "")[:80],
        "finished_at": str(data.get("finished_at") or "")[:80],
        "manifest_sha256": manifest_hash,
        "integrity": "hashes_match" if integrity else "verification_failed",
        "stages": statuses,
        "artifact_checks": checks,
        "records": records,
        "zero_days_confirmed": 0,
        "_records": findings if integrity else [],
    }


def read_campaign_history(root: str | Path, approved_roots, limit: int = MAX_CAMPAIGNS) -> dict:
    """Discover a bounded number of direct-child campaign directories."""
    base = _root(root, approved_roots)
    if base is None:
        return {"status": "unavailable", "campaigns": [], "invalid": 0, "truncated": False}
    folders = []
    invalid = 0
    try:
        for index, path in enumerate(base.iterdir()):
            if index >= MAX_DISCOVERED:
                break
            if not NAME.fullmatch(path.name):
                continue
            if path.is_symlink():
                invalid += 1
                continue
            if path.is_dir() and (path / "manifest.json").exists():
                folders.append(path)
    except OSError:
        return {"status": "unavailable", "campaigns": [], "invalid": 0, "truncated": False}
    folders.sort(key=lambda p: p.name, reverse=True)
    selected = folders[:max(1, min(int(limit), MAX_CAMPAIGNS))]
    campaigns = []
    for folder in selected:
        item = _load(folder)
        if item is None:
            invalid += 1
            continue
        campaigns.append(item)
    campaigns.sort(key=lambda row: (row["started_at"], row["id"]), reverse=True)
    return {
        "status": "ready",
        "campaigns": campaigns,
        "invalid": invalid,
        "truncated": len(folders) > len(selected),
    }


def compare_campaigns(history: dict, left: str, right: str) -> dict:
    """Compare only verified snapshots of the SAME local source project."""
    if not (isinstance(left, str) and isinstance(right, str)
            and NAME.fullmatch(left) and NAME.fullmatch(right) and left != right):
        return {"status": "invalid_selection"}
    by_name = {c["id"]: c for c in history.get("campaigns", [])}
    a, b = by_name.get(left), by_name.get(right)
    if not a or not b:
        return {"status": "not_found"}
    if a["integrity"] != "hashes_match" or b["integrity"] != "hashes_match":
        return {"status": "evidence_not_verified"}
    if not a["project"] or a["project"] != b["project"]:
        return {"status": "different_projects"}

    def keys(c):
        result = set()
        for item in c["_records"]:
            if not isinstance(item, dict):
                continue
            result.add((
                str(item.get("source") or ""),
                str(item.get("file") or ""),
                str(item.get("line") or ""),
                str(item.get("title") or "").casefold().strip(),
            ))
        return result

    old, new = keys(a), keys(b)
    return {
        "status": "ready", "left": left, "right": right,
        "project": a["project"],
        "left_records": a["records"], "right_records": b["records"],
        "record_delta": b["records"] - a["records"],
        "candidate_keys_added": len(new - old),
        "candidate_keys_missing": len(old - new),
        "stage_changes": [
            {"name": stage, "left": a["stages"][stage], "right": b["stages"][stage]}
            for stage in STAGES if a["stages"][stage] != b["stages"][stage]
        ],
        "warning": (
            "Record keys are heuristic; an added record is not necessarily a "
            "new vulnerability. Missing records do not prove remediation."
        ),
    }


def public_history(history: dict) -> dict:
    """Do not expose potentially large source findings to templates or URLs."""
    return {
        **history,
        "campaigns": [
            {key: val for key, val in c.items() if not key.startswith("_")}
            for c in history["campaigns"]
        ],
    }
