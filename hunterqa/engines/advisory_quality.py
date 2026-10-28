"""Offline OSV snapshot quality, provenance and freshness assessment.

This module never makes network requests. A reported acquisition timestamp is
user-supplied metadata, not a verified download receipt or signature.
Snapshots without such metadata remain usable but have UNKNOWN freshness.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone, timedelta

MAX_ADVISORIES = 5000


def _date(value):
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() is None:
            return None
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def _fingerprint(item: dict) -> str:
    return hashlib.sha256(json.dumps(
        item, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")).hexdigest()


def audit_snapshot(payload, *, now=None, max_age_days=30) -> tuple[list[dict], dict]:
    """Deduplicate ID records conservatively, retaining newest valid modification.

    A duplicate with conflicting content and no strictly newer modified timestamp
    is excluded, rather than arbitrarily choosing a possibly misleading record.
    Missing modified fields are allowed for older user snapshots, but counted
    as unverified metadata.
    """
    now = now or datetime.now(timezone.utc)
    if now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    now = now.astimezone(timezone.utc)
    if not isinstance(max_age_days, int) or not 1 <= max_age_days <= 365:
        raise ValueError("Invalid freshness window")
    metadata = payload.get("snapshot_metadata", {}) if isinstance(payload, dict) else {}
    if not isinstance(metadata, dict):
        metadata = {}
    fetched = _date(metadata.get("fetched_at"))
    if not fetched:
        freshness = "unknown"
    elif fetched > now + timedelta(minutes=5):
        freshness = "invalid_future_timestamp"
    elif fetched < now - timedelta(days=max_age_days):
        freshness = "stale"
    else:
        freshness = "within_declared_window"
    advisories = payload.get("vulns") if isinstance(payload, dict) else payload
    if not isinstance(advisories, list) or len(advisories) > MAX_ADVISORIES:
        raise ValueError("OSV snapshot must contain a bounded vulnerability array")

    counts = Counter()
    seen = {}
    ambiguous = set()
    for record in advisories:
        if not isinstance(record, dict):
            counts["invalid_records"] += 1
            continue
        key = record.get("id")
        if not isinstance(key, str) or not 1 <= len(key) <= 100:
            counts["invalid_records"] += 1
            continue
        modified_text = record.get("modified")
        modified = _date(modified_text)
        if modified_text is None:
            counts["missing_modified"] += 1
        elif not modified or modified > now + timedelta(days=1):
            counts["invalid_modified"] += 1
            continue
        if record.get("withdrawn"):
            counts["withdrawn_records"] += 1
            # Keep withdrawal records during de-duplication. Otherwise an older
            # active duplicate would incorrectly survive a newer withdrawal.
        fingerprint = _fingerprint(record)
        if key not in seen:
            seen[key] = (record, modified, fingerprint)
            continue
        counts["duplicate_ids"] += 1
        old, old_date, old_fp = seen[key]
        if old_fp == fingerprint:
            continue
        if old_date is not None and modified is not None:
            if modified > old_date:
                seen[key] = (record, modified, fingerprint)
                ambiguous.discard(key)
                continue
            if modified < old_date:
                continue
        ambiguous.add(key)
    for key in ambiguous:
        seen.pop(key, None)
    counts["ambiguous_ids_excluded"] = len(ambiguous)
    sanitized = [record for record, _, _ in seen.values() if not record.get("withdrawn")]
    return sanitized, {
        "freshness": freshness,
        "fetched_at": fetched.isoformat() if fetched else None,
        "max_age_days": max_age_days,
        "provenance": "user_supplied_unverified",
        "advisories_received": len(advisories),
        "advisories_eligible": len(sanitized),
        **dict(counts),
        "source": str(metadata.get("source") or "unspecified")[:100],
        "warning": (
            "Snapshot metadata is not independently authenticated. Unknown or "
            "stale freshness does not imply the absence of current advisories."
        ),
    }
