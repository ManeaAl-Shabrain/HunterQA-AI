"""Human review decisions over immutable HunterQA triage records.

No automated verdicts or zero-day promotion; SQLite is separate from reports.
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

REVIEW_STATES = ("new", "in_review", "confirmed", "false_positive", "remediated")
TRANSITIONS = {
    "new": {"in_review", "false_positive"},
    "in_review": {"new", "confirmed", "false_positive"},
    "confirmed": {"in_review", "remediated"},
    "false_positive": {"in_review"},
    "remediated": {"in_review"},
}
IDENTIFIER = re.compile(r"^[a-zA-Z0-9_-]{1,100}$")


def _fingerprint(record):
    """Conservative *suggested* groups, never automatic evidence correlation.

    Only scan/AI findings from an identically named source file qualify.
    No cross-type correlations with separate memory-safety diagnostics.
    """
    if record.get("source") not in {"scan", "ai"}:
        return None
    file_name = str(record.get("file") or "").strip().replace("\\", "/").lower()
    if not file_name:
        return None
    text = " ".join(str(record.get(k) or "") for k in ("title", "evidence")).lower()
    if "pickle" in text or "deserializ" in text:
        family = "pickle_deserialization" if "pickle" in text else None
        # AI suggestions with only 'deserialization' cannot prove pickle use.
        # Quote-backed observations can supply that additional context.
    elif "shell=true" in text or "shell = true" in text:
        family = "shell_true"
    elif re.search(r"\beval\b", text):
        family = "eval"
    else:
        return None
    if not family:
        return None
    return hashlib.sha256(f"{file_name}\0{family}".encode()).hexdigest()[:12]


def decorate_records(report: dict, db) -> dict:
    """Enrich a validated triage view with review states, without mutating JSON."""
    records = report.get("findings", [])
    if not isinstance(records, list):
        raise ValueError("Triage findings must be an array")

    # Bounded indexed lookups, independent of sqlite3 variable-count defaults.
    reviews = {}
    for record in records[:1600]:
        identity = record.get("id")
        if not isinstance(identity, str) or not IDENTIFIER.fullmatch(identity):
            continue
        row = db.execute(
            "SELECT evidence_sha256, analyst_status, note, updated_at "
            "FROM triage_reviews WHERE finding_id = ?", (identity,)
        ).fetchone()
        reviews[identity] = row

    group_members = defaultdict(list)
    for record in records:
        key = _fingerprint(record)
        if key:
            group_members[key].append(record.get("id"))

    enriched = []
    for item in records:
        item = dict(item)
        identity = item.get("id")
        review = reviews.get(identity)
        # A review is only valid for exactly the same original report evidence.
        evidence_hash = item.get("source_hash")
        current = review if review is not None and review["evidence_sha256"] == evidence_hash else None
        item["analyst_status"] = current["analyst_status"] if current else "new"
        item["analyst_note"] = current["note"] if current else ""
        item["review_updated_at"] = current["updated_at"] if current else None
        key = _fingerprint(item)
        item["possible_group"] = key if key and len(group_members[key]) > 1 else None
        item["possible_group_count"] = len(group_members[key]) if item["possible_group"] else 0
        enriched.append(item)

    result = dict(report)
    result["findings"] = enriched
    result["by_review"] = dict(Counter(x["analyst_status"] for x in enriched))
    result["potential_duplicate_groups"] = sum(len(v) > 1 for v in group_members.values())
    return result


def change_review(db, record: dict, next_status: str, note: str) -> str:
    """Commit a human decision and append-only audit record in one transaction.

    Caller must validate CSRF and resolve record from the trusted local loader.
    Returns the resulting state; does not change source findings or severity.
    """
    identity = record.get("id")
    evidence_hash = record.get("source_hash")
    if not isinstance(identity, str) or not IDENTIFIER.fullmatch(identity):
        raise ValueError("Invalid finding identifier")
    if not isinstance(evidence_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", evidence_hash):
        raise ValueError("Invalid report evidence fingerprint")
    if next_status not in REVIEW_STATES:
        raise ValueError("Invalid review status")
    if not isinstance(note, str) or len(note) > 2000:
        raise ValueError("Review note is too long")
    note = note.strip()
    if next_status in {"confirmed", "false_positive", "remediated"} and len(note) < 20:
        raise ValueError("Provide at least 20 characters of supporting review or retest evidence")

    existing = db.execute(
        "SELECT analyst_status, evidence_sha256 FROM triage_reviews WHERE finding_id = ?",
        (identity,)
    ).fetchone()
    previous = "new"
    if existing:
        if existing["evidence_sha256"] != evidence_hash:
            raise ValueError("Source evidence changed; start a new review")
        previous = existing["analyst_status"]
    if next_status == previous:
        raise ValueError("Choose a different status")
    if next_status not in TRANSITIONS.get(previous, set()):
        raise ValueError(f"Review transition {previous} -> {next_status} is not allowed")

    when = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with db:
        db.execute(
            "INSERT INTO triage_reviews(finding_id, evidence_sha256, analyst_status, note, updated_at) "
            "VALUES (?,?,?,?,?) ON CONFLICT(finding_id) DO UPDATE SET "
            "analyst_status=excluded.analyst_status, note=excluded.note, updated_at=excluded.updated_at",
            (identity, evidence_hash, next_status, note, when),
        )
        db.execute(
            "INSERT INTO triage_review_events(finding_id, evidence_sha256, old_status, new_status, note, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (identity, evidence_hash, previous, next_status, note, when),
        )
        db.execute(
            "INSERT INTO audit_events(action, subject, created_at) VALUES(?,?,?)",
            ("triage_review_updated", f"{identity}: {previous} -> {next_status}", when),
        )
    return next_status
