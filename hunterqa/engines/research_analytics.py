"""Read-only research analytics for HunterQA AI.

Analyst events are stored in SQLite, not written into source evidence.
"Possible duplicate" links are suggestions, never validated correlations.
"""
from __future__ import annotations

from collections import Counter, defaultdict


def build_research_analytics(report: dict, db, *, timeline_limit: int = 80) -> dict:
    """Summarize only the evidence and analyst decisions already on record."""
    records = report.get("findings", []) if report.get("status") == "ready" else []
    records = [r for r in records[:1600] if isinstance(r, dict)]

    by_source = Counter(str(r.get("source") or "unknown") for r in records)
    by_review = Counter(str(r.get("analyst_status") or "new") for r in records)
    by_evidence_status = Counter(str(r.get("status") or "unknown") for r in records)
    total = len(records)
    reviewed = total - by_review.get("new", 0)

    sources = [
        {"name": name, "count": count, "percent": round(100 * count / total, 1) if total else 0}
        for name, count in sorted(by_source.items())
    ]
    reviews = [
        {"name": name, "count": count, "percent": round(100 * count / total, 1) if total else 0}
        for name, count in sorted(by_review.items())
    ]

    # Suggested relationships only, and only for records grouped by
    # the existing conservative triage review fingerprint.
    grouped = defaultdict(list)
    for r in records:
        group_id = r.get("possible_group")
        if isinstance(group_id, str) and group_id:
            grouped[group_id].append(r)

    suggested_groups = []
    for group_id, members in sorted(grouped.items()):
        if len(members) < 2:
            continue
        suggested_groups.append({
            "id": group_id[:40],
            "members": [
                {
                    "id": str(m.get("id") or "")[:100],
                    "source": str(m.get("source") or "")[:50],
                    "title": str(m.get("title") or "")[:300],
                    "file": str(m.get("file") or "")[:400],
                    "line": m.get("line") if type(m.get("line")) is int else None,
                }
                for m in members[:15]
            ],
            "member_count": len(members),
            "relationship": "possible_duplicate_only",
            "verified_correlation": False,
        })

    # A review event belongs to the current report only when BOTH
    # its finding ID and evidence hash match the current record.
    current_evidence = {
        str(r.get("id")): str(r.get("source_hash"))
        for r in records
        if isinstance(r.get("id"), str)
        and isinstance(r.get("source_hash"), str)
    }
    capped_limit = min(100, max(1, int(timeline_limit)))
    events = db.execute(
        """SELECT id, finding_id, evidence_sha256, old_status,
                  new_status, note, created_at
           FROM triage_review_events
           ORDER BY id DESC LIMIT ?""",
        (capped_limit,),
    ).fetchall()
    timeline = []
    for e in events:
        identity = str(e["finding_id"])
        matched = current_evidence.get(identity) == e["evidence_sha256"]
        timeline.append({
            "event_id": e["id"],
            "finding_id": identity[:100],
            "old_status": str(e["old_status"])[:50],
            "new_status": str(e["new_status"])[:50],
            "note": str(e["note"])[:1000],
            "created_at": str(e["created_at"])[:80],
            "current_evidence": bool(matched),
        })

    return {
        "status": report.get("status", "missing"),
        "total_records": total,
        "source_counts": sources,
        "review_counts": reviews,
        "evidence_status_counts": dict(by_evidence_status),
        "reviewed_records": reviewed,
        "review_progress_percent": round(100 * reviewed / total, 1) if total else 0,
        "suggested_groups": suggested_groups[:100],
        "timeline": timeline,
        "zero_days_confirmed": 0,
        "limitations": (
            "Counts refer to evidence records, not distinct vulnerabilities or "
            "percent of source code covered. Suggested links are not proof of "
            "shared root cause; analyst confirmation is not exploitability proof."
        ),
    }
