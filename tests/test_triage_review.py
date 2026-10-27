"""Automated Phase 7.5.3 checks (no remote network or LLM required)."""
import pytest
from hunterqa.engines.triage_review import change_review, decorate_records


def _record(identity="example1", source="scan", title="Unsafe eval"):
    return {"id": identity, "source": source, "title": title, "file": "demo.py",
            "evidence": "eval(user_input)", "source_hash": "a" * 64}


def test_review_transition_and_history(app):
    from hunterqa.db import get_db
    with app.app_context():
        db = get_db()
        item = _record()
        assert change_review(db, item, "in_review", "Started source inspection") == "in_review"
        with pytest.raises(ValueError, match="20 characters"):
            change_review(db, item, "confirmed", "ok")
        change_review(db, item, "confirmed", "Manually reviewed the affected code and reproduction")
        assert db.execute("SELECT count(*) FROM triage_review_events").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM audit_events WHERE action = 'triage_review_updated'").fetchone()[0] == 2
        decorated = decorate_records({"findings": [item]}, db)
        assert decorated["findings"][0]["analyst_status"] == "confirmed"
        assert decorated["findings"][0]["analyst_note"].startswith("Manually")


def test_report_change_invalidates_review(app):
    from hunterqa.db import get_db
    with app.app_context():
        db = get_db()
        item = _record()
        change_review(db, item, "in_review", "Checking the test case")
        changed = dict(item, source_hash="b" * 64)
        assert decorate_records({"findings": [changed]}, db)["findings"][0]["analyst_status"] == "new"
        with pytest.raises(ValueError, match="changed"):
            change_review(db, changed, "confirmed", "Changed source is unrelated to previous review")


def test_possible_duplicate_is_only_a_suggestion(app):
    from hunterqa.db import get_db
    with app.app_context():
        records = [_record("scan1"), _record("ai2", "ai", "Use of eval function")]
        decorated = decorate_records({"findings": records}, get_db())
        assert decorated["potential_duplicate_groups"] == 1
        assert all(item["analyst_status"] == "new" for item in decorated["findings"])
        assert all(item["possible_group_count"] == 2 for item in decorated["findings"])


def test_triage_update_route_requires_csrf(client, app, tmp_path):
    import json
    p = tmp_path / "triage.json"
    p.write_text(json.dumps({"engine": "unified_evidence_triage", "findings": [{
        "id": "example1", "source": "scan", "title": "Review", "status": "unverified_static_finding",
        "source_report_sha256": "a" * 64}]}))
    app.config["TRIAGE_REPORT_PATH"] = str(p)
    denied = client.post("/triage/review/example1", data={"review_status": "in_review", "note": "Test"})
    assert denied.status_code == 400
    with client.session_transaction() as session:
        session["csrf_token"] = "known-token"
    accepted = client.post("/triage/review/example1", data={
        "csrf_token": "known-token", "review_status": "in_review", "note": "Review started"})
    assert accepted.status_code == 302
    page = client.get("/triage")
    assert b"in_review" in page.data
