"""Read-only Phase 7.6 research analytics regression checks."""
import json

from hunterqa.db import get_db
from hunterqa.engines.research_analytics import build_research_analytics
from hunterqa.engines.triage_review import change_review, decorate_records


def _report():
    return {"status": "ready", "findings": [
        {"id": "scan1", "source": "scan", "title": "Unsafe eval", "file": "demo.py",
         "evidence": "eval(input)", "status": "unverified_static_finding", "source_hash": "a"*64},
        {"id": "ai2", "source": "ai", "title": "Use of eval function", "file": "demo.py",
         "evidence": "eval(input)", "status": "unverified_ai_hypothesis", "source_hash": "b"*64},
    ]}


def test_analytics_counts_and_suggested_group(app):
    with app.app_context():
        db = get_db()
        report = decorate_records(_report(), db)
        result = build_research_analytics(report, db)
        assert result["total_records"] == 2
        assert result["reviewed_records"] == 0
        assert len(result["suggested_groups"]) == 1
        assert result["suggested_groups"][0]["verified_correlation"] is False
        assert result["zero_days_confirmed"] == 0


def test_timeline_keeps_historical_evidence_separate(app):
    with app.app_context():
        db = get_db()
        record = _report()["findings"][0]
        change_review(db, record, "in_review", "Investigating local test source")
        original = build_research_analytics(decorate_records(_report(), db), db)
        assert original["timeline"][0]["current_evidence"] is True
        changed = _report()
        changed["findings"][0]["source_hash"] = "f"*64
        later = build_research_analytics(decorate_records(changed, db), db)
        assert later["timeline"][0]["current_evidence"] is False
        assert later["reviewed_records"] == 0


def test_analytics_route_renders_escaped_data(client, app, tmp_path):
    report_path = tmp_path / "triage.json"
    report_path.write_text(json.dumps({"engine": "unified_evidence_triage", "findings": [
        {"id": "finding1", "source": "scan", "title": "<script>alert(1)</script>",
         "status": "unverified_static_finding", "source_report_sha256": "a"*64}
    ]}))
    app.config["TRIAGE_REPORT_PATH"] = str(report_path)
    response = client.get("/analytics")
    assert response.status_code == 200
    assert b"Research Analytics" in response.data
    assert b"Confirmed zero-days" in response.data
    assert b"<script>alert(1)</script>" not in response.data
