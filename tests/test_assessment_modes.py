"""Shared provenance, actual detector reuse and protected offline demo lifecycle."""
import copy
import hashlib
import json
import socket
from pathlib import Path

import pytest

from hunterqa import assessment_demo as demo, assessment_modes as modes, business_rules


@pytest.fixture
def approved(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    return tmp_path


def test_all_demo_modules_run_detectors_without_network_and_retain_labels(approved, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("Demo opened a socket")
    monkeypatch.setattr(socket, "socket", no_network)
    result = demo.run(approved / "demo", authorized=True)
    assert result["all_cases_matched"] and len(result["reports"]) == 16
    metrics = result["fixture_metrics"]
    assert metrics["true_positives"] == metrics["true_negatives"] == 10
    assert metrics["false_positives"] == metrics["false_negatives"] == 0
    assert metrics["precision"] == metrics["recall"] == 1 and metrics["false_positive_rate"] == 0
    for item in result["reports"]:
        path = approved / "demo" / item["report_file"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]
        report = modes.load_report(path)
        assert report["execution_source"] == "DEMO" and report["synthetic"]
        assert report["verification_status"] == "Tested with Mocks" and not report["real_provider_verified"]
        assert all(row["execution_source"] == "DEMO" and row["evidence_ids"] for row in report["findings"])
        sarif = json.loads(modes.export(path, "sarif"))["runs"][0]
        assert sarif["properties"]["executionSource"] == "DEMO" and sarif["properties"]["synthetic"]
        assert all(row["properties"]["executionSource"] == "DEMO" for row in sarif["results"])
        assert "DEMO" in modes.export(path, "html")
    with pytest.raises(ValueError, match="relabeled"):
        modes.analyze("cloud", approved / "demo/cloud/positive/fixture.json", mode="LIVE", authorized=True)


@pytest.mark.parametrize("mode", ["LAB", "LIVE"])
@pytest.mark.parametrize("module", ["business", "cloud", "iam", "network", "ad"])
def test_same_analyzers_review_supplied_evidence_without_claiming_collection(approved, mode, module):
    path = approved / "evidence.json"
    path.write_text(json.dumps(demo.fixtures(module)), encoding="utf-8")
    report = modes.analyze(module, path, mode=mode, authorized=True)
    assert report["findings"] and report["execution_source"] == mode and not report["synthetic"]
    assert report["verification_status"] == "Not Yet Verified" and not report["real_provider_verified"]
    assert report["collector"] == "not-collected-by-this-command" and report["network_requests"] == 0
    assert report["evidence"][0]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("change", ["source", "provider", "finding-source", "evidence-source", "link"])
def test_provenance_tampering_is_rejected_in_export(approved, change):
    demo.run(approved / "demo", module="business", authorized=True)
    path = approved / "demo/business/positive/report.json"
    report = json.loads(path.read_text())
    if change == "source":
        report["execution_source"] = "LIVE"
    elif change == "provider":
        report["real_provider_verified"] = True
    elif change == "finding-source":
        report["findings"][0]["execution_source"] = "LIVE"
    elif change == "evidence-source":
        report["evidence"][0]["origin"] = "live-provider"
    else:
        report["findings"][0]["evidence_ids"] = ["0" * 64]
    path.write_text(json.dumps(report))
    with pytest.raises(ValueError):
        modes.export(path, "sarif")


def test_scope_authorization_and_no_overwrite_are_preserved(approved):
    with pytest.raises(PermissionError):
        demo.run(approved / "demo")
    demo.run(approved / "demo", module="cloud", authorized=True)
    with pytest.raises(ValueError):
        demo.run(approved / "demo", module="cloud", authorized=True)
    outside = approved.parent / (approved.name + "-outside.json")
    outside.write_text(json.dumps(demo.fixtures("cloud")))
    with pytest.raises(ValueError):
        modes.analyze("cloud", outside, mode="LIVE", authorized=True)
    with pytest.raises(PermissionError):
        modes.analyze("cloud", outside, mode="LIVE")


def test_business_rules_detect_role_tenant_amount_and_state_inconsistency():
    data = demo.business_fixture(False)
    assert not business_rules.review(data)["findings"]
    event = data["events"][0]
    event.update(role="viewer", same_tenant=False, amount_cents=-1)
    assert {r["rule_id"] for r in business_rules.review(data)["findings"]} == {"business.role-boundary", "business.tenant-boundary", "business.transaction-limit"}
    data["events"].append({**event, "id": "second", "from": "draft", "to": "paid"})
    assert {r["rule_id"] for r in business_rules.review(data)["findings"]} >= {"business.unapproved-transition", "business.state-continuity"}
    event["succeeded"] = False
    assert not any(r["test_case"] == event["id"] for r in business_rules.review(data)["findings"])
    data["events"][1]["id"] = event["id"]
    with pytest.raises(ValueError):
        business_rules.review(data)


def test_duplicate_findings_are_counted_without_collapsing_separate_events(approved):
    source = {"sha256": "1" * 64}
    row = business_rules.review(demo.business_fixture())["findings"][0]
    result = {"findings": [row, copy.deepcopy(row), {**row, "test_case": "different-event"}]}
    report = modes.envelope("business", "DEMO", result, [source], origin="generated-synthetic")
    assert len(report["findings"]) == 2 and report["findings"][0]["duplicate_count"] == 1
    path = approved / "events.json"
    path.write_text(json.dumps(report))
    rows = json.loads(modes.export(path, "sarif"))["runs"][0]["results"]
    assert len({r["partialFingerprints"]["hunterqaCandidate/v1"] for r in rows}) == 2


def test_demo_dashboard_preserves_rbac_csrf_project_history_export_and_integrity(tmp_path, monkeypatch):
    from hunterqa import create_app, assessment_history, operator_store, workspace
    from hunterqa.db import get_db
    from tests import test_workspaces as ws
    spaces = ws.spaces.__wrapped__(tmp_path, monkeypatch)
    app = create_app({"WORKSPACE_CONFIG": str(spaces[2][0]), "TESTING": True})
    with app.app_context():
        with get_db() as db:
            db.execute("INSERT INTO projects(id,name,path) VALUES(1,'Owned demo project',?)", (str(spaces[1][0] / "assessments"),))
    client = app.test_client()
    assert client.get("/assessment-modules").status_code == 302
    assert client.post("/assessment-modules/demo").status_code == 401
    ws._login(client)
    assert client.post("/assessment-modules/demo", data={"authorized": "yes"}).status_code == 400
    assert client.get("/assessment-modules?mode=wrong").status_code == 400
    assert client.get("/assessment-modules").status_code == 200
    with client.session_transaction() as state:
        token = state["csrf_token"]
    response = client.post("/assessment-modules/demo", data={"csrf_token": token, "authorized": "yes", "module": "business", "project_id": "1"})
    assert response.status_code == 302
    page = client.get(response.location)
    assert b"DEMO" in page.data and b"Owned demo project" in page.data and b"role restriction" in page.data
    rows = assessment_history.history(app.config["DATABASE"])
    assert len(rows) == 2 and all(":DEMO:business" in row["kind"] for row in rows)
    run_id = rows[0]["id"]
    for kind in ("html", "json", "sarif"):
        exported = client.get(f"/scenarios/{run_id}/export.{kind}")
        assert exported.status_code == 200 and b"DEMO" in exported.data
    path = assessment_history.report_file(app.config["DATABASE"], run_id)
    path.write_text("{}")
    assert client.get(f"/scenarios/{run_id}/export.json").status_code == 404
    operator_store.add_operator(app.config["OPERATOR_DATABASE"], "viewer", "viewer", ws.PASSWORD, authorized=True)
    client.post("/logout", data={"csrf_token": token})
    client.get("/login")
    with client.session_transaction() as state:
        token = state["csrf_token"]
    client.post("/login", data={"username": "viewer", "password": ws.PASSWORD, "csrf_token": token})
    assert client.post("/assessment-modules/demo", data={"csrf_token": token, "authorized": "yes"}).status_code == 403
    monkeypatch.setattr(workspace, "_ACTIVE", None)


def test_traceability_is_complete_classified_and_points_to_real_code_and_tests():
    root = Path(__file__).resolve().parents[1]
    data = json.loads((root / "docs/PLATFORM_REQUIREMENTS.json").read_text())
    rows = data["requirements"]
    assert len(rows) == 370 and len({r["id"] for r in rows}) == len(rows)
    assert {r["baseline_status"] for r in rows} == {"Already Implemented and Verified", "Implemented but Requires Improvement", "Partially Implemented", "Missing", "Blocked by External Dependencies"}
    for row in rows:
        assert row["remaining_limitations"]
        assert all((root / p).is_file() for p in row["implementation_files"] + row["test_files"])
