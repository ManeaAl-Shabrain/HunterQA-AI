import hashlib
import json
from pathlib import Path

import pytest

from hunterqa.agent_workflow_v12 import plan, correlate, SKILLS
from hunterqa.api_surface_v12 import inspect_openapi


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({
        "program": "Owned reward lab", "platform": "local-lab",
        "authorization_reference": "Approved local fixture demonstration",
        "acknowledged_authorization": True,
        "allowed_hosts": ["app.example.test"],
        "excluded_hosts": ["admin.example.test"],
        "methods": ["HEAD"], "allowed_ports": [443],
        "max_requests": 2, "interval_seconds": 1.5,
    }))
    return tmp_path, p


def test_plan_is_nonexecuting_and_budgeted(workspace):
    root, profile = workspace
    spec = root / "openapi.json"
    spec.write_text(json.dumps({
        "openapi": "3.1.0", "paths": {"/users/{userId}": {"get": {}}}
    }))
    targets = root / "targets.txt"
    targets.write_text("https://app.example.test/")
    result = plan(profile, api_spec=spec, targets_path=targets, authorized=True)
    assert result["metrics"]["approved_targets_preflighted"] == 1
    assert result["metrics"]["api_contract_operations"] == 1
    assert result["metrics"]["network_requests_executed"] == 0
    assert result["guardrails"]["no_shell_from_ai"] is True
    assert result["guardrails"]["no_evasion"] is True
    assert {s["agent_id"] for s in result["steps"]} == {s["id"] for s in SKILLS}


def test_out_of_scope_preflight_rejects_plan(workspace):
    root, profile = workspace
    targets = root / "bad.txt"
    targets.write_text("https://admin.example.test/")
    with pytest.raises(ValueError):
        plan(profile, targets_path=targets, authorized=True)


def test_plan_does_not_request_public_network(workspace, monkeypatch):
    import socket
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("network attempted")))
    result = plan(workspace[1], authorized=True)
    assert result["metrics"]["network_requests_executed"] == 0


def test_plan_requires_authorization(workspace):
    with pytest.raises(PermissionError):
        plan(workspace[1])


def test_manual_evidence_correlation_never_claims_zero_day(workspace):
    root, profile = workspace
    policy_hash = hashlib.sha256(profile.read_bytes()).hexdigest()
    base = {
        "engine": "hunterqa_authorized_bounty_observation",
        "program": "Owned reward lab", "policy_sha256": policy_hash,
        "findings": [{"id": "header.hsts.absent",
                      "source_url": "https://app.example.test/"}],
    }
    first = root / "one.json"
    second = root / "two.json"
    first.write_text(json.dumps(base))
    second.write_text(json.dumps(base, indent=2))
    report = correlate(profile, [first, second], authorized=True)
    assert report["summary"]["deduplicated_review_candidates"] == 1
    item = report["review_queue"][0]
    assert item["independent_document_count"] == 2
    assert item["review_priority"] == "corroboration_review"
    assert item["confirmed_vulnerability"] is False
    assert item["confirmed_zero_day"] is False
    assert "app.example.test" not in json.dumps(report)


def test_distinct_api_candidates_and_web_evidence_do_not_collapse(workspace):
    root, profile = workspace
    spec = root / "openapi.json"
    spec.write_text(json.dumps({
        "openapi": "3.1.0", "paths": {"/users/{userId}": {"get": {}}}
    }))
    report = inspect_openapi(spec, profile, authorized=True)
    filepath = root / "inventory.json"
    filepath.write_text(json.dumps(report))
    summary = correlate(profile, [filepath], authorized=True)
    assert summary["summary"]["deduplicated_review_candidates"] >= 1
    assert all(i["needs_human_review"] for i in summary["review_queue"])


def test_out_of_scope_and_unknown_rules_skipped(workspace):
    root, profile = workspace
    base = {
        "engine": "hunterqa_authorized_bounty_observation",
        "program": "Owned reward lab",
        "policy_sha256": hashlib.sha256(profile.read_bytes()).hexdigest(),
        "findings": [
            {"id": "header.hsts.absent", "source_url": "https://outside.invalid/"},
            {"id": "invented-confirmed-zero-day", "source_url": "https://app.example.test/"}
        ]
    }
    r = root / "report.json"
    r.write_text(json.dumps(base))
    output = correlate(profile, [r], authorized=True)
    assert not output["review_queue"]


def test_mismatched_program_evidence_rejected(workspace):
    root, profile = workspace
    other = root / "evidence.json"
    other.write_text(json.dumps({"engine": "hunterqa_authorized_bounty_observation",
                                 "program": "Someone Else",
                                 "policy_sha256": "a" * 64, "findings": []}))
    with pytest.raises(ValueError, match="scope provenance"):
        correlate(profile, [other], authorized=True)


def test_unknown_engine_rejected(workspace):
    root, profile = workspace
    r = root / "bad.json"
    r.write_text(json.dumps({"engine": "arbitrary", "findings": []}))
    with pytest.raises(ValueError, match="Unsupported"):
        correlate(profile, [r], authorized=True)


def test_too_many_evidence_files_rejected(workspace):
    with pytest.raises(ValueError):
        correlate(workspace[1], [str(i) for i in range(9)], authorized=True)


def test_authorization_required_for_correlation(workspace):
    with pytest.raises(PermissionError):
        correlate(workspace[1], ["anything"])


def test_evidence_paths_must_live_inside_approved_roots(workspace, tmp_path, monkeypatch):
    root, profile = workspace
    outside = tmp_path / "external.json"
    outside.write_text("{}")
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(root / "nonexistent"))
    with pytest.raises((OSError, ValueError)):
        correlate(profile, [outside], authorized=True)
