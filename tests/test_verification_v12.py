"""Private, offline reviewer dossier tests; no public targets or shell tools."""
import hashlib
import json

import pytest

from hunterqa.agent_workflow_v12 import correlate
from hunterqa.api_surface_v12 import inspect_openapi
from hunterqa.verification_v12 import (
    ENGINE, disclosure_draft, prepare_dossier, read_review_summary, record_review,
)


@pytest.fixture
def sample(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    profile = tmp_path / "approved.json"
    profile.write_text(json.dumps({
        "program": "Owned developer lab", "platform": "local-lab",
        "authorization_reference": "Explicit approved offline lab #234",
        "acknowledged_authorization": True,
        "allowed_hosts": ["app.example.test"],
    }))
    spec = tmp_path / "openapi.json"
    spec.write_text(json.dumps({
        "openapi": "3.1.0", "info": {"title": "Owned lab", "version": "1"},
        "paths": {
            "/v1/users/{userId}": {"get": {"responses": {"200": {"description": "OK"}}}},
            "/v1/billing": {"post": {"security": []}},
        },
    }))
    inventory = inspect_openapi(spec, profile, authorized=True)
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(json.dumps(inventory))
    correlation = correlate(profile, [inventory_path], authorized=True)
    correlated = tmp_path / "correlated.json"
    correlated.write_text(json.dumps(correlation))
    dossier = prepare_dossier(profile, correlated, authorized=True)
    dossier_file = tmp_path / "dossier-v1.json"
    dossier_file.write_text(json.dumps(dossier))
    proof = tmp_path / "reviewer-reproduction.json"
    proof.write_text(json.dumps({
        "authorized_fixture": True,
        "procedure": "Owned accounts only; separate manual reproduction required.",
        "sensitive_payloads_exported": False,
    }))
    return tmp_path, profile, correlated, dossier, dossier_file, proof


def test_review_init_from_real_local_api_correlation(sample):
    root, profile, correlated, dossier, _, _ = sample
    assert dossier["engine"] == ENGINE
    assert len(dossier["cases"]) >= 2
    assert dossier["summary"]["analyst_validated"] == 0
    assert dossier["summary"]["confirmed_zero_days"] == 0
    assert all(c["status"] == "needs_review" and c["history"] == [] for c in dossier["cases"])
    assert all(c["assigned_cve"] is None for c in dossier["cases"])
    assert "app.example.test" not in json.dumps(dossier)


def test_dossier_rejects_correlations_from_other_programs(sample):
    root, profile, correlated, _, _, _ = sample
    payload = json.loads(correlated.read_text())
    payload["policy_sha256"] = "f" * 64
    correlated.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="policy"):
        prepare_dossier(profile, correlated, authorized=True)


def test_no_automatic_confirmation_and_no_unverified_disclosure(sample):
    root, profile, correlated, dossier, file, _ = sample
    with pytest.raises(ValueError, match="No analyst-validated"):
        disclosure_draft(profile, file, authorized=True)
    assert read_review_summary(file) == {
        "status": "ready", "total": len(dossier["cases"]),
        "analyst_validated": 0, "unvalidated": len(dossier["cases"]),
    }


def test_reviewer_can_mark_not_reproducible_without_fake_proof(sample):
    root, profile, correlated, dossier, file, _ = sample
    case = dossier["cases"][0]["id"]
    next_doc = record_review(profile, file, case, "not_reproducible", "kali-reviewer",
                             authorized=True)
    assert next_doc["cases"][0]["status"] == "not_reproducible"
    assert len(next_doc["cases"][0]["history"]) == 1
    assert next_doc["cases"][0]["last_review"]["artifact_sha256"] is None
    assert next_doc["summary"]["analyst_validated"] == 0
    assert next_doc["cases"][0]["history"][0]["previous_event_hash"] == "0" * 64
    assert next_doc["cases"][0]["history"][0]["event_sha256"] != "0" * 64


def test_validated_case_requires_reproduction_file_and_impact(sample):
    root, profile, correlated, dossier, file, proof = sample
    case = dossier["cases"][0]["id"]
    with pytest.raises(ValueError, match="Impact"):
        record_review(profile, file, case, "analyst_validated", "kali-reviewer",
                      impact="too short", reproduction="A" * 40,
                      evidence_path=proof, authorized=True)
    with pytest.raises(ValueError, match="requires"):
        record_review(profile, file, case, "analyst_validated", "kali-reviewer",
                      impact="A" * 40, reproduction="B" * 40,
                      authorized=True)


def test_manual_attestation_stays_private_and_export_is_gated(sample):
    root, profile, correlated, dossier, file, proof = sample
    case = dossier["cases"][0]["id"]
    impact = "Observed access to a controlled fixture resource belonging to another owned test identity."
    reproduction = "Using only owned test accounts, repeat the fixture request with an isolated session and compare the result."
    reviewed = record_review(
        profile, file, case, "analyst_validated", "analyst01",
        impact=impact, reproduction=reproduction, evidence_path=proof,
        authorized=True)
    second = root / "dossier-v2.json"
    second.write_text(json.dumps(reviewed))
    assert reviewed["summary"]["analyst_validated"] == 1
    assert reviewed["summary"]["confirmed_zero_days"] == 0
    assert reviewed["cases"][0]["last_review"]["artifact_sha256"] == hashlib.sha256(
        proof.read_bytes()).hexdigest()
    output = disclosure_draft(profile, second, authorized=True)
    assert "Locally analyst-validated" in output
    assert "Zero-day status: Not established" in output
    assert "CVE: Not assigned" in output
    assert impact in output and reproduction in output
    assert "app.example.test" not in output
    assert "analyst01" in output
    assert json.dumps(reviewed).find("authorized_fixture") == -1
    assert read_review_summary(second)["analyst_validated"] == 1


def test_review_history_detects_modified_provenance(sample):
    root, profile, correlated, dossier, file, proof = sample
    case = dossier["cases"][0]["id"]
    first = record_review(profile, file, case, "needs_more_evidence",
                          "auditor01", authorized=True)
    first_file = root / "second.json"
    first_file.write_text(json.dumps(first))
    second = record_review(profile, first_file, case, "false_positive",
                           "auditor02", authorized=True)
    assert len(second["cases"][0]["history"]) == 2
    assert second["cases"][0]["history"][1]["previous_event_hash"] == (
        second["cases"][0]["history"][0]["event_sha256"])
    second["cases"][0]["history"][0]["analyst_alias"] = "forged-reviewer"
    tampered = root / "tampered.json"
    tampered.write_text(json.dumps(second))
    with pytest.raises(ValueError, match="digest|hash"):
        record_review(profile, tampered, case, "false_positive",
                      "auditor03", authorized=True)
    with pytest.raises(ValueError, match="digest|hash"):
        disclosure_draft(profile, tampered, authorized=True)


def test_out_of_scope_cannot_be_marked_validated(sample):
    root, profile, correlated, dossier, file, proof = sample
    case = dossier["cases"][0]["id"]
    edited = record_review(profile, file, case, "out_of_scope",
                           "analyst01", authorized=True)
    next_file = root / "out-of-scope.json"
    next_file.write_text(json.dumps(edited))
    with pytest.raises(ValueError, match="out-of-scope"):
        record_review(profile, next_file, case, "analyst_validated", "analyst01",
                      impact="A" * 40, reproduction="B" * 40,
                      evidence_path=proof, authorized=True)


def test_unapproved_proof_and_symlink_rejected(sample, tmp_path, monkeypatch):
    root, profile, correlated, dossier, file, proof = sample
    case = dossier["cases"][0]["id"]
    link = root / "sym-link.json"
    link.symlink_to(proof)
    with pytest.raises(ValueError, match="Symlink"):
        record_review(profile, file, case, "analyst_validated", "analyst01",
                      impact="A" * 40, reproduction="B" * 40,
                      evidence_path=link, authorized=True)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(root / "nonexistent"))
    with pytest.raises((OSError, ValueError)):
        record_review(profile, file, case, "false_positive", "analyst01",
                      authorized=True)


@pytest.mark.parametrize("decision", ["false_positive", "not_reproducible", "analyst_validated"])
def test_decisions_never_confirm_zero_day(sample, decision):
    root, profile, correlated, dossier, file, proof = sample
    case = dossier["cases"][0]["id"]
    kwargs = {}
    if decision == "analyst_validated":
        kwargs = {"impact": "Observed impact restricted to a locally owned test account.",
                  "reproduction": "Independently repeat the observation with another permitted local account.",
                  "evidence_path": proof}
    result = record_review(profile, file, case, decision, "researcher01",
                           authorized=True, **kwargs)
    assert result["summary"]["confirmed_zero_days"] == 0
    assert result["cases"][0]["confirmed_zero_day"] is False
    assert result["cases"][0]["assigned_cve"] is None


def test_unknown_rule_or_auto_confirmed_correlation_denied(sample):
    root, profile, correlated, dossier, file, proof = sample
    raw = json.loads(correlated.read_text())
    raw["review_queue"][0]["confirmed_vulnerability"] = True
    corrupted = root / "untrusted.json"
    corrupted.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="unconfirmed"):
        prepare_dossier(profile, corrupted, authorized=True)
    raw["review_queue"][0]["confirmed_vulnerability"] = False
    raw["review_queue"][0]["rule_id"] = "arbitrary-agent-exploit"
    corrupted.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="Unknown rule"):
        prepare_dossier(profile, corrupted, authorized=True)


def test_authorization_required(sample):
    root, profile, correlated, dossier, file, proof = sample
    with pytest.raises(PermissionError):
        prepare_dossier(profile, correlated)
    with pytest.raises(PermissionError):
        record_review(profile, file, dossier["cases"][0]["id"], "false_positive", "analyst01")
    with pytest.raises(PermissionError):
        disclosure_draft(profile, file)


def test_review_dossier_does_not_execute_network_requests(sample, monkeypatch):
    import socket
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("network contacted")))
    root, profile, correlated, dossier, file, proof = sample
    assert prepare_dossier(profile, correlated, authorized=True)["summary"]["total"] > 0
