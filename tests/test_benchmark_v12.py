"""Offline synthetic review-cue benchmark tests. No public network targets."""
import json
import shutil
from pathlib import Path

import pytest

from hunterqa.api_surface_v12 import inspect_openapi
from hunterqa.benchmark_v12 import benchmark_gate, evaluate_pack, read_benchmark_summary


@pytest.fixture
def synthetic(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    examples = Path(__file__).resolve().parents[1] / "examples" / "benchmarks"
    for name in ("v12_scoped_auth.json", "v12_missing_auth.json",
                 "v12_openapi_golden.json"):
        shutil.copy2(examples / name, tmp_path / name)
    profile = tmp_path / "scope.json"
    profile.write_text(json.dumps({
        "program": "Offline benchmark fixture only",
        "platform": "local-lab",
        "authorization_reference": "Authorized disposable synthetic regression fixture",
        "acknowledged_authorization": True,
        "allowed_hosts": ["app.example.test"],
        "max_requests": 1,
    }))
    return tmp_path, profile, tmp_path / "v12_openapi_golden.json"


def test_golden_pack_scores_review_cues_not_security_vulnerabilities(synthetic):
    root, profile, pack = synthetic
    result = evaluate_pack(profile, pack, authorized=True)
    metrics = result["metrics"]
    assert result["case_count"] == 2
    assert result["golden_review_expectations_met"] is True
    assert metrics["true_positive_review_suggestions"] == 10
    assert metrics["true_negative_review_checks"] == 21
    assert metrics["false_positive_review_suggestions"] == 0
    assert metrics["missed_review_suggestions"] == 0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1"] == 1.0
    assert benchmark_gate(result) is True
    assert result["claims"]["confirmed_vulnerabilities"] == 0
    assert result["claims"]["confirmed_zero_days"] == 0
    assert result["claims"]["real_world_detection_accuracy"] is None
    assert all(not item["violations"] for item in result["cases"])
    assert "app.example.test" not in json.dumps(result)
    assert "/v1/accounts/" not in json.dumps(result)


def test_missing_expected_review_is_counted_as_false_negative(synthetic):
    root, profile, pack = synthetic
    spec = root / "v12_scoped_auth.json"
    doc = json.loads(spec.read_text())
    doc["paths"]["/v1/payments/transfer"]["post"].pop("security")
    spec.write_text(json.dumps(doc))
    result = evaluate_pack(profile, pack, authorized=True)
    assert result["golden_review_expectations_met"] is False
    assert result["metrics"]["missed_review_suggestions"] == 1
    assert result["metrics"]["false_positive_review_suggestions"] == 0
    assert result["cases"][0]["violations"][0]["rule_id"] == "api.public-write-review"
    with pytest.raises(ValueError, match="Synthetic review benchmark failed"):
        benchmark_gate(result)


def test_unexpected_known_negative_counts_as_false_positive(synthetic):
    root, profile, pack = synthetic
    spec = root / "v12_scoped_auth.json"
    doc = json.loads(spec.read_text())
    doc["paths"]["/v1/health"]["get"]["deprecated"] = True
    spec.write_text(json.dumps(doc))
    result = evaluate_pack(profile, pack, authorized=True)
    assert result["golden_review_expectations_met"] is False
    assert result["metrics"]["false_positive_review_suggestions"] == 1
    assert result["metrics"]["labeled_negative_false_positive_rate"] > 0
    assert result["cases"][0]["violations"][0]["kind"] == "unexpected_review"
    assert result["metrics"]["missed_review_suggestions"] == 0


def test_unlabeled_candidate_is_penalized_not_ignored(synthetic):
    root, profile, pack = synthetic
    spec = root / "v12_scoped_auth.json"
    doc = json.loads(spec.read_text())
    doc["paths"]["/v1/accounts/{accountId}"]["get"]["deprecated"] = True
    spec.write_text(json.dumps(doc))
    result = evaluate_pack(profile, pack, authorized=True)
    assert result["metrics"]["unlabeled_predictions_counted_as_false_positive"] == 1
    assert result["metrics"]["false_positive_review_suggestions"] == 1
    assert result["cases"][0]["violations"][0]["kind"] == "unlabeled_prediction"


def test_pack_cannot_refer_to_path_traversal(synthetic):
    root, profile, pack = synthetic
    doc = json.loads(pack.read_text())
    doc["cases"][0]["spec"] = "../outside.json"
    pack.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="safe relative"):
        evaluate_pack(profile, pack, authorized=True)


def test_symlink_spec_is_rejected(synthetic):
    root, profile, pack = synthetic
    target = root / "v12_scoped_auth.json"
    link = root / "synthetic-link.json"
    link.symlink_to(target)
    doc = json.loads(pack.read_text())
    doc["cases"][0]["spec"] = "synthetic-link.json"
    pack.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="Symlink"):
        evaluate_pack(profile, pack, authorized=True)


def test_duplicate_labels_are_rejected(synthetic):
    root, profile, pack = synthetic
    doc = json.loads(pack.read_text())
    doc["cases"][0]["labels"].append(dict(doc["cases"][0]["labels"][0]))
    pack.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="Duplicate benchmark label"):
        evaluate_pack(profile, pack, authorized=True)


def test_invalid_operation_reference_is_rejected(synthetic):
    root, profile, pack = synthetic
    doc = json.loads(pack.read_text())
    doc["cases"][0]["labels"][0]["path"] = "/unknown/not/in/schema"
    pack.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="does not match"):
        evaluate_pack(profile, pack, authorized=True)


def test_negative_only_pack_cannot_claim_precision(synthetic):
    root, profile, pack = synthetic
    doc = json.loads(pack.read_text())
    for case in doc["cases"]:
        for label in case["labels"]:
            label["expected"] = False
    pack.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="positive and negative"):
        evaluate_pack(profile, pack, authorized=True)


def test_unknown_auto_confirmed_inventory_is_rejected(synthetic):
    root, profile, pack = synthetic

    def injected(spec_path, profile_path, *, authorized):
        result = inspect_openapi(spec_path, profile_path, authorized=authorized)
        if result["review_candidates"]:
            result["review_candidates"][0]["confirmed"] = True
        return result

    with pytest.raises(ValueError, match="automatically confirmed"):
        evaluate_pack(profile, pack, authorized=True, inventory=injected)


def test_injected_duplicate_candidate_is_rejected(synthetic):
    root, profile, pack = synthetic

    def duplicates(spec_path, profile_path, *, authorized):
        report = inspect_openapi(spec_path, profile_path, authorized=authorized)
        report["review_candidates"].append(dict(report["review_candidates"][0]))
        return report

    with pytest.raises(ValueError, match="Duplicate candidate prediction"):
        evaluate_pack(profile, pack, authorized=True, inventory=duplicates)


def test_no_network_calls_and_explicit_authorization_required(synthetic, monkeypatch):
    import socket
    monkeypatch.setattr(socket, "create_connection",
                        lambda *args, **kwargs: pytest.fail("Offline benchmark attempted a network request"))
    root, profile, pack = synthetic
    with pytest.raises(PermissionError):
        evaluate_pack(profile, pack)
    assert evaluate_pack(profile, pack, authorized=True)["golden_review_expectations_met"]


def test_benchmark_output_is_private_summary_and_invalid_values_fail_closed(synthetic, monkeypatch):
    root, profile, pack = synthetic
    output = root / "result.json"
    result = evaluate_pack(profile, pack, authorized=True)
    output.write_text(json.dumps(result))
    assert read_benchmark_summary(output) == {
        "status": "ready", "cases": 2, "precision": 1.0,
        "recall": 1.0, "unexpected_reviews": 0,
    }
    result["metrics"]["precision"] = 10
    output.write_text(json.dumps(result))
    assert read_benchmark_summary(output)["status"] == "not_configured"
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(root / "not_approved"))
    assert read_benchmark_summary(output)["status"] == "not_configured"


def test_cli_strict_gates_synthetic_regressions(synthetic, capsys):
    from hunterqa.cli import main
    root, profile, pack = synthetic
    report = root / "benchmark-out.json"
    main(["bounty-benchmark", "--profile", str(profile), "--pack", str(pack),
          "--out", str(report), "--strict", "--authorized"])
    assert report.exists()
    assert "Review expectation gate: PASS" in capsys.readouterr().out
    spec = root / "v12_scoped_auth.json"
    doc = json.loads(spec.read_text())
    doc["paths"]["/v1/health"]["get"]["deprecated"] = True
    spec.write_text(json.dumps(doc))
    fail_path = root / "benchmark-regression.json"
    with pytest.raises(ValueError, match="Synthetic review benchmark failed"):
        main(["bounty-benchmark", "--profile", str(profile), "--pack", str(pack),
              "--out", str(fail_path), "--strict", "--authorized"])
    assert json.loads(fail_path.read_text())["metrics"]["false_positive_review_suggestions"] == 1



def test_agent_lab_shows_only_bounded_synthetic_benchmark_metrics(synthetic, app, client):
    root, profile, pack = synthetic
    result = evaluate_pack(profile, pack, authorized=True)
    result["private_raw_api_url"] = "https://private.example.test/top-secret"
    result["private_token"] = "NEVER-DISPLAY-BENCHMARK-TOKEN"
    file = root / "dashboard-benchmark.json"
    file.write_text(json.dumps(result))
    app.config["BENCHMARK_REPORT_PATH"] = str(file)
    response = client.get("/agent-lab?start-scan=true")
    assert response.status_code == 200
    assert b"OpenAPI review benchmark: ready" in response.data
    assert b"Synthetic test cases: 2" in response.data
    assert b"Labeled-review precision:" in response.data
    assert b"100.0%" in response.data
    assert b"NEVER-DISPLAY-BENCHMARK-TOKEN" not in response.data
    assert b"private.example.test" not in response.data
    assert b"not real vulnerability accuracy" in response.data.lower() or b"NOT real vulnerability accuracy" in response.data


def test_agent_lab_does_not_read_nonapproved_benchmark_file(synthetic, app, client, monkeypatch):
    root, profile, pack = synthetic
    result = evaluate_pack(profile, pack, authorized=True)
    file = root / "hidden-benchmark.json"
    file.write_text(json.dumps(result))
    app.config["BENCHMARK_REPORT_PATH"] = str(file)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(root / "different"))
    response = client.get("/agent-lab")
    assert response.status_code == 200
    assert b"OpenAPI review benchmark: not_configured" in response.data



def test_inventory_candidate_ids_must_match_operation_and_rule(synthetic):
    root, profile, pack = synthetic
    def forged(spec_path, profile_path, *, authorized):
        result = inspect_openapi(spec_path, profile_path, authorized=authorized)
        if result["review_candidates"]:
            result["review_candidates"][0]["id"] = "0" * 20
        return result
    with pytest.raises(ValueError, match="deterministic API operation identity"):
        evaluate_pack(profile, pack, authorized=True, inventory=forged)


def test_malformed_label_rule_rejected_without_typeerror(synthetic):
    root, profile, pack = synthetic
    doc = json.loads(pack.read_text())
    doc["cases"][0]["labels"][0]["rule_id"] = {"unexpected": "object"}
    pack.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="label does not match"):
        evaluate_pack(profile, pack, authorized=True)


def test_malformed_method_rejected_without_typeerror(synthetic):
    root, profile, pack = synthetic
    doc = json.loads(pack.read_text())
    doc["cases"][0]["labels"][0]["method"] = ["PATCH"]
    pack.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="label does not match"):
        evaluate_pack(profile, pack, authorized=True)
