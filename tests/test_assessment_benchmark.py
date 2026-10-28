import html
import json

import pytest

from hunterqa.assessment_benchmark import benchmark_assessments, score
from hunterqa.coverage_audit import coverage_audit
from hunterqa.web_canaries import execute_canaries
from hunterqa.workflow_network import NetworkJournal, inspect_network


def test_owned_application_benchmark_retains_labeled_evidence(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    root = tmp_path / "benchmark"
    report = benchmark_assessments(root, authorized=True)
    assert report["all_cases_matched"] and len(report["cases"]) == 8
    assert report["network_requests"] == 14
    assert len(report["ground_truth_sha256"]) == 64 and len(report["fixture_source_sha256"]) == 64
    assert all(row["precision"] == row["recall"] == 1 for row in report["by_class"].values())
    assert (root / "web-canary-check-run" / "report.html").exists()
    assert (root / "authorization-matrix-run" / "report.sarif").exists()
    assert "real-world" in " ".join(report["limitations"])
    with pytest.raises(FileExistsError):
        benchmark_assessments(root, authorized=True)


def test_scoring_preserves_false_negatives_and_false_positives():
    labels = {"cases": [{"id": "positive", "class": "sql-error", "expected": ["rule"]},
                        {"id": "negative", "class": "sql-error", "expected": []}]}
    result = score(labels, [{"test_case": "negative", "rule_id": "rule"}])
    group = result["by_class"]["sql-error"]
    assert group["false_negatives"] == group["false_positives"] == 1
    assert group["precision"] == group["recall"] == 0
    assert not result["all_cases_matched"]
    with pytest.raises(ValueError, match="outside labeled"):
        score(labels, [{"test_case": "unknown", "rule_id": "rule"}])


@pytest.mark.parametrize("context", ["escaped", "textarea", "title", "script", "plaintext", "attribute", "json", "textarea-slash", "script-slash"])
def test_reflection_negative_contexts_do_not_become_markup_findings(tmp_path, monkeypatch, context):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    url = "https://owned.example.test/app"
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"schema_version": 1, "checks": [
        {"id": "owned-check", "kind": "markup-reflection", "url": url, "parameter": "q"}]}))
    policy = {"program": "Owned negative fixture", "platform": "private",
        "authorization_reference": "Written authorization for original offline fixture",
        "acknowledged_authorization": True, "allowed_hosts": ["owned.example.test"],
        "allowed_paths": ["/app"], "methods": ["GET"], "allowed_ports": [443],
        "max_requests": 2, "interval_seconds": 0.5}

    def transport(policy, target, method, *, query):
        value = query["q"]
        body = {"escaped": html.escape(value), "textarea": f"<textarea>{value}</textarea>",
            "title": f"<title>{value}</title>", "script": f"<script>{value}</script>",
            "plaintext": f"<plaintext>{value}</plaintext>{value}",
            "attribute": f"<input value='{value}'>", "json": json.dumps({"q": value}),
            "textarea-slash": f"<textarea/>{value}", "script-slash": f"<script/>{value}"}[context]
        return {"status": 200, "headers": [("Content-Type", "application/json" if context == "json" else "text/html")],
                "body": body.encode()}

    result = execute_canaries({"policy": policy, "step": {"targets": [url], "requests": 2},
        "binding": {"file": str(manifest)}, "network_log": str(tmp_path / "network.jsonl"),
        "interval_seconds": 0.5}, transport=transport, sleeper=lambda _: None)
    assert result["requests"] == 2 and not result["findings"]


def test_query_journal_rejects_a_different_probe_even_with_a_valid_hash_chain(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    target = "https://owned.example.test/app"
    path = tmp_path / "network.jsonl"
    journal = NetworkJournal(path)
    journal.append("intent", target, "GET", request_sha256="0" * 64)
    journal.close()
    with pytest.raises(ValueError, match="reviewed fixed probe"):
        inspect_network(path, [target], request_digests=["1" * 64])


def test_coverage_contract_never_equates_adapters_with_complete_areas():
    report = coverage_audit()
    assert len(report["areas"]) == 7 and not report["all_seven_areas_complete"]
    assert all(area["status"] == "partial" and area["missing"] for area in report["areas"])
    assert any("SSRF" in area["missing"] for area in report["areas"])
