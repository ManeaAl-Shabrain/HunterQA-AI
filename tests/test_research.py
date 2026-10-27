import json
from hunterqa.research import get_crash_signal, load_research_report, normalize_research_report
from hunterqa.evidence_refresh import load_evidence_snapshot


def sample():
    return {"project": "ZeroScope AI", "findings": [{
        "filename": "id:000000,sig:06", "sha256": "a" * 64, "input_size": 12,
        "attempts": [{"signal": 6, "return_code": -6}], "reproducible": True,
        "category": "unclassified", "verification_status": "requires_source_review"}],
        "sanitizer_evidence": [{"sanitizer": "AddressSanitizer", "category": "heap-use-after-free",
                                "cwe_candidate": "CWE-416", "evidence_confirmed": True,
                                "source_locations": [{"file": "uaf_test.c", "line": 14, "column": 27}]}]}


def test_flat_integrated_report_maps_signal_and_provenance():
    report = normalize_research_report(sample())
    assert report["project"] == "HunterQA AI"
    assert report["source_project_name"] == "ZeroScope AI"
    finding = report["findings"][0]
    assert finding["filename"] == "id:000000,sig:06"
    assert finding["signal"] == 6 and finding["input_size"] == 12
    assert finding["reproducible"] and finding["matched_diagnostics_count"] == 0
    assert finding["correlation_status"] == "not_established"
    assert report["sanitizer_evidence"][0]["cwe_candidate"] == "CWE-416"
    assert report["summary"]["zero_days_confirmed"] == 0


def test_legacy_nested_report():
    report = normalize_research_report({"findings": [{"crash": {"filename": "legacy", "signal": 6},
                                                   "ai_analysis": {"cwe": "CWE-121", "zero_day_confirmed": True}}]})
    assert report["findings"][0]["signal"] == 6
    assert report["findings"][0]["zero_day_confirmed"] is False
    assert report["findings"][0]["cwe_candidate"] == "CWE-121"  # candidate only


def test_snapshot_sha_and_invalid_payload(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(sample()))
    result = load_evidence_snapshot(path)
    assert result["status"] == "ready"
    assert len(result["sha256"]) == 64
    path.write_text("not-json")
    assert load_evidence_snapshot(path)["status"] == "invalid"
    assert load_research_report(path)["error"]


def test_symlink_report_rejected(tmp_path):
    real = tmp_path / "real.json"
    real.write_text(json.dumps(sample()))
    link = tmp_path / "link.json"
    link.symlink_to(real)
    assert load_evidence_snapshot(link)["status"] != "ready"


def test_malicious_claim_is_never_confirmed():
    p = sample()
    p["summary"] = {"zero_days_confirmed": 999}
    p["findings"][0]["zero_day_confirmed"] = True
    p["sanitizer_evidence"][0]["zero_day_confirmed"] = True
    output = normalize_research_report(p)
    assert output["summary"]["zero_days_confirmed"] == 0
    assert output["findings"][0]["zero_day_confirmed"] is False
    assert output["sanitizer_evidence"][0]["zero_day_confirmed"] is False


def test_signal_from_negative_return_code():
    assert get_crash_signal({"attempts": [{"return_code": -6}]}) == 6
    assert get_crash_signal({"attempts": [{"return_code": 0}]}) is None
