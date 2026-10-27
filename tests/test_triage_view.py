
import json

from hunterqa.engines.triage_view import read_triage_report


def sample_report():
    return {
        "engine": "unified_evidence_triage",
        "findings": [
            {
                "id": "test-1",
                "source": "scan",
                "title": "Possible unsafe deserialization",
                "status": "unverified_static_finding",
                "cwe_candidate": "CWE-502",
                "source_report_sha256": "a" * 64,
                "zero_day_confirmed": True,
            },
            {
                "id": "test-2",
                "source": "sanitizer",
                "title": "heap-use-after-free",
                "status": "sanitizer_diagnostic_requires_impact_review",
                "cwe_candidate": "CWE-416",
            },
        ],
    }


def test_triage_loader(tmp_path):
    path = tmp_path / "triage.json"
    path.write_text(json.dumps(sample_report()))

    result = read_triage_report(path)

    assert result["status"] == "ready"
    assert result["total_records"] == 2
    assert result["by_source"]["scan"] == 1
    assert result["by_source"]["sanitizer"] == 1
    assert result["zero_days_confirmed"] == 0
    assert all(
        not row["zero_day_confirmed"]
        for row in result["findings"]
    )


def test_invalid_triage_json(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text("{bad json")

    result = read_triage_report(path)

    assert result["status"] == "invalid"
    assert result["findings"] == []


def test_triage_dashboard_route(client, app, tmp_path):
    path = tmp_path / "triage.json"
    path.write_text(json.dumps(sample_report()))

    app.config["TRIAGE_REPORT_PATH"] = str(path)

    response = client.get("/triage")

    assert response.status_code == 200
    assert b"Vulnerability Triage" in response.data
    assert b"heap-use-after-free" in response.data

    filtered = client.get("/triage?source=scan")

    assert filtered.status_code == 200
    assert b"Possible unsafe deserialization" in filtered.data
    assert b"heap-use-after-free" not in filtered.data
