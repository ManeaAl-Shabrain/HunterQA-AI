"""Tests do not contact Ollama or modify source code."""
import hashlib
import json

import pytest

from hunterqa.engines import remediation


@pytest.fixture
def project_and_report(tmp_path, monkeypatch):
    root = tmp_path / "authorized"
    root.mkdir()
    project = root / "project"
    project.mkdir()
    source = project / "demo.py"
    source.write_text("def run(expr):\n    return eval(expr)\n")
    report = root / "triage.json"
    report.write_text(json.dumps({
        "engine": "unified_evidence_triage",
        "findings": [{
            "id": "finding001", "source": "scan",
            "title": "Review dynamic evaluation",
            "file": "demo.py", "line": 2,
            "source_report_sha256": "a" * 64,
        }]
    }))
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(root))
    return project, report, source


def test_proposal_is_read_only_and_hash_bound(project_and_report, monkeypatch):
    project, report, source = project_and_report
    before = source.read_bytes()
    monkeypatch.setattr(remediation, "_ollama_request", lambda prompt, model: {
        "applicable": True,
        "replacement_line": "    return ast.literal_eval(expr)",
        "rationale": "Only safe if the app requires Python literals.",
        "regression_test_idea": "Review valid literals and invalid input",
        "uncertainty": "Requires a separate import and behavioral review.",
    })
    result = remediation.propose_remediation(project, report, "finding001")
    assert result["status"] == "proposal_only"
    assert "-    return eval(expr)" in result["suggested_diff"]
    assert result["source_file_sha256"] == hashlib.sha256(before).hexdigest()
    assert source.read_bytes() == before
    assert result["source_modified"] is False
    assert result["verification_status"] == "not_tested"


def test_missing_source_or_outside_path_rejected(project_and_report):
    project, report, _ = project_and_report
    data = json.loads(report.read_text())
    data["findings"][0]["file"] = "../outside.py"
    report.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="Traversal"):
        remediation.propose_remediation(project, report, "finding001")


def test_reject_multiline_model_output(project_and_report, monkeypatch):
    project, report, source = project_and_report
    monkeypatch.setattr(remediation, "_ollama_request", lambda prompt, model: {
        "applicable": True,
        "replacement_line": "return 1\nexec('bad')",
        "rationale": "no", "regression_test_idea": "no", "uncertainty": "no",
    })
    result = remediation.propose_remediation(project, report, "finding001")
    assert result["status"] == "no_safe_one_line_proposal"
    assert result["suggested_diff"] == ""
