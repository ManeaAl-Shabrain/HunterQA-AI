import json
import pytest
from hunterqa.engines.patch_guard import inspect_patch_line
from hunterqa.engines import remediation

@pytest.fixture
def project_and_report(tmp_path, monkeypatch):
    root = tmp_path / 'approved'
    project = root / 'source'
    project.mkdir(parents=True)
    file = project / 'demo.py'
    file.write_text('def test(expr):\n    return eval(expr)\n')
    report = root / 'triage.json'
    report.write_text(json.dumps({'engine': 'unified_evidence_triage', 'findings': [
        {'id': 'finding001', 'source': 'scan', 'title': 'Dynamic evaluation',
         'file': 'demo.py', 'line': 2, 'source_report_sha256': 'a' * 64}
    ]}))
    monkeypatch.setenv('HUNTERQA_APPROVED_ROOTS', str(root))
    return project, report, file


@pytest.mark.parametrize("line", [
    "return eval(expression, {'__builtins__': None})",
    "return eval(expression)",
    "exec(source)",
    "return pickle.loads(data)",
    "return subprocess.run(command, shell=True)",
    "return os.system(command)",
])
def test_unsafe_python_remediations_blocked(line):
    result = inspect_patch_line("demo.py", line)
    assert result["verdict"] == "blocked_unsafe"
    assert result["blocking"] is True
    assert result["security_fix_verified"] is False


def test_correct_looking_patch_still_needs_review():
    result = inspect_patch_line("demo.py", "return ast.literal_eval(expression)")
    assert result["verdict"] == "manual_review"
    assert result["blocking"] is False
    assert result["security_fix_verified"] is False


def test_unsupported_language_not_auto_approved():
    result = inspect_patch_line("demo.php", "return $value;")
    assert result["verdict"] == "manual_review"


def test_invalid_patch_is_blocked():
    result = inspect_patch_line("demo.py", "return x\nexec(y)")
    assert result["verdict"] == "blocked_invalid"


def test_unsafe_ollama_suggestion_never_produces_patch(
    project_and_report, monkeypatch
):
    project, report, source = project_and_report
    original = source.read_bytes()
    monkeypatch.setattr(remediation, "_ollama_request", lambda prompt, model: {
        "applicable": True,
        "replacement_line": "    return eval(expr, {'__builtins__': None})",
        "rationale": "Incorrect claim",
        "regression_test_idea": "Check code",
        "uncertainty": "unknown",
    })
    result = remediation.propose_remediation(project, report, "finding001")
    assert result["status"] == "rejected_unsafe_proposal"
    assert result["safety_gate"]["blocking"] is True
    assert result["suggested_diff"] == ""
    assert result["source_modified"] is False
    assert source.read_bytes() == original
