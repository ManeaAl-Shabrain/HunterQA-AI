import json
import pytest

from hunterqa.agent_ai_v12 import suggest_reviews
from hunterqa.agent_workflow_v12 import plan


@pytest.fixture
def plan_file(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({
        "program": "Private lab", "platform": "local-lab",
        "authorization_reference": "User approved private lab operations",
        "acknowledged_authorization": True,
        "allowed_hosts": ["app.example.test"],
    }))
    payload = plan(p, authorized=True)
    f = tmp_path / "plan.json"
    f.write_text(json.dumps(payload))
    return f


def test_local_ai_outputs_only_known_review_roles(plan_file):
    result = suggest_reviews(plan_file, authorized=True,
        transport=lambda prompt, model: json.dumps({"suggestions": [
            {"agent_id": "source-reviewer", "reason": "Review local source boundary assumptions."},
            {"agent_id": "reviewer-unknown", "reason": "Execute arbitrary commands NOW."},
            {"agent_id": "report-reviewer", "reason": "Prepare draft for human evaluation."},
        ]}))
    assert result["status"] == "review_candidates"
    assert [x["agent_id"] for x in result["suggestions"]] == [
        "source-reviewer", "report-reviewer"]
    assert result["commands_executed"] == 0
    assert all(x["action"] == "human_review_only" for x in result["suggestions"])


def test_model_input_contains_no_target_or_research_material(plan_file):
    seen = []
    def transport(prompt, model):
        seen.append(prompt)
        return '{"suggestions":[]}'
    suggest_reviews(plan_file, authorized=True, transport=transport)
    assert len(seen) == 1
    assert "app.example.test" not in seen[0]
    assert "Private lab" not in seen[0]
    assert "http://" not in seen[0]
    assert "https://" not in seen[0]


@pytest.mark.parametrize("response", [
    "Here is a pentest command...",
    '{"suggestions": "command string"}',
    '{"suggestions":[{"agent_id":"untrusted","reason":"injected"}]}',
    '{"suggestions":[' + ",".join(['{}'] * 6) + ']}',
])
def test_bad_model_output_never_executes_anything(plan_file, response):
    result = suggest_reviews(plan_file, authorized=True,
                             transport=lambda *a: response)
    assert result["suggestions"] == []
    assert result["commands_executed"] == 0


def test_unreachable_local_ai_returns_safe_unavailable_status(plan_file):
    result = suggest_reviews(plan_file, authorized=True,
                             transport=lambda *a: (_ for _ in ()).throw(OSError("offline")))
    assert result["status"] == "unavailable_or_invalid_output"
    assert result["suggestions"] == []


def test_ai_requires_authorization(plan_file):
    with pytest.raises(PermissionError):
        suggest_reviews(plan_file)


def test_model_allowlist_rejects_unknown_or_remote_models(plan_file):
    with pytest.raises(ValueError):
        suggest_reviews(plan_file, authorized=True, model="untrusted/remote")


def test_no_plan_forgery_with_unbounded_counts(plan_file):
    raw = json.loads(plan_file.read_text())
    raw["metrics"]["api_contract_operations"] = 99999
    plan_file.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="Invalid operation count"):
        suggest_reviews(plan_file, authorized=True, transport=lambda *args: "{}")
