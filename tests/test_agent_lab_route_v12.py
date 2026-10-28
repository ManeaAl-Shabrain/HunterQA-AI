import json

from hunterqa.agent_workflow_v12 import dashboard_summary, plan


def test_agent_lab_page_is_read_only_even_with_malicious_query(client):
    response = client.get("/agent-lab?target=https://outside.example.net/&execute=true")
    assert response.status_code == 200
    assert b"AI Agent" in response.data
    assert b"No local v1.2 research artifacts loaded" in response.data


def test_agent_lab_renders_only_admin_selected_local_summaries(app, client, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    profile = tmp_path / "scope.json"
    profile.write_text(json.dumps({
        "program": "Owned test bounty", "platform": "local-lab",
        "authorization_reference": "Authorized internal test environment",
        "acknowledged_authorization": True,
        "allowed_hosts": ["app.example.test"],
    }))
    payload = plan(profile, authorized=True)
    p = tmp_path / "plan.json"
    p.write_text(json.dumps(payload))
    app.config["AGENT_PLAN_PATH"] = str(p)
    response = client.get("/agent-lab")
    assert response.status_code == 200
    assert b"Owned test bounty" in response.data
    assert b"scope-guard" in response.data
    assert b"no" in response.data.lower()


def test_admin_report_path_outside_approved_roots_not_loaded(app, client, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path / "other"))
    p = tmp_path / "not-approved.json"
    p.write_text("{}")
    app.config["AGENT_PLAN_PATH"] = str(p)
    response = client.get("/agent-lab")
    assert response.status_code == 200
    assert b"unavailable" in response.data
    assert dashboard_summary(str(p))["status"] == "unavailable"
