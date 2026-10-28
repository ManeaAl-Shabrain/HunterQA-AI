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



def test_agent_lab_displays_only_bounded_browser_and_replay_counts(app, client, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    browser = tmp_path / "browser-report.json"
    browser.write_text(json.dumps({
        "engine": "hunterqa_v12_owned_browser_lab",
        "traffic": {"approved_requests": 3, "blocked_requests": 1},
        "authentication": "attempted_unverified",
        "dangerous_raw_cookie": "private-cookie-do-not-show",
    }))
    replay = tmp_path / "head-report.json"
    replay.write_text(json.dumps({
        "engine": "hunterqa_v12_controlled_head_replay",
        "summary": {"requests_attempted": 1, "status_differences": 0},
        "private_url": "http://secret.internal/do-not-show",
    }))
    app.config["BROWSER_LAB_REPORT_PATH"] = str(browser)
    app.config["HEAD_REPLAY_REPORT_PATH"] = str(replay)
    response = client.get("/agent-lab?execute=true")
    assert response.status_code == 200
    assert b"Playwright owned-browser lab: ready" in response.data
    assert b"HEAD-only sanitized HAR replay: ready" in response.data
    assert b"attempted_unverified" in response.data
    assert b"private-cookie-do-not-show" not in response.data
    assert b"secret.internal" not in response.data


def test_agent_lab_does_not_load_unapproved_browser_report(app, client, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path / "empty"))
    report = tmp_path / "unapproved.json"
    report.write_text(json.dumps({"engine": "hunterqa_v12_owned_browser_lab",
                                  "traffic": {"approved_requests": 5, "blocked_requests": 0},
                                  "authentication": "not_attempted"}))
    app.config["BROWSER_LAB_REPORT_PATH"] = str(report)
    response = client.get("/agent-lab")
    assert b"Playwright owned-browser lab: not_configured" in response.data
