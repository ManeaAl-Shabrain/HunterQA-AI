from hunterqa.engines.campaign_trends import build_campaign_trends


def run(name, project="demo", records=None, scan="completed", integrity="hashes_match"):
    return {
        "id": name, "project": project, "started_at": name,
        "finished_at": name, "manifest_sha256": "a" * 64,
        "integrity": integrity, "records": len(records or []),
        "stages": {"scan": scan, "ai": "skipped"},
        "_records": records or [],
    }


def finding(title, source="scan"):
    return {
        "source": source, "title": title,
        "file": "demo.py", "line": 9, "cwe_candidate": "CWE-95",
    }


def test_added_and_persisting_are_not_confirmed_regressions():
    history = {"status": "ready", "campaigns": [
        run("2026-01", records=[finding("A")]),
        run("2026-02", records=[finding("A"), finding("B"), finding("AI", "ai")]),
    ]}
    result = build_campaign_trends(history)
    step = result["projects"][0]["transitions"][0]
    assert step["new_static_candidates"] == 1
    assert step["persisting_static_candidates"] == 1
    assert step["no_longer_observed"] == 0
    assert result["zero_days_confirmed"] == 0
    assert "not proof" in result["limitations"]


def test_failed_or_partial_scan_not_comparable():
    history = {"status": "ready", "campaigns": [
        run("2026-01", records=[finding("A")]),
        run("2026-02", records=[], scan="failed"),
    ]}
    step = build_campaign_trends(history)["projects"][0]["transitions"][0]
    assert step["comparison"] == "not_comparable"
    assert step["new_static_candidates"] is None


def test_unverified_and_different_projects_excluded():
    history = {"status": "ready", "campaigns": [
        run("one", project="alpha", records=[finding("A")]),
        run("two", project="beta", records=[finding("B")]),
        run("bad", project="alpha", records=[finding("C")], integrity="verification_failed"),
    ]}
    result = build_campaign_trends(history)
    assert result["excluded_unverified"] == 1
    assert len(result["projects"]) == 2
    assert all(not item["transitions"] for item in result["projects"])


def test_missing_history_returns_unavailable():
    result = build_campaign_trends({"status": "unavailable", "campaigns": []})
    assert result["status"] == "unavailable"
    assert result["projects"] == []


def test_trends_route(client, app, tmp_path):
    app.config["CAMPAIGN_HISTORY_ROOT"] = str(tmp_path)
    app.config["APPROVED_ROOTS"] = [str(tmp_path)]
    response = client.get("/trends")
    assert response.status_code == 200
    assert b"Research Trends" in response.data
    assert b"Confirmed zero-days" in response.data
