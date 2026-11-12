"""Actual owned HTTP/SQLite/Chromium versus explicitly simulated AD/cloud models."""
from datetime import timedelta
import json
import os
import socketserver
import threading
import time

import pytest

from hunterqa import access_graph, assessment_sessions, scenario_assessment as suite, scenario_lab as lab
from hunterqa import service_fingerprints
from hunterqa.engagement import utcnow


@pytest.fixture
def owned(tmp_path, monkeypatch):
    cases, secrets = tmp_path / "cases", tmp_path / "private"
    cases.mkdir(mode=0o700)
    secrets.mkdir(mode=0o700)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(cases))
    monkeypatch.setenv("HUNTERQA_ASSESSMENT_SECRET_ROOT", str(secrets))
    monkeypatch.delenv("HUNTERQA_QUOTA_LEDGER", raising=False)
    with lab.serve() as services:
        profile = cases / "profile.json"
        profile.write_text(json.dumps(lab.profile(services)))
        vault, key = secrets / "session.json", secrets / "session.key"
        assessment_sessions.create(vault, key, json.dumps(lab.sessions(services)).encode(), authorized=True)
        yield {**services, "root": cases, "profile": profile, "session_file": str(vault), "session_key": str(key), "key": key}


def execute(owned, case, *, send=suite.transport):
    path = owned["root"] / "plan.json"
    path.write_text(json.dumps(lab.plan([case])))
    sessions = {key: owned[key] for key in ("session_file", "session_key")}
    before = suite.preflight(owned["profile"], path, **sessions)
    return suite.run(owned["profile"], path, before["approval_sha256"], authorized=True, send=send, **sessions)


@pytest.mark.parametrize("context", ["single-quoted", "double-quoted", "numeric"])
def test_actual_sqlite_context_differential_with_negative_and_repeat_controls(owned, context):
    report = execute(owned, lab.case("sqli-boolean", owned, context=context))
    row = report["cases"][0]
    assert row["state"] == "matched" and row["repeat_consistent"]
    assert [r["canary_observed"] for r in row["receipts"]] == [False, True, False, True, False]
    assert report["requests"] == 5 and not report["stopped"]
    assert report["customer_vulnerabilities_confirmed"] == 0


def test_parameterized_query_negative_control_does_not_match(owned):
    case = lab.case("sqli-boolean", owned)
    case["url"] = owned["base"] + "/safe"
    report = execute(owned, case)
    assert report["cases"][0]["state"] == "not_observed"


def test_actual_owned_ssrf_callback_and_inert_upload_cleanup(owned):
    report = execute(owned, lab.case("ssrf-callback", owned))
    assert report["cases"][0]["state"] == "matched" and report["requests"] == 3
    assert ("GET", "/receive") in owned["requests"]
    report = execute(owned, lab.case("upload-canary", owned))
    assert report["cases"][0]["state"] == "matched" and report["requests"] == 5
    assert report["cases"][0]["cleanup_verified"] and not owned["uploads"]


def test_actual_workflow_checks_two_actor_boundaries_and_cookie_session(owned):
    report = execute(owned, lab.case("workflow", owned))
    assert report["cases"][0]["state"] == "matched" and report["requests"] == 5
    assert [r["status"] for r in report["cases"][0]["receipts"]] == [200, 403, 403, 200, 200]
    assert lab.SECRET not in json.dumps(report)


def test_get_only_profile_does_not_authorize_uploads_or_browser_posts(owned):
    profile = json.loads(owned["profile"].read_text())
    profile.pop("scenario_methods")
    owned["profile"].write_text(json.dumps(profile))
    with pytest.raises(ValueError, match="POST scope"):
        execute(owned, lab.case("upload-canary", owned))
    with pytest.raises(ValueError, match="method"):
        execute(owned, lab.case("browser-journey", owned))
    assert not owned["requests"]


def test_native_slow_response_respects_combined_io_deadline(owned):
    from hunterqa.bounty import BountyPolicy
    policy = BountyPolicy.from_dict(lab.profile(owned))
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        suite.transport(policy, owned["base"] + "/slow", "GET", deadline=start + 0.25)
    assert time.monotonic() - start < 1.5


def test_expired_target_session_is_rejected_before_io(owned):
    data = lab.sessions(owned)
    data["expires_at"] = (utcnow() - timedelta(seconds=1)).isoformat()
    with pytest.raises(ValueError, match="expire"):
        assessment_sessions.validate(data)


def test_anonymous_http_control_does_not_inherit_a_previous_cookie(owned):
    case = lab.case("workflow", owned)
    steps = case["steps"][-2:]
    for row in steps:
        row["actor"] = "anonymous"
    steps[-1]["expected_status"], steps[-1]["expected_body_sha256"] = 403, None
    case["steps"] = steps
    report = execute(owned, case)
    assert report["cases"][0]["state"] == "matched"
    assert report["cases"][0]["receipts"][-1]["status"] == 403


def test_timing_measures_only_a_simulated_delay_and_does_not_claim_sql_proof(owned):
    report = execute(owned, lab.case("sqli-timing", owned))
    row = report["cases"][0]
    assert row["state"] == "timing_signal"
    assert row["evidence_level"] == "latency-differential-not-sql-proof"
    assert not row["customer_vulnerability_confirmed"]


@pytest.mark.parametrize("change", ["scope", "expiry", "method", "unowned", "budget", "actor-origin", "collector-origin", "parameter"])
def test_rejected_contracts_do_not_send_traffic(owned, change):
    case = lab.case("ssrf-callback", owned)
    plan = lab.plan([case])
    if change == "scope":
        case["url"] = "https://outside.invalid/"
    elif change == "expiry":
        plan["expires_at"] = (utcnow() - timedelta(seconds=1)).isoformat()
    elif change == "method":
        case["method"] = "DELETE"
    elif change == "unowned":
        case["owned_test_endpoint"] = False
    elif change == "budget":
        plan["max_requests"] = 2
    elif change == "actor-origin":
        case["collector_actor"] = "owner"
    elif change == "collector-origin":
        case["receive_url"] = owned["base"] + "/receive"
        case["read_url"] = owned["base"] + "/read"
    else:
        case["parameter"] = "bad\r\nname"
    path = owned["root"] / "plan.json"
    path.write_text(json.dumps(plan))
    before = len(owned["requests"])
    with pytest.raises((ValueError, TypeError)):
        suite.preflight(owned["profile"], path, session_file=owned["session_file"], session_key=owned["session_key"])
    assert len(owned["requests"]) == before


def test_authorization_approval_change_stop_and_shared_quota_are_checked_before_network(owned):
    case = lab.case("sqli-boolean", owned)
    path = owned["root"] / "plan.json"
    path.write_text(json.dumps(lab.plan([case])))
    approval = suite.preflight(owned["profile"], path)["approval_sha256"]
    with pytest.raises(PermissionError):
        suite.run(owned["profile"], path, approval)
    with pytest.raises(PermissionError):
        suite.run(owned["profile"], path, "a" * 64, authorized=True)
    (owned["root"] / "stop").write_text("stop")
    result = suite.run(owned["profile"], path, approval, authorized=True)
    assert result["stopped"] and result["requests"] == 0
    (owned["root"] / "stop").unlink()
    plan = json.loads(path.read_text())
    plan["max_requests"] = 39
    path.write_text(json.dumps(plan))
    with pytest.raises(PermissionError):
        suite.run(owned["profile"], path, approval, authorized=True)


def test_scope_modified_between_requests_stops_without_second_request(owned):
    count = 0
    def changed(*args, **kwargs):
        nonlocal count
        count += 1
        response = suite.transport(*args, **kwargs)
        profile = json.loads(owned["profile"].read_text())
        profile["max_requests"] = 39
        owned["profile"].write_text(json.dumps(profile))
        return response
    report = execute(owned, lab.case("sqli-boolean", owned), send=changed)
    assert count == report["requests"] == 1 and report["stopped"]


def test_shared_ledger_stop_after_first_request_preserves_full_reservation(owned, monkeypatch):
    from hunterqa import shared_quota
    ledger = owned["root"] / "quota.sqlite3"
    shared_quota.initialize(ledger, max_requests=5, max_active_runs=1,
        expires_at=(utcnow() + timedelta(minutes=5)).isoformat(), authorized=True)
    monkeypatch.setenv("HUNTERQA_QUOTA_LEDGER", str(ledger))
    def stopped(*args, **kwargs):
        response = suite.transport(*args, **kwargs)
        shared_quota.stop(ledger, authorized=True)
        return response
    result = execute(owned, lab.case("sqli-boolean", owned), send=stopped)
    assert result["requests"] == 1 and result["stopped"]
    assert result["shared_quota"]["reservation_released"] is True
    state = shared_quota.status(ledger)
    assert state["charged_requests"] == 5


def test_upload_timeout_keeps_manual_cleanup_reference(owned):
    def timeout(policy, url, method, **kwargs):
        if method == "POST":
            raise TimeoutError("owned timeout")
        return suite.transport(policy, url, method, **kwargs)
    report = execute(owned, lab.case("upload-canary", owned), send=timeout)
    row = report["cases"][0]
    assert row["state"] == "inconclusive" and len(row["canary_id"]) == 32
    assert not row["cleanup_verified"] and report["stopped"]


def test_encrypted_vault_and_key_scope_rotation(owned, monkeypatch):
    from pathlib import Path
    assert lab.SECRET.encode() not in Path(owned["session_file"]).read_bytes()
    case = lab.case("workflow", owned)
    path = owned["root"] / "plan.json"
    path.write_text(json.dumps(lab.plan([case])))
    sessions = {key: owned[key] for key in ("session_file", "session_key")}
    suite.preflight(owned["profile"], path, **sessions)
    owned["key"].write_text("a" * 64)
    with pytest.raises(ValueError):
        suite.preflight(owned["profile"], path, **sessions)
    monkeypatch.setenv("HUNTERQA_ASSESSMENT_SECRET_ROOT", str(owned["root"]))
    with pytest.raises(ValueError):
        assessment_sessions.private_path(owned["root"] / "bad")


@pytest.mark.parametrize("domain", ["active-directory", "aws", "azure", "gcp"])
def test_group_access_tenant_denial_and_candidate_paths_are_explicit_models(domain):
    report = access_graph.evaluate(lab.graph(domain))
    assert [row["model_result"] for row in report["queries"]] == ["allow", "deny"]
    assert all(row["contract_state"] == "matched" for row in report["queries"])
    assert report["paths"][0]["candidate_paths"]
    assert not report["effective_live_access_verified"] and report["network_requests"] == 0


@pytest.mark.parametrize("condition,effect,expected", [("unknown", "deny", "unknown"), ("satisfied", "deny", "deny"), ("unsatisfied", "deny", "allow")])
def test_unknown_conditions_and_explicit_denial_override_allow(condition, effect, expected):
    data = lab.graph("aws")
    data["grants"].append({"principal": "user-a", "resource": "resource-a", "actions": ["read", "administer"],
        "effect": effect, "condition": condition, "source_sha256": "a" * 64})
    report = access_graph.evaluate(data)
    assert report["queries"][0]["model_result"] == expected
    assert bool(report["paths"][0]["candidate_paths"]) == (expected == "allow")


def test_nested_membership_cycles_disabled_users_and_wildcards_fail_safe():
    data = lab.graph("azure")
    data["memberships"].append({"member": "group-a", "group": "group-a", "source_sha256": "a" * 64})
    assert access_graph.evaluate(data)["queries"][0]["model_result"] == "allow"
    data["principals"][0]["enabled"] = False
    assert access_graph.evaluate(data)["queries"][0]["model_result"] == "deny"
    data["grants"][0]["actions"] = ["*"]
    with pytest.raises(ValueError):
        access_graph.evaluate(data)


@pytest.mark.parametrize("protocol,banner", [("ssh", b"SSH-2.0-OpenSSH_9.0 Ubuntu\r\n"), ("smtp", b"220 Postfix Debian\r\n"),
    ("ftp", b"220 vsFTPd\r\n"), ("redis", b"+PONG\r\n"), ("http", b"HTTP/1.0 200 OK\r\nServer: nginx\r\n\r\n")])
def test_real_owned_tcp_protocol_responses_and_product_claims(owned, protocol, banner):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            if protocol in {"redis", "http"}:
                self.request.recv(1024)
            self.request.sendall(banner)
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        contract = {"schema_version": 1, "protocol": protocol, "authorization_reference": "Owned service fixture",
            "acknowledged_authorization": True, "expires_at": (utcnow() + timedelta(minutes=5)).isoformat(),
            "server_ip": "127.0.0.1", "server_port": server.server_address[1], "allow_private_network": True}
        path = owned["root"] / "service.json"
        path.write_text(json.dumps(contract))
        report = service_fingerprints.inspect(path, authorized=True)
        assert report["outcome"] == "observed" and not report["product_verified"] and not report["os_verified"]
        assert "Ubuntu" not in json.dumps(report) or report["advertised_os_hint"] == "Ubuntu"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


@pytest.mark.skipif(os.environ.get("HUNTERQA_ENGAGEMENT_BROWSER_CI") != "1", reason="Opt-in actual Chromium app interaction")
def test_real_browser_session_localstorage_actions_and_dynamic_routes(owned):
    report = execute(owned, lab.case("browser-journey", owned))
    row = report["cases"][0]
    assert row["state"] == "matched", row
    assert len(row["actions"]) == 4 and row["discovered_routes_sha256"]
    assert report["requests"] == 2 and lab.SECRET not in json.dumps(report)


@pytest.mark.skipif(os.environ.get("HUNTERQA_ENGAGEMENT_BROWSER_CI") != "1", reason="Opt-in actual Chromium XSS controls")
@pytest.mark.parametrize("context,path,expected", [("html", "html", "matched"), ("double-attribute", "double", "matched"),
    ("single-attribute", "single", "matched"), ("dom-fragment", "dom", "matched"), ("html", "safe", "not_observed"), ("html", "csp", "not_observed")])
def test_real_browser_xss_contexts_escape_controls_and_owner_csp(owned, context, path, expected):
    case = {"id": "xss", "kind": "xss-context", "owned_test_endpoint": True, "actor": "anonymous",
        "url": owned["base"] + "/xss-" + path, "parameter": "value", "context": context, "script_urls": []}
    report = execute(owned, case)
    row = report["cases"][0]
    assert row["state"] == expected, row
    assert row["execution_signals"] == ([False, True, False, True, False] if expected == "matched" else [False] * 5)
    assert not row["customer_vulnerability_confirmed"]


def test_saved_evidence_correlation_links_digests_without_promoting_findings(owned):
    from hunterqa.assessment_correlation import correlate
    from hunterqa.scenario_reports import summary
    first = execute(owned, lab.case("workflow", owned))
    path = owned["root"] / "workflow-report.json"
    path.write_text(json.dumps(first))
    witness = first["cases"][0]["receipts"][0]["body_sha256"]
    data = lab.graph("gcp")
    data["grants"][0]["source_sha256"] = witness
    second = access_graph.evaluate(data)
    second_path = owned["root"] / "graph-report.json"
    second_path.write_text(json.dumps(second))
    result = correlate([path, second_path], authorized=True)
    assert result["links"] and result["links"][0]["meaning"] == "matching-digest-only"
    assert result["network_requests"] == result["customer_vulnerabilities_confirmed"] == 0
    saved = owned["root"] / "index.json"
    saved.write_text(json.dumps(result))
    assert summary(saved)["status"] == "ready"
    with pytest.raises(ValueError):
        correlate([path, path], authorized=True)


def test_workspace_history_links_project_verifies_digest_and_respects_operator_gate(tmp_path, monkeypatch):
    from hunterqa import assessment_history, create_app, workspace
    from hunterqa.db import get_db
    from tests import test_workspaces as ws
    spaces = ws.spaces.__wrapped__(tmp_path, monkeypatch)
    config = spaces[2][0]
    app = create_app({"WORKSPACE_CONFIG": str(config), "TESTING": True})
    with app.app_context():
        with get_db() as db:
            db.execute("INSERT INTO projects(id,name,path) VALUES(1,'Scenario project',?)", (str(spaces[1][0] / "assessments"),))
    output = spaces[1][0] / "assessments/evidence/scenario.json"
    binding = assessment_history.prepare(config, output, 1)
    report = {"engine": "approved-scenario-suite", "schema_version": 1, "cases": [{"id": "one", "kind": "workflow", "state": "matched"}], "stopped": False}
    output.write_text(json.dumps(report))
    run_id = assessment_history.record(binding, output, report)
    client = app.test_client()
    assert client.get("/scenarios/" + str(run_id)).status_code == 302
    ws._login(client)
    response = client.get("/scenarios/" + str(run_id))
    assert response.status_code == 200 and b"Scenario project" in response.data and b"workflow" in response.data
    assert assessment_history.saved(app.config["DATABASE"], run_id)["status"] == "ready"
    output.write_text("{}")
    assert assessment_history.saved(app.config["DATABASE"], run_id)["status"] == "unavailable"
    with pytest.raises(ValueError):
        assessment_history.prepare(config, tmp_path / "outside.json", 1)
    from hunterqa.cli import main
    model = spaces[1][0] / "assessments/model.json"
    model.write_text(json.dumps(lab.graph("aws")))
    monkeypatch.delenv("HUNTERQA_APPROVED_ROOTS", raising=False)
    main(["access-graph-review", "--input", str(model), "--out", str(model.with_name("model-report.json")),
        "--workspace-config", str(config), "--project-id", "1", "--authorized"])
    assert len(assessment_history.history(app.config["DATABASE"])) == 2
    monkeypatch.setattr(workspace, "_ACTIVE", None)
