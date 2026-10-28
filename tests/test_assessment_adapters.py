import hashlib
import json
import os
import socket
import threading
import time
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hunterqa import shared_quota
from hunterqa.assessment_setup import setup_assessment
from hunterqa.engagement import utcnow
from hunterqa.workflow_runner import run_workflow


@pytest.fixture
def owned(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    seen = []
    state = {"delay": 0, "status": None}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            time.sleep(state["delay"])
            status = state["status"] or (200 if self.headers.get("Authorization") == "Bearer SENSITIVE_FIXTURE_A"
                or self.path == "/app/broken" else 403)
            self.send_response(status)
            self.end_headers()
            try:
                self.wfile.write(b"Owned synthetic object")
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    seed = f"http://127.0.0.1:{server.server_port}/app/owner"
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"program": "Owned assessment fixture", "platform": "local-lab",
        "authorization_reference": "Written authorization for owned synthetic loopback tests",
        "acknowledged_authorization": True, "allowed_hosts": ["127.0.0.1", "other.example.test"],
        "allowed_ports": [server.server_port], "allowed_paths": ["/app"],
        "methods": ["GET"], "max_requests": 8, "interval_seconds": 0.5,
        "lab_mode": True, "allow_http": True, "allow_private_network": True}))
    roles = {"owner": {"origin": seed, "authenticated": True},
             "other": {"origin": seed, "authenticated": True},
             "anonymous": {"origin": seed, "authenticated": False}}
    cases = [{"id": case_id, "role": role, "url": url, "expect": expect, "statuses": statuses,
              "body_sha256": None} for case_id, role, url, expect, statuses in (
        ("own-object", "owner", seed, "allow", [200]),
        ("cross-account-denied", "other", seed, "deny", [403]),
        ("anonymous-denied", "anonymous", seed, "deny", [403]),
        ("broken-cross-account", "other", seed.replace("/owner", "/broken"), "deny", [403]))]
    matrix = tmp_path / "matrix.json"
    matrix.write_text(json.dumps({"schema_version": 1, "roles": roles, "cases": cases}))
    secrets = tmp_path / "credentials.json"
    secrets.write_text(json.dumps({"owner": "Bearer SENSITIVE_FIXTURE_A", "other": "Bearer SENSITIVE_FIXTURE_B"}))
    try:
        yield tmp_path, profile, seed, matrix, secrets, seen, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def run(owned, *, tool="authorization-matrix", targets=()):
    root, profile, _, matrix, secrets, _, _ = owned
    config = root / "config"
    kwargs = {"input_file": matrix, "secret_file": secrets} if tool == "authorization-matrix" else {"targets": targets}
    review = setup_assessment(profile, tool, config, authorized=True, **kwargs)
    return run_workflow(profile, config / "protocol.json", config / "bindings.json", root / "run",
        execution_approval=review["execution_sha256"], protocol_approval=review["preflight"]["protocol_sha256"],
        approved_steps=["assess"], authorized=True)


def test_real_role_pairs_and_anonymous_denials_remain_separate_and_private(owned):
    result = run(owned)
    assert result["status"] == "completed" and len(owned[5]) == 4
    assert result["charged_requests"] == 4
    assert result["access_checks"][0]["summary"]["contracts_matched"] == 3
    assert len(result["findings"]) == 1
    assert result["findings"][0]["test_case"] == "broken-cross-account"
    assert result["findings"][0]["verification_status"] == "unverified"
    assert result["network_evidence"][0]["intents"] == 4
    assert result["network_evidence"][0]["responses"] == 4
    for path in (owned[0] / "run").iterdir():
        if path.suffix in (".json", ".jsonl", ".html", ".sarif", ".input"):
            assert "SENSITIVE_FIXTURE" not in path.read_text()
    assert not any(path.name.endswith("secret.input") for path in (owned[0] / "run").iterdir())


@pytest.mark.parametrize("status", [302, 401, 429, 503])
def test_unexpected_auth_failure_or_safety_signal_stops_followups(owned, status):
    owned[6]["status"] = status
    result = run(owned)
    assert result["status"] == "cancelled" and len(owned[5]) == 1
    assert result["charged_requests"] == 4


def test_cross_origin_credentials_are_rejected_during_offline_planning(owned):
    root, profile, seed, matrix, secrets, seen, _ = owned
    data = json.loads(matrix.read_text())
    data["cases"][0]["url"] = seed.replace("127.0.0.1", "other.example.test")
    matrix.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="origin"):
        setup_assessment(profile, "authorization-matrix", root / "config",
            input_file=matrix, secret_file=secrets, authorized=True)
    assert not seen


def test_credential_rotation_requires_fresh_approval(owned):
    root, profile, _, matrix, secrets, seen, _ = owned
    config = root / "config"
    review = setup_assessment(profile, "authorization-matrix", config,
        input_file=matrix, secret_file=secrets, authorized=True)
    secrets.write_text(json.dumps({"owner": "Bearer ROTATED_FIXTURE_A", "other": "Bearer ROTATED_FIXTURE_B"}))
    with pytest.raises(PermissionError, match="fingerprint"):
        run_workflow(profile, config / "protocol.json", config / "bindings.json", root / "denied",
            execution_approval=review["execution_sha256"], protocol_approval=review["preflight"]["protocol_sha256"],
            approved_steps=["assess"], authorized=True)
    assert not seen and not (root / "denied").exists()


def test_real_service_connects_distinguish_open_and_refused_without_http_requests(owned):
    root, profile, seed, _, _, seen, _ = owned
    with socket.socket() as closed:
        closed.bind(("127.0.0.1", 0))  # Held without listening: owned, deterministically refused.
        port = closed.getsockname()[1]
        value = json.loads(profile.read_text())
        value["allowed_ports"].append(port)
        profile.write_text(json.dumps(value))
        target = f"http://127.0.0.1:{port}/app/"
        result = run(owned, tool="service-enumeration", targets=[seed, target])
    assert result["status"] == "completed" and not seen
    assert [row["outcome"] for row in result["observations"]] == ["connected", "refused"]
    assert result["network_evidence"][0]["connections"] == 2
    assert result["network_evidence"][0]["responses"] == 0
    assert not result["findings"]


def test_shared_stop_terminates_live_worker_and_keeps_reservation(owned, monkeypatch):
    root, _, _, _, _, seen, state = owned
    ledger = root / "quota.sqlite3"
    shared_quota.initialize(ledger, max_requests=4, max_active_runs=1,
        expires_at=(utcnow() + timedelta(hours=1)).isoformat(), authorized=True)
    monkeypatch.setenv("HUNTERQA_QUOTA_LEDGER", str(ledger))
    state["delay"] = 3

    def stop_after_request():
        deadline = time.monotonic() + 5
        while not seen and time.monotonic() < deadline:
            time.sleep(0.01)
        shared_quota.stop(ledger, authorized=True)

    stopper = threading.Thread(target=stop_after_request)
    stopper.start()
    result = run(owned)
    stopper.join(6)
    assert result["status"] == "cancelled" and len(seen) == 1
    assert result["network_evidence"][0]["responses"] == 0
    assert shared_quota.status(ledger)["charged_requests"] == 4
    assert shared_quota.status(ledger)["active_runs"] == 0


def test_access_digest_contract_mismatch_is_observed_without_false_confirmation(owned):
    matrix = owned[3]
    value = json.loads(matrix.read_text())
    value["cases"][0]["body_sha256"] = hashlib.sha256(b"A different approved object").hexdigest()
    matrix.write_text(json.dumps(value))
    result = run(owned)
    assert result["access_checks"][0]["cases"][0]["contract_matched"] is False
    assert len(result["findings"]) == 1  # Only the unexpected successful denial case.


def test_distinct_role_cases_on_same_resource_do_not_deduplicate_away(owned):
    value = json.loads(owned[3].read_text())
    for case in value["cases"]:
        case.update(expect="deny", statuses=[403])
    owned[3].write_text(json.dumps(value))
    owned[6]["status"] = 200
    result = run(owned)
    assert len(result["findings"]) == 4
    assert len({f["id"] for f in result["findings"]}) == 4
    sarif = json.loads((owned[0] / "run" / "report.sarif").read_text())
    rows = sarif["runs"][0]["results"]
    assert len({r["partialFingerprints"]["hunterqaCandidate/v1"] for r in rows}) == 4
    assert {r["properties"]["assessmentCase"] for r in rows} == {c["id"] for c in value["cases"]}


@pytest.mark.parametrize("change", ["denial-2xx", "unknown-field", "credential-newline"])
def test_unsafe_or_ambiguous_access_contracts_fail_without_traffic(owned, change):
    root, profile, _, matrix, secrets, seen, _ = owned
    data = json.loads(matrix.read_text())
    if change == "denial-2xx":
        data["cases"][1]["statuses"] = [200]
    elif change == "unknown-field":
        data["cases"][0]["command"] = "unsupported"
    else:
        secrets.write_text(json.dumps({"owner": "Bearer BAD\r\nInjected: x", "other": "Bearer fixture-other"}))
    matrix.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        setup_assessment(profile, "authorization-matrix", root / "config",
            input_file=matrix, secret_file=secrets, authorized=True)
    assert not seen


@pytest.mark.skipif(os.environ.get("HUNTERQA_ENGAGEMENT_BROWSER_CI") != "1", reason="Opt-in owned access dashboard Chromium test")
def test_access_dashboard_real_browser(owned, app):
    from playwright.sync_api import sync_playwright, expect
    from werkzeug.serving import make_server
    run(owned)
    app.config["WORKFLOW_RUN_PATH"] = str(owned[0] / "run")
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as driver:
            browser = driver.chromium.launch(headless=True)
            try:
                page = browser.new_page(viewport={"width": 390, "height": 844})
                page.goto(f"http://127.0.0.1:{server.server_port}/workflows")
                expect(page.get_by_role("heading", name="Role access contracts · assess", exact=True)).to_be_visible()
                assert "SENSITIVE_FIXTURE" not in page.locator("body").inner_text()
                assert page.locator("body").evaluate("el => el.scrollWidth <= window.innerWidth")
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
