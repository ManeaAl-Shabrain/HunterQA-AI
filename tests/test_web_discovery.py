"""Owned loopback integration tests; no external assessment traffic."""
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hunterqa.bounty import BountyPolicy
from hunterqa.web_discovery import PageInventory, admit_url, discover, setup_discovery
from hunterqa.workflow_network import NetworkJournal, inspect_network
from hunterqa.workflow_results import summarize_run
from hunterqa.workflow_runner import execution_plan, run_workflow


@pytest.fixture
def lab(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    seen = []
    state = {"status": 200, "delay": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, time.monotonic()))
            time.sleep(state["delay"])
            self.send_response(state["status"])
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b'''<a href="/app/child">child</a>
                <a href="/app/admin">excluded</a><a href="/app?token=PRIVATE">query</a>
                <a href="https://outside.example.test/app">outside</a>
                <a href="/app/grandchild">depth</a><img src="/app/image">
                <script>fetch('/app/script')</script>
                <form method="post" action="/app/login">
                <input type="password" name="PRIVATE_NAME" value="PRIVATE_VALUE">
                <input type="hidden" name="token" value="PRIVATE_TOKEN"></form>'''
                if self.path == "/app" else b'<a href="/app/deeper">deeper</a>')

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    profile = tmp_path / "profile.json"
    data = {"program": "Owned HTML discovery lab", "platform": "local-lab",
        "authorization_reference": "Written owned loopback fixture authorization",
        "acknowledged_authorization": True, "allowed_hosts": ["127.0.0.1"],
        "allowed_ports": [server.server_port], "allowed_paths": ["/app"],
        "excluded_paths": ["/app/admin"], "methods": ["GET"], "max_requests": 5,
        "interval_seconds": 0.5, "lab_mode": True, "allow_private_network": True, "allow_http": True}
    profile.write_text(json.dumps(data))
    seed = f"http://127.0.0.1:{server.server_port}/app"
    try:
        yield tmp_path, profile, seed, seen, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def launch(lab, *, pages=5, depth=1):
    root, profile, seed, _, _ = lab
    config = root / "config"
    review = setup_discovery(profile, [seed], config, max_pages=pages, max_depth=depth, authorized=True)
    return run_workflow(profile, config / "protocol.json", config / "bindings.json", root / "run",
        execution_approval=review["execution_sha256"],
        protocol_approval=review["preflight"]["protocol_sha256"],
        approved_steps=["discover"], authorized=True)


def test_real_workers_discover_links_and_forms_with_scope_and_privacy(lab):
    result = launch(lab)
    root, _, _, seen, _ = lab
    assert result["status"] == "completed"
    assert [path for path, _ in seen] == ["/app", "/app/child", "/app/grandchild"]
    assert all(b[1] - a[1] >= 0.49 for a, b in zip(seen, seen[1:]))
    assert result["charged_requests"] == 5
    discovery = result["web_discovery"][0]
    assert discovery["summary"]["visited"] == 3
    assert discovery["summary"]["limits_reached"] is True
    assert any(not row["visited"] and row["url"].endswith("/deeper") for row in discovery["endpoints"])
    form = discovery["forms"][0]
    assert form["method"] == "POST" and form["submission_enabled"] is False
    assert form["input_types"] == ["password", "hidden"]
    assert result["network_evidence"][0]["intents"] == 3
    assert result["network_evidence"][0]["responses"] == 3
    assert all(row["verification_status"] == "unverified" for row in result["findings"])
    report = (root / "run" / "report.html").read_text()
    assert "PRIVATE" not in report and "PRIVATE" not in json.dumps(result)
    assert summarize_run(root / "run")["web_discovery"] == result["web_discovery"]


@pytest.mark.parametrize("status", [302, 401, 403, 429, 503])
def test_denial_redirect_and_server_failure_stop_without_followups(lab, status):
    lab[4]["status"] = status
    result = launch(lab)
    assert result["status"] == "cancelled"
    assert len(lab[3]) == 1 and result["charged_requests"] == 5
    assert result["web_discovery"][0]["summary"]["safety_stop"] is True


@pytest.mark.parametrize("pages,depth", [(1, 3), (5, 0)])
def test_request_and_depth_limits_bound_real_traffic(lab, pages, depth):
    result = launch(lab, pages=pages, depth=depth)
    assert result["status"] == "completed" and len(lab[3]) == 1
    assert result["web_discovery"][0]["summary"]["limits_reached"] is True


def test_checkpoint_and_depth_binding_fail_before_traffic(lab):
    root, profile, seed, seen, _ = lab
    config = root / "config"
    review = setup_discovery(profile, [seed], config, authorized=True)
    with pytest.raises(PermissionError, match="checkpoint"):
        run_workflow(profile, config / "protocol.json", config / "bindings.json", root / "denied",
                     execution_approval=review["execution_sha256"], authorized=True)
    assert not seen and not (root / "denied").exists()
    binding = json.loads((config / "bindings.json").read_text())
    binding["steps"]["discover"]["max_depth"] = 4
    (config / "bindings.json").write_text(json.dumps(binding))
    with pytest.raises(ValueError, match="max_depth"):
        execution_plan(profile, config / "protocol.json", config / "bindings.json")
    assert not seen


@pytest.mark.parametrize("suffix", ["/admin", "?token=secret", "/../outside", "%2fadmin"])
def test_url_admission_rejects_exclusions_and_ambiguous_paths(lab, suffix):
    _, profile, seed, _, _ = lab
    policy = BountyPolicy.from_dict(json.loads(profile.read_text()))
    from hunterqa.web_discovery import origin
    assert admit_url(policy, seed + suffix, seed, {origin(seed)}) is None


def test_journal_independently_rejects_out_of_scope_dynamic_target(lab):
    root, profile, seed, _, _ = lab
    policy = BountyPolicy.from_dict(json.loads(profile.read_text()))
    path = root / "network.jsonl"
    journal = NetworkJournal(path)
    journal.append("intent", seed, "GET", target_url=seed)
    journal.append("response", seed, "GET", status=200)
    journal.append("intent", seed + "/admin", "GET", target_url=seed + "/admin")
    journal.close()
    with pytest.raises(ValueError):
        inspect_network(path, [seed], discovery_policy=policy, request_budget=5)


def test_journal_rejects_outcome_method_mismatch(lab):
    root, profile, seed, _, _ = lab
    policy = BountyPolicy.from_dict(json.loads(profile.read_text()))
    path = root / "network.jsonl"
    journal = NetworkJournal(path)
    journal.append("intent", seed, "GET", target_url=seed)
    journal.append("response", seed, "HEAD", status=200)
    journal.close()
    with pytest.raises(ValueError, match="matching intent"):
        inspect_network(path, [seed], discovery_policy=policy, request_budget=5)


def test_cli_planning_never_contacts_target(lab, capsys):
    from hunterqa.cli import main
    root, profile, seed, seen, _ = lab
    main(["discovery-setup", "--profile", str(profile), "--seed", seed,
          "--out-dir", str(root / "cli-config"), "--authorized"])
    plan = json.loads(capsys.readouterr().out)
    assert plan["preflight"]["dynamic_scope_steps"] == ["discover"]
    assert plan["preflight"]["network_requests"] == 0 and not seen


def test_parser_caps_and_omits_field_secrets():
    parser = PageInventory()
    parser.feed('<a href="/app/x">x</a>' * 201 +
                '<form><input type="password" name="SECRET" value="SECRET"></form>' * 101)
    assert len(parser.links) == 200 and len(parser.forms) == 100 and parser.truncated
    assert "SECRET" not in json.dumps(parser.forms)


def test_worker_timeout_preserves_reserved_budget_and_intent(lab):
    root, profile, seed, seen, state = lab
    state["delay"] = 3
    config = root / "config"
    setup_discovery(profile, [seed], config, max_pages=1, authorized=True)
    protocol = json.loads((config / "protocol.json").read_text())
    protocol["steps"][0]["timeout_seconds"] = 1
    (config / "protocol.json").write_text(json.dumps(protocol))
    review = execution_plan(profile, config / "protocol.json", config / "bindings.json")
    result = run_workflow(profile, config / "protocol.json", config / "bindings.json", root / "run",
        execution_approval=review["execution_sha256"],
        protocol_approval=review["preflight"]["protocol_sha256"], approved_steps=["discover"], authorized=True)
    assert result["status"] == "cancelled" and result["charged_requests"] == 1
    assert len(seen) == 1
    assert result["network_evidence"][0]["intents"] == 1
    assert result["network_evidence"][0]["responses"] == 0


@pytest.mark.parametrize("kind,expected", [
    ("secure-html", set()),
    ("missing-html", {"header.hsts.absent", "header.nosniff.absent", "header.csp.absent"}),
    ("json", set()),
    ("cookie", {"cookie.secure.absent", "cookie.httponly.absent"}),
])
def test_detection_positive_and_negative_controls(tmp_path, monkeypatch, kind, expected):
    """Original synthetic rule-cue controls; not a real-world accuracy estimate."""
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    policy = {"program": "Synthetic discovery controls", "platform": "private",
        "authorization_reference": "Original offline synthetic fixture authorization",
        "acknowledged_authorization": True, "allowed_hosts": ["owned.example.test"],
        "allowed_paths": ["/app"], "methods": ["GET"], "max_requests": 1,
        "interval_seconds": 0.5, "allowed_ports": [443]}
    seed = "https://owned.example.test/app"
    secure = [("Strict-Transport-Security", "max-age=31536000"),
              ("X-Content-Type-Options", "nosniff"), ("Content-Security-Policy", "default-src 'self'")]
    headers = [] if kind == "missing-html" else secure[:]
    headers.append(("Content-Type", "application/json" if kind == "json" else "text/html"))
    if kind == "cookie":
        headers.append(("Set-Cookie", "sid=PRIVATE_VALUE"))
    calls = []

    def transport(policy, url, method):
        calls.append((url, method))
        return {"status": 200, "headers": headers, "body": b"{}" if kind == "json" else b"<p>Owned fixture</p>"}

    result = discover({"policy": policy, "step": {"targets": [seed], "requests": 1},
        "binding": {"max_depth": 0}, "interval_seconds": 0.5,
        "network_log": str(tmp_path / "network.jsonl")}, transport=transport)
    assert len(calls) == 1
    assert {row["rule_id"] for row in result["findings"]} == expected
    assert "PRIVATE_VALUE" not in json.dumps(result)


@pytest.mark.skipif(os.environ.get("HUNTERQA_ENGAGEMENT_BROWSER_CI") != "1", reason="Opt-in owned discovery dashboard Chromium test")
def test_discovery_dashboard_real_browser(lab, app):
    from playwright.sync_api import sync_playwright, expect
    from werkzeug.serving import make_server
    launch(lab)
    app.config["WORKFLOW_RUN_PATH"] = str(lab[0] / "run")
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as driver:
            browser = driver.chromium.launch(headless=True)
            try:
                page = browser.new_page(viewport={"width": 390, "height": 844})
                page.goto(f"http://127.0.0.1:{server.server_port}/workflows")
                expect(page.get_by_role("heading", name="HTML discovery · discover", exact=True)).to_be_visible()
                expect(page.get_by_text("POST", exact=True)).to_be_visible()
                assert "PRIVATE_VALUE" not in page.locator("body").inner_text()
                assert page.locator("body").evaluate("el => el.scrollWidth <= window.innerWidth")
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
