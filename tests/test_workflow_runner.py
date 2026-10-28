import json
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hunterqa.cli import main
from hunterqa.workflow_benchmark import benchmark_adapters
from hunterqa.workflow_results import compare_runs, export_report, review_finding, summarize_run
from hunterqa.workflow_runner import execution_plan, run_workflow, setup_workflow, _environment
from hunterqa.workflow_store import Store


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    source = tmp_path / "source"
    source.mkdir()
    (source / "Dockerfile").write_text("FROM example:latest\nUSER root\n")
    (source / "__init__.py").write_text("raise RuntimeError('TARGET CODE MUST NEVER EXECUTE')")
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"program": "Owned workflow fixture", "platform": "private",
        "authorization_reference": "Written workflow fixture authorization", "acknowledged_authorization": True,
        "allowed_hosts": ["owned.example.test"], "allowed_paths": ["/app"], "excluded_paths": [],
        "methods": ["HEAD"], "max_requests": 4, "interval_seconds": 0.5, "allowed_ports": [443]}))
    config = tmp_path / "config"
    review = setup_workflow(profile, source, ["https://owned.example.test/app"], config, authorized=True)
    return tmp_path, profile, source, config, review


def launch(prepared, name="run", **kwargs):
    root, profile, _, config, review = prepared
    return run_workflow(profile, config / "protocol.json", config / "bindings.json", root / name,
                        execution_approval=review["execution_sha256"], authorized=True, **kwargs)


def test_real_fixed_workers_report_and_never_execute_target(prepared):
    result = launch(prepared)
    run = prepared[0] / "run"
    assert result["status"] == "completed"
    assert len(result["findings"]) == 2
    assert result["charged_requests"] == 0
    assert all(row["verification_status"] == "unverified" for row in result["findings"])
    assert all(row["state"] == "succeeded" for row in result["steps"])
    assert (run / "report.html").exists() and (run / "report.sarif").exists()
    assert "TARGET CODE" not in (run / "report.html").read_text()
    assert result["next_actions"][0]["evidence"][0]["result_sha256"]
    assert summarize_run(run)["audit_head_sha256"] == result["audit_head_sha256"]
    with pytest.raises(FileExistsError):
        launch(prepared)
    if os.name == "posix":
        assert (run.stat().st_mode & 0o777) == 0o700
        assert ((run / "run.sqlite3").stat().st_mode & 0o777) == 0o600


def test_execution_review_binds_input_and_rejects_unknown_tools(prepared):
    root, profile, _, config, review = prepared
    with pytest.raises(PermissionError):
        run_workflow(profile, config / "protocol.json", config / "bindings.json", root / "run",
                     execution_approval=review["execution_sha256"])
    with pytest.raises(PermissionError):
        run_workflow(profile, config / "protocol.json", config / "bindings.json", root / "run",
                     execution_approval="0" * 64, authorized=True)
    data = json.loads((config / "bindings.json").read_text())
    data["steps"]["assets"]["command"] = "whoami"
    (config / "bindings.json").write_text(json.dumps(data))
    with pytest.raises(ValueError, match="binding"):
        execution_plan(profile, config / "protocol.json", config / "bindings.json")
    assert not (root / "run").exists()


def test_worker_environment_omits_secrets(monkeypatch):
    monkeypatch.setenv("HUNTERQA_TEST_PASSWORD", "secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.setenv("HTTPS_PROXY", "http://untrusted.test")
    assert not {"HUNTERQA_TEST_PASSWORD", "AWS_SECRET_ACCESS_KEY", "HTTPS_PROXY"} & set(_environment())


def test_runtime_changes_invalidate_execution_review(prepared, monkeypatch):
    import hunterqa.workflow_runner as runner
    monkeypatch.setattr(runner, "_runtime_identity", lambda: "f" * 64)
    with pytest.raises(PermissionError, match="fingerprint"):
        launch(prepared)
    assert not (prepared[0] / "run").exists()


def test_distribution_upgrade_invalidates_existing_execution_review(prepared, monkeypatch):
    import hunterqa.workflow_runner as runner
    monkeypatch.setattr(runner, "distribution_version", lambda name: "1.3.1")
    with pytest.raises(PermissionError, match="fingerprint"):
        launch(prepared)
    assert not (prepared[0] / "run").exists()


def test_multiple_source_projects_keep_distinct_candidates(prepared):
    root, profile, source, config, _ = prepared
    other = root / "other-source"
    other.mkdir()
    (other / "Dockerfile").write_bytes((source / "Dockerfile").read_bytes())
    value = json.loads((config / "protocol.json").read_text())
    value["steps"].append(dict(value["steps"][1], id="other-project"))
    value["steps"][2]["depends_on"].append("other-project")
    (config / "protocol.json").write_text(json.dumps(value))
    binding = json.loads((config / "bindings.json").read_text())
    binding["steps"]["other-project"] = {"project": str(other)}
    (config / "bindings.json").write_text(json.dumps(binding))
    review = execution_plan(profile, config / "protocol.json", config / "bindings.json")
    result = launch((*prepared[:4], review))
    assert len(result["findings"]) == 4
    assert len({row["project_ref_hash"] for row in result["findings"]}) == 2
    sarif = json.loads((root / "run" / "report.sarif").read_text())
    assert all("locations" not in row for row in sarif["runs"][0]["results"])
    assert len({row["partialFingerprints"]["hunterqaCandidate/v1"] for row in sarif["runs"][0]["results"]}) == 4


def test_review_retest_export_and_tamper_detection(prepared):
    first = launch(prepared)
    root, _, source, _, _ = prepared
    run = root / "run"
    proof = root / "proof.txt"
    proof.write_text("Analyst independently checked the disposable local fixture")
    finding = first["findings"][0]["id"]
    with pytest.raises(PermissionError):
        review_finding(run, finding, "confirmed", "Analyst", "Reviewed", proof)
    review_finding(run, finding, "confirmed", "Analyst", "Reviewed local fixture", proof, authorized=True)
    assert summarize_run(run)["review_counts"]["confirmed"] == 1
    export_report(run, root / "reviewed.json", "json")
    export_report(run, root / "reviewed.sarif", "sarif")
    # SARIF deliberately retains the conservative unverified export contract.
    assert json.loads((root / "reviewed.sarif").read_text())["runs"][0]["results"][0]["properties"]["verificationStatus"] == "unverified"
    (source / "Dockerfile").write_text("FROM example:1\nUSER 10001\n")
    launch(prepared, name="retest")
    comparison = compare_runs(run, root / "retest")
    assert len(comparison["not_observed"]) == 2 and not comparison["unknown"]
    assert "proof of repair" in comparison["limitations"]
    store = Store(run)
    with store.db:
        store.db.execute("UPDATE reviews SET value=?", ('{"decision":"false-positive"}',))
    store.close()
    with pytest.raises(ValueError, match="review"):
        summarize_run(run)


def test_result_and_audit_edits_fail_integrity(prepared):
    launch(prepared)
    run = prepared[0] / "run"
    store = Store(run)
    with store.db:
        store.db.execute("UPDATE steps SET result='{}' WHERE id='identify'")
    store.close()
    with pytest.raises(ValueError, match="result"):
        summarize_run(run)


def test_crash_reconciliation_does_not_replay_and_live_lock_blocks_it(prepared):
    from hunterqa.workflow_runner import abandon_run
    from hunterqa.workflow_store import run_lock
    launch(prepared)
    run = prepared[0] / "run"
    store = Store(run)
    store.state("identify", "running")
    store.audited_meta("status", "interrupted", "run-interrupted")
    charged = store.meta("charged_requests")
    store.close()
    with run_lock(run):
        with pytest.raises(ValueError, match="lock"):
            abandon_run(run, authorized=True)
    result = abandon_run(run, authorized=True)
    assert result["execution_resumed"] is False
    report = summarize_run(run)
    assert report["status"] == "abandoned" and report["charged_requests"] == charged
    assert next(row for row in report["steps"] if row["id"] == "identify")["state"] == "cancelled"


@pytest.mark.parametrize("condition", ["dead-parent", "expired", "stop-file"])
def test_worker_independent_watchdog_stops_before_execution(prepared, condition):
    import sys
    from datetime import timedelta
    from hunterqa.engagement import utcnow
    from hunterqa.workflow_store import private_write
    from hunterqa import workflow_worker
    root, _, _, config, _ = prepared
    step = json.loads((config / "protocol.json").read_text())["steps"][0]
    stop = root / "independent-stop"
    if condition == "stop-file":
        stop.touch()
    value = {"step": step, "binding": {}, "parent_pid": 0 if condition == "dead-parent" else os.getpid(),
             "watchdog_seconds": 60, "stop_path": str(stop),
             "expires_at": (utcnow() + timedelta(seconds=-1 if condition == "expired" else 60)).isoformat()}
    request, output = root / "worker.request.json", root / "worker.output.json"
    private_write(request, value)
    process = subprocess.run([sys.executable, "-I", "-B", workflow_worker.__file__, str(request), str(output)],
                             env=_environment(), capture_output=True, timeout=10)
    assert process.returncode == 124 and not output.exists()


def test_real_worker_timeout_blocks_dependencies(prepared, monkeypatch):
    import hunterqa.workflow_runner as runner
    original = subprocess.Popen
    children = []

    def sleeping_worker(*args, **kwargs):
        child = original([runner.sys.executable, "-I", "-c", "import time; time.sleep(20)"], **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(runner.subprocess, "Popen", sleeping_worker)
    config = prepared[3]
    data = json.loads((config / "protocol.json").read_text())
    data["steps"][0]["timeout_seconds"] = 1
    (config / "protocol.json").write_text(json.dumps(data))
    prepared = (*prepared[:4], execution_plan(prepared[1], config / "protocol.json", config / "bindings.json"))
    start = time.monotonic()
    result = launch(prepared)
    assert result["status"] == "failed" and time.monotonic() - start < 10
    assert all(child.poll() is not None for child in children)
    states = {step["id"]: step["state"] for step in result["steps"]}
    assert states["assets"] == "failed" and states["identify"] == "blocked"


def test_real_worker_emergency_stop_and_live_read_snapshot(prepared, monkeypatch):
    import hunterqa.workflow_runner as runner
    original = subprocess.Popen
    started = threading.Event()
    children = []

    def sleeping_worker(*args, **kwargs):
        child = original([runner.sys.executable, "-I", "-c", "import time; time.sleep(20)"], **kwargs)
        children.append(child)
        started.set()
        return child

    monkeypatch.setattr(runner.subprocess, "Popen", sleeping_worker)
    result, errors = [], []

    def execute():
        try:
            result.append(launch(prepared))
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=execute)
    thread.start()
    assert started.wait(10)
    run = prepared[0] / "run"
    try:
        assert summarize_run(run)["status"] == "running"
        runner.stop_run(run)
    finally:
        thread.join(10)
    assert not thread.is_alive() and not errors
    assert result[0]["status"] == "cancelled"
    assert all(child.poll() is not None for child in children)


def test_fixture_benchmark_and_cli(prepared, capsys):
    root = prepared[0]
    result = benchmark_adapters(root)
    assert result["all_cases_matched"] and result["precision"] == result["recall"] == 1
    main(["workflow-benchmark", "--out", str(root / "benchmark.json")])
    assert json.loads((root / "benchmark.json").read_text())["network_requests"] == 0
    launch(prepared)
    main(["workflow-status", "--run", str(root / "run")])
    assert '"completed"' in capsys.readouterr().out


def test_service_and_external_evidence_bindings_are_snapshotted(prepared):
    root, profile, _, config, _ = prepared
    services = root / "services.json"
    services.write_text(json.dumps({"services": [{"url": "https://owned.example.test/app", "service": "https"}]}))
    external = root / "nuclei.jsonl"
    external.write_text(json.dumps({"template-id": "fixture", "type": "http",
        "matched-at": "https://owned.example.test/app?token=PRIVATE_TOKEN",
        "info": {"severity": "high", "name": "PRIVATE_ATTACK_TEXT"}}))
    data = json.loads((config / "protocol.json").read_text())
    service_step = dict(data["steps"][0], id="services", tool="service-evidence", depends_on=["assets"])
    import_step = dict(data["steps"][1], id="imported", tool="external-findings", depends_on=["services"])
    data["steps"][1]["depends_on"] = ["services"]
    data["steps"][2]["depends_on"] = ["identify", "imported"]
    data["steps"].extend([service_step, import_step])
    data["limits"]["timeout_seconds"] = 300
    (config / "protocol.json").write_text(json.dumps(data))
    bindings = json.loads((config / "bindings.json").read_text())
    bindings["steps"].update(services={"file": str(services)}, imported={"file": str(external), "tool": "nuclei"})
    (config / "bindings.json").write_text(json.dumps(bindings))
    review = execution_plan(profile, config / "protocol.json", config / "bindings.json")
    updated = (*prepared[:4], review)
    result = launch(updated)
    assert len(result["findings"]) == 3
    assert "PRIVATE_TOKEN" not in json.dumps(result) and "PRIVATE_ATTACK_TEXT" not in json.dumps(result)
    assert (root / "run" / "imported.input").read_bytes() == external.read_bytes()
    external.write_text(external.read_text() + "\n")
    with pytest.raises(PermissionError):
        launch(updated, name="changed-input-run")


def test_profile_revocation_cancels_an_inflight_worker(prepared, monkeypatch):
    import hunterqa.workflow_runner as runner
    original = subprocess.Popen
    changed = False
    children = []

    def revoke_during_work(*args, **kwargs):
        nonlocal changed
        child = original([runner.sys.executable, "-I", "-c", "import time; time.sleep(20)"], **kwargs)
        children.append(child)
        if not changed:
            prepared[1].write_text(prepared[1].read_text() + "\n")
            changed = True
        return child

    monkeypatch.setattr(runner.subprocess, "Popen", revoke_during_work)
    result = launch(prepared)
    assert result["status"] == "cancelled"
    assert all(child.poll() is not None for child in children)
    assert any(row["error_type"] == "authorization-changed" for row in result["steps"])


@pytest.mark.skipif(os.environ.get("HUNTERQA_ENGAGEMENT_BROWSER_CI") != "1", reason="Opt-in local workflow dashboard Chromium test")
def test_workflow_dashboard_real_browser(prepared, app):
    from playwright.sync_api import sync_playwright, expect
    from werkzeug.serving import make_server
    launch(prepared)
    app.config["WORKFLOW_RUN_PATH"] = str(prepared[0] / "run")
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as driver:
            browser = driver.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 390, "height": 844})
            page.goto(f"http://127.0.0.1:{server.server_port}/workflows")
            expect(page.get_by_role("heading", name="Workflow run", exact=True)).to_be_visible()
            expect(page.get_by_role("heading", name="Execution steps", exact=True)).to_be_visible()
            assert page.locator("body").evaluate("el => el.scrollWidth <= window.innerWidth")
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_dashboard_read_only_and_configuration(prepared, app):
    launch(prepared)
    app.config["WORKFLOW_RUN_PATH"] = str(prepared[0] / "run")
    response = app.test_client().get("/workflows?run=/untrusted/path")
    assert response.status_code == 200
    assert b"Workflow run" in response.data and b"docker.root-user" in response.data
    assert app.test_client().post("/workflows").status_code == 405
    store = Store(prepared[0] / "run")
    with store.db:
        store.db.execute("UPDATE events SET fingerprint='tampered' WHERE seq=1")
    store.close()
    response = app.test_client().get("/workflows")
    assert b"failed integrity checks" in response.data


@pytest.mark.parametrize("http_status", [200, 429])
def test_loopback_http_observations_require_checkpoint_and_share_budget(prepared, http_status):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            seen.append(time.monotonic())
            self.send_response(http_status)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    root, profile, source, _, _ = prepared
    value = json.loads(profile.read_text())
    value.update(allowed_hosts=["127.0.0.1"], allowed_ports=[server.server_port],
                 lab_mode=True, allow_private_network=True, allow_http=True)
    profile.write_text(json.dumps(value))
    config = root / "network-config"
    targets = [f"http://127.0.0.1:{server.server_port}/app/{i}" for i in range(2)]
    review = setup_workflow(profile, source, targets, config, observe=True, authorized=True)
    try:
        with pytest.raises(PermissionError, match="checkpoint"):
            run_workflow(profile, config / "protocol.json", config / "bindings.json", root / "denied",
                         execution_approval=review["execution_sha256"], authorized=True)
        assert not seen
        result = run_workflow(profile, config / "protocol.json", config / "bindings.json", root / "network-run",
            execution_approval=review["execution_sha256"],
            protocol_approval=review["preflight"]["protocol_sha256"], approved_steps=["validate"], authorized=True)
        assert result["status"] == ("completed" if http_status == 200 else "cancelled")
        expected = 2 if http_status == 200 else 1
        assert result["charged_requests"] == 2 and len(result["observations"]) == expected
        assert len(seen) == expected
        if http_status == 200:
            assert seen[1] - seen[0] >= 0.49
        assert result["network_evidence"][0]["intents"] == expected
        assert result["network_evidence"][0]["responses"] == expected
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_real_concurrent_workers_respect_execution_ceiling(prepared, monkeypatch):
    import hunterqa.workflow_runner as runner
    original = subprocess.Popen
    children, observed = [], []
    script = ('import json,sys,time; r=json.load(open(sys.argv[1])); time.sleep(0.3); '
              'json.dump({"adapter":r["step"]["tool"],"findings":[],"requests":0},open(sys.argv[2],"w"))')

    def controlled_worker(args, **kwargs):
        observed.append(1 + sum(child.poll() is None for child in children))
        child = original([runner.sys.executable, "-I", "-c", script, args[-2], args[-1]], **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(runner.subprocess, "Popen", controlled_worker)
    config = prepared[3]
    value = json.loads((config / "protocol.json").read_text())
    value["steps"] = [dict(value["steps"][0], id=f"branch-{i}", timeout_seconds=3) for i in range(5)]
    value["limits"].update(concurrency=2, timeout_seconds=30)
    (config / "protocol.json").write_text(json.dumps(value))
    (config / "bindings.json").write_text(json.dumps({"schema_version": 1,
        "steps": {f"branch-{i}": {} for i in range(5)}}))
    review = execution_plan(prepared[1], config / "protocol.json", config / "bindings.json")
    result = launch((*prepared[:4], review))
    assert result["status"] == "completed" and len(children) == 5
    assert max(observed) == 2 and all(child.poll() is not None for child in children)


def test_network_journal_prefix_and_edits(prepared):
    from hunterqa.workflow_network import NetworkJournal, inspect_network
    target = "https://owned.example.test/app"
    path = prepared[0] / "network.jsonl"
    journal = NetworkJournal(path)
    journal.append("intent", target, "HEAD")
    journal.append("response", target, "HEAD", status=200)
    journal.close()
    assert inspect_network(path, [target])["responses"] == 1
    with path.open("ab") as stream:
        stream.write(b'{"partial":')
    assert inspect_network(path, [target])["incomplete_tail"] is True
    rows = path.read_bytes().splitlines(keepends=True)
    row = json.loads(rows[0])
    row["value"]["target_sha256"] = "0" * 64
    path.write_bytes((json.dumps(row) + "\n").encode() + b"".join(rows[1:]))
    with pytest.raises(ValueError, match="hash chain"):
        inspect_network(path, [target])
