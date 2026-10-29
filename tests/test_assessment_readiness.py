import json
import os
import shutil
import socket
import subprocess
import threading
from datetime import timedelta
from http.server import ThreadingHTTPServer
from urllib.parse import urlencode

import pytest

from hunterqa.assessment_benchmark import OwnedFixture, benchmark_assessments
from hunterqa.assessment_readiness import assessment_readiness
from hunterqa.cli import main
from hunterqa.engagement import utcnow
from hunterqa import shared_quota


@pytest.fixture(scope="module")
def owned_evidence(tmp_path_factory):
    root = tmp_path_factory.mktemp("owned-readiness-evidence")
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("HUNTERQA_APPROVED_ROOTS", str(root))
        patch.delenv("HUNTERQA_QUOTA_LEDGER", raising=False)
        benchmark_assessments(root / "lab", authorized=True)
    return root / "lab"


@pytest.fixture
def evidence(owned_evidence, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    monkeypatch.delenv("HUNTERQA_QUOTA_LEDGER", raising=False)
    destination = tmp_path / "lab"
    shutil.copytree(owned_evidence, destination)
    return destination


def no_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Readiness must never launch tools or contact a target")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def test_readiness_is_read_only_and_recomputes_current_owned_evidence(evidence, monkeypatch):
    no_execution(monkeypatch)
    before = {p.relative_to(evidence): p.read_bytes() for p in evidence.rglob("*") if p.is_file()}
    result = assessment_readiness(benchmark_dir=evidence, profile=evidence / "profile.json")
    after = {p.relative_to(evidence): p.read_bytes() for p in evidence.rglob("*") if p.is_file()}
    assert before == after
    assert result["installation_ready"] and result["supported_owned_lab_checks_passed"]
    assert result["owned_lab_evidence"]["network_operations_recorded"] == 18
    assert set(result["owned_lab_evidence"]["tested_adapters"]) == {
        "web-discovery", "web-canary-check", "authorization-matrix", "service-enumeration"}
    assert result["real_world_effectiveness"] == "unverified"
    assert not result["production_multi_user_ready"] and not result["all_seven_areas_complete"]
    assert result["network_requests"] == result["tools_launched"] == 0 and not result["changes_made"]
    assert str(evidence) not in json.dumps(result)


@pytest.mark.parametrize("change", ["request-count", "metrics", "journal", "missing-run", "report-type"])
def test_forged_or_missing_claims_cannot_become_ready(evidence, monkeypatch, change):
    path = evidence / "benchmark.json"
    report = json.loads(path.read_text())
    if change == "request-count":
        report["network_requests"] = 0
    elif change == "metrics":
        report["by_class"]["sql-error"]["recall"] = 0
    elif change == "journal":
        with (evidence / "web-discovery-run" / "discover.network.jsonl").open("ab") as stream:
            stream.write(b" ")
    elif change == "missing-run":
        (evidence / "service-enumeration-run" / "run.sqlite3").unlink()
    else:
        report = []
    path.write_text(json.dumps(report))
    no_execution(monkeypatch)
    result = assessment_readiness(benchmark_dir=evidence)
    assert result["owned_lab_evidence"]["status"] == "invalid"
    assert not result["supported_owned_lab_checks_passed"]


@pytest.mark.parametrize("change", ["source", "labels", "runtime"])
def test_stale_evidence_requires_a_new_owned_run(evidence, monkeypatch, change):
    if change == "runtime":
        import hunterqa.workflow_runner as runner
        monkeypatch.setattr(runner, "_runtime_identity", lambda: "0" * 64)
    else:
        path = evidence / ("benchmark.json" if change == "source" else "ground-truth.json")
        value = json.loads(path.read_text())
        if change == "source":
            value["fixture_source_sha256"] = "0" * 64
        else:
            value["fixture_version"] = "old"
        path.write_text(json.dumps(value))
    result = assessment_readiness(benchmark_dir=evidence)
    assert result["owned_lab_evidence"]["status"] == "stale"
    assert not result["supported_owned_lab_checks_passed"]


def test_no_roots_no_benchmark_and_no_secret_disclosure(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNTERQA_APPROVED_ROOTS", raising=False)
    monkeypatch.delenv("HUNTERQA_QUOTA_LEDGER", raising=False)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "PRIVATE_READINESS_SECRET")
    no_execution(monkeypatch)
    result = assessment_readiness(profile=tmp_path / "missing.json")
    assert not result["installation_ready"] and not result["supported_owned_lab_checks_passed"]
    assert result["owned_lab_evidence"]["status"] == "not_provided"
    assert "PRIVATE_READINESS_SECRET" not in json.dumps(result)
    assert any(c["name"] == "scope_profile" and c["status"] == "fail" for c in result["checks"])


def test_shared_stop_blocks_readiness_and_status_uses_read_only_connection(evidence, tmp_path, monkeypatch):
    ledger = tmp_path / "quota.sqlite3"
    shared_quota.initialize(ledger, max_requests=30, max_active_runs=1,
        expires_at=(utcnow() + timedelta(hours=1)).isoformat(), authorized=True)
    shared_quota.stop(ledger, authorized=True)
    monkeypatch.setenv("HUNTERQA_QUOTA_LEDGER", str(ledger))
    original = shared_quota.sqlite3.connect
    modes = []

    def connect(path, *args, **kwargs):
        modes.append(str(path))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(shared_quota.sqlite3, "connect", connect)
    result = assessment_readiness(benchmark_dir=evidence)
    assert not result["installation_ready"] and not result["supported_owned_lab_checks_passed"]
    assert any("quota.sqlite3?mode=ro" in uri for uri in modes)


def test_cli_strict_readiness_and_marked_feature_list(evidence, capsys):
    with pytest.raises(SystemExit) as error:
        main(["assessment-readiness", "--require-owned-lab"])
    assert error.value.code == 2
    assert not json.loads(capsys.readouterr().out)["supported_owned_lab_checks_passed"]
    main(["assessment-readiness", "--benchmark-dir", str(evidence), "--require-owned-lab"])
    assert json.loads(capsys.readouterr().out)["supported_owned_lab_checks_passed"]
    main(["coverage-audit", "--format", "markdown"])
    checklist = capsys.readouterr().out
    assert checklist.count("- [x]") >= 14 and checklist.count("- [ ]") > 14
    assert "SSRF" in checklist and "Real-world effectiveness remains unverified" in checklist


@pytest.mark.skipif(os.environ.get("HUNTERQA_ENGAGEMENT_BROWSER_CI") != "1", reason="Opt-in owned fixture browser containment check")
def test_owned_fixture_blocks_script_execution_in_real_chromium():
    from playwright.sync_api import sync_playwright
    server = ThreadingHTTPServer(("127.0.0.1", 0), OwnedFixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as driver:
            browser = driver.chromium.launch(headless=True)
            try:
                page = browser.new_page()
                value = "<script>window.HUNTERQA_FIXTURE_EXECUTED=true</script>"
                page.goto(f"http://127.0.0.1:{server.server_port}/app/markup/raw?{urlencode({'q': value})}")
                assert "HUNTERQA_FIXTURE_EXECUTED" in page.content()
                assert page.evaluate("window.HUNTERQA_FIXTURE_EXECUTED") is None
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
