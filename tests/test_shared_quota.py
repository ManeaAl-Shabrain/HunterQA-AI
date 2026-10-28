import json
import os
import sqlite3
import subprocess
import sys
from datetime import timedelta

import pytest

from hunterqa import shared_quota
from hunterqa.engagement import utcnow
from hunterqa.workflow_runner import execution_plan, run_workflow, setup_workflow


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    path = tmp_path / "organization.sqlite3"
    shared_quota.initialize(path, max_requests=10, max_active_runs=3,
        expires_at=(utcnow() + timedelta(hours=1)).isoformat(), authorized=True)
    monkeypatch.setenv("HUNTERQA_QUOTA_LEDGER", str(path))
    return path, shared_quota.configured_review()


def test_cross_process_reservations_are_atomic_and_never_refunded(ledger):
    path, review = ledger
    script = '''import json,sys
from hunterqa.shared_quota import reserve
try:
    reserve(json.loads(sys.argv[1]), sys.argv[2], 3)
except PermissionError:
    sys.exit(3)
'''
    processes = [subprocess.Popen([sys.executable, "-c", script, json.dumps(review), f"run-{i}"],
                 stdout=subprocess.PIPE, stderr=subprocess.PIPE) for i in range(8)]
    codes = []
    for process in processes:
        _, error = process.communicate(timeout=20)
        assert not error
        codes.append(process.returncode)
    assert codes.count(0) == 3 and codes.count(3) == 5
    assert shared_quota.status(path)["charged_requests"] == 9
    for i in range(8):
        shared_quota.release(review, f"run-{i}")
    assert shared_quota.status(path)["active_runs"] == 0
    assert shared_quota.status(path)["charged_requests"] == 9
    with pytest.raises(PermissionError, match="exhausted"):
        shared_quota.reserve(review, "new", 2)


def test_shared_stop_invalidates_active_leases_and_future_admission(ledger):
    path, review = ledger
    shared_quota.reserve(review, "active", 2)
    assert shared_quota.check(review, "active")
    shared_quota.stop(path, authorized=True)
    assert not shared_quota.check(review, "active")
    with pytest.raises(PermissionError):
        shared_quota.reserve(review, "next", 1)
    with pytest.raises(PermissionError):
        shared_quota.configured_review()
    shared_quota.reconcile(path, "active", authorized=True)
    assert shared_quota.status(path)["active_runs"] == 0
    assert shared_quota.status(path)["charged_requests"] == 2


def test_runner_binds_quota_and_releases_offline_slot(ledger, tmp_path, monkeypatch):
    path, _ = ledger
    source = tmp_path / "source"
    source.mkdir()
    (source / "Dockerfile").write_text("FROM example:latest\n")
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"program": "Owned quota fixture", "platform": "private",
        "authorization_reference": "Written owned quota fixture authorization",
        "acknowledged_authorization": True, "allowed_hosts": ["owned.example.test"],
        "allowed_paths": ["/"], "methods": ["HEAD"], "max_requests": 2,
        "interval_seconds": 0.5, "allowed_ports": [443]}))
    config = tmp_path / "config"
    review = setup_workflow(profile, source, ["https://owned.example.test/"], config, authorized=True)
    result = run_workflow(profile, config / "protocol.json", config / "bindings.json", tmp_path / "run",
        execution_approval=review["execution_sha256"], authorized=True)
    assert result["status"] == "completed" and result["shared_quota"]["path"] == str(path)
    assert shared_quota.status(path)["active_runs"] == 0
    monkeypatch.delenv("HUNTERQA_QUOTA_LEDGER")
    changed = execution_plan(profile, config / "protocol.json", config / "bindings.json")
    assert changed["execution_sha256"] != review["execution_sha256"]
    with pytest.raises(PermissionError, match="fingerprint"):
        run_workflow(profile, config / "protocol.json", config / "bindings.json", tmp_path / "denied",
            execution_approval=review["execution_sha256"], authorized=True)
    assert not (tmp_path / "denied").exists()


def test_quota_paths_permissions_and_initialization_are_strict(ledger, tmp_path):
    path, review = ledger
    with pytest.raises(PermissionError):
        shared_quota.stop(path)
    with pytest.raises(PermissionError):
        shared_quota.reconcile(path, "active")
    with pytest.raises(ValueError):
        shared_quota.reserve(review, "too-large", 41)
    with pytest.raises(FileExistsError):
        shared_quota.initialize(path, max_requests=1, max_active_runs=1,
            expires_at=(utcnow() + timedelta(hours=1)).isoformat(), authorized=True)
    with pytest.raises(ValueError, match="24 hours"):
        shared_quota.initialize(tmp_path / "expired", max_requests=1, max_active_runs=1,
            expires_at=(utcnow() - timedelta(seconds=1)).isoformat(), authorized=True)
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600


def test_configuration_changes_invalidate_active_and_new_admission(ledger):
    path, review = ledger
    shared_quota.reserve(review, "fixture-run", 2)
    assert shared_quota.status(path)["active_reservations"][0]["run_id"] == "fixture-run"
    with sqlite3.connect(path) as db:
        db.execute("UPDATE configuration SET max_requests=11")
    assert not shared_quota.check(review, "fixture-run")
    with pytest.raises(PermissionError, match="changed"):
        shared_quota.reserve(review, "next-run", 1)
