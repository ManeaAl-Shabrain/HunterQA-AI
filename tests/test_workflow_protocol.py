import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from hunterqa.cli import main
from hunterqa.workflow_protocol import CATALOG, compile_protocol

NOW = datetime(2026, 10, 28, 12, tzinfo=timezone.utc)
TARGET = "https://owned.example.test/app"


@pytest.fixture
def protocol(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({
        "program": "Protocol fixture", "platform": "private",
        "authorization_reference": "Written fixture authorization",
        "acknowledged_authorization": True,
        "allowed_hosts": ["owned.example.test"], "excluded_hosts": [],
        "allowed_paths": ["/app"], "excluded_paths": [],
        "methods": ["HEAD", "GET"], "allowed_ports": [443],
        "max_requests": 8, "interval_seconds": 1,
    }))
    names = ["declared-assets", "service-evidence", "source-review",
             "approved-observation", "evidence-index", "report-draft"]
    steps = [{"id": f"step-{index}", "tool": name,
              "depends_on": [f"step-{index-1}"] if index else [],
              "targets": [TARGET], "requests": 1 if CATALOG[name][1] else 0,
              "timeout_seconds": 10, "approval_required": CATALOG[name][1]}
             for index, name in enumerate(names)]
    value = {"schema_version": 1,
             "policy_sha256": hashlib.sha256(profile.read_bytes()).hexdigest(),
             "authorization_reference": "Written fixture authorization",
             "starts_at": (NOW - timedelta(minutes=1)).isoformat(),
             "expires_at": (NOW + timedelta(hours=1)).isoformat(),
             "targets": [TARGET], "stop_file": "emergency-stop",
             "limits": {"max_requests": 4, "interval_seconds": 1,
                        "concurrency": 2, "timeout_seconds": 120}, "steps": steps}
    path = tmp_path / "protocol.json"
    return profile, path, value


def check(fixture, **kwargs):
    profile, path, value = fixture
    path.write_text(json.dumps(value))
    return compile_protocol(profile, path, now=NOW, **kwargs)


def test_six_stage_preflight_has_no_execution_or_network(protocol, monkeypatch):
    import socket
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("Offline preflight attempted external work")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    result = check(protocol)
    assert result["planning_batches"] == [[f"step-{i}"] for i in range(6)]
    assert result["pending_checkpoints"] == ["step-3"]
    assert result["network_requests"] == result["tools_launched"] == 0
    assert result["execution_enabled"] is False
    assert result["reserved_requests"] == 1
    assert TARGET not in json.dumps(result)


@pytest.mark.parametrize("target", ["https://other.example.test/app", TARGET + "?token=secret",
    "https://owned.example.test:444/app", "https://owned.example.test/outside",
    "https://user:pass@owned.example.test/app", TARGET + "/%2e%2e/secret"])
def test_scope_is_exact_even_with_empty_exclusions(protocol, target):
    protocol[2]["targets"] = [target]
    with pytest.raises(ValueError):
        check(protocol)


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(extra=True),
    lambda p: p.update(schema_version=True),
    lambda p: p.update(stop_file="../stop"),
    lambda p: p.update(policy_sha256="0" * 64),
    lambda p: p.update(authorization_reference="Different authority"),
    lambda p: p.update(expires_at=NOW.isoformat()),
    lambda p: p.update(expires_at=(NOW + timedelta(hours=25)).isoformat()),
    lambda p: p.update(starts_at="2026-10-28T12:00:00"),
    lambda p: p["limits"].update(concurrency=9),
    lambda p: p["limits"].update(concurrency=True),
    lambda p: p["limits"].update(interval_seconds=float("nan")),
    lambda p: p["limits"].update(interval_seconds=10 ** 400),
    lambda p: p["limits"].update(interval_seconds=0.5),
    lambda p: p["limits"].update(max_requests=9),
    lambda p: p["limits"].update(timeout_seconds=20),
    lambda p: p["steps"][3].update(approval_required=False),
    lambda p: p["steps"][3].update(requests=0),
    lambda p: p["steps"][0].update(requests=1),
    lambda p: p["steps"][0].update(tool="shell"),
    lambda p: p["steps"][0].update(command="whoami"),
    lambda p: p["steps"][0].update(id="step-1"),
    lambda p: p["steps"][1].update(depends_on=["missing"]),
    lambda p: p["steps"][1].update(depends_on=["step-1"]),
    lambda p: p["steps"][1].update(depends_on=["step-0", "step-0"]),
    lambda p: p["steps"][0].update(depends_on=["step-5"]),
    lambda p: p["steps"][0].update(targets=["https://owned.example.test/app/undeclared"]),
])
def test_invalid_protocols_fail_closed(protocol, mutation):
    mutation(protocol[2])
    with pytest.raises(ValueError):
        check(protocol)


def test_profile_bytes_and_protocol_changes_invalidate_review(protocol):
    fingerprint = check(protocol)["protocol_sha256"]
    with pytest.raises(PermissionError):
        check(protocol, approved_steps=["step-3"], approved_fingerprint=fingerprint)
    result = check(protocol, approved_steps=["step-3"], approved_fingerprint=fingerprint, authorized=True)
    assert result["pending_checkpoints"] == []
    assert result["execution_enabled"] is False
    protocol[2]["limits"]["concurrency"] = 1
    with pytest.raises(PermissionError):
        check(protocol, approved_steps=["step-3"], approved_fingerprint=fingerprint, authorized=True)
    protocol[0].write_text(protocol[0].read_text() + "\n")
    with pytest.raises(ValueError, match="profile bytes"):
        check(protocol)


def test_checkpoint_names_and_empty_approval(protocol):
    with pytest.raises(ValueError, match="checkpoint"):
        check(protocol, approved_steps=["step-0"])
    with pytest.raises(ValueError, match="requires at least"):
        check(protocol, approved_fingerprint="0" * 64)


def test_existing_profile_exclusions_cannot_be_overridden(protocol):
    profile = protocol[0]
    scope = json.loads(profile.read_text())
    scope["excluded_paths"] = ["/app"]
    profile.write_text(json.dumps(scope))
    protocol[2]["policy_sha256"] = hashlib.sha256(profile.read_bytes()).hexdigest()
    with pytest.raises(ValueError):
        check(protocol)


def test_offline_only_zero_request_budget(protocol):
    protocol[2]["steps"] = [protocol[2]["steps"][0]]
    protocol[2]["limits"]["max_requests"] = 0
    result = check(protocol)
    assert result["reserved_requests"] == 0
    assert result["pending_checkpoints"] == []


def test_same_stage_cycle_and_concurrency_batches(protocol):
    value = protocol[2]
    value["steps"] = [dict(value["steps"][0], id=f"branch-{i}") for i in range(5)]
    assert check(protocol)["planning_batches"] == [
        ["branch-0", "branch-1"], ["branch-2", "branch-3"], ["branch-4"]]
    value["steps"][0]["depends_on"] = ["branch-1"]
    value["steps"][1]["depends_on"] = ["branch-0"]
    with pytest.raises(ValueError, match="cycle"):
        check(protocol)


def test_stage_barriers_and_future_window(protocol):
    for step in protocol[2]["steps"]:
        step["depends_on"] = []
    protocol[2]["starts_at"] = (NOW + timedelta(minutes=5)).isoformat()
    result = check(protocol)
    assert result["window_open"] is False
    assert result["planning_batches"] == [[f"step-{i}"] for i in range(6)]


def test_request_reservations_and_spacing(protocol):
    step = protocol[2]["steps"][3]
    step["requests"] = 4
    protocol[2]["limits"]["timeout_seconds"] = 62
    with pytest.raises(ValueError, match="spacing"):
        check(protocol)
    protocol[2]["limits"]["timeout_seconds"] = 120
    second = dict(step, id="second-validation", depends_on=["step-3"], requests=1)
    protocol[2]["steps"].append(second)
    with pytest.raises(ValueError, match="reservations"):
        check(protocol)


def test_duplicate_json_and_size_limits(protocol):
    profile, path, value = protocol
    path.write_text('{"schema_version":1,"schema_version":1}')
    with pytest.raises(ValueError, match="Duplicate"):
        compile_protocol(profile, path, now=NOW)
    path.write_text(" " * 65_537)
    with pytest.raises(ValueError, match="size limit"):
        compile_protocol(profile, path, now=NOW)
    path.write_text(json.dumps(value))


def test_cli_private_output_is_create_only(protocol, monkeypatch, capsys):
    import hunterqa.workflow_protocol as module
    monkeypatch.setattr(module, "utcnow", lambda: NOW)
    check(protocol)
    profile, path, _ = protocol
    output = path.parent / "preflight.json"
    args = ["workflow-preflight", "--profile", str(profile), "--protocol", str(path), "--out", str(output)]
    main(args)
    assert json.loads(output.read_text())["execution_enabled"] is False
    with pytest.raises(FileExistsError):
        main(args)
    main(["workflow-tools"])
    assert '"workflow_execution_available": false' in capsys.readouterr().out
