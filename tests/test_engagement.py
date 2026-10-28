"""Assessment admission, privacy and stop regressions; no remote targets."""
import hashlib
import json
import os
from datetime import timedelta
from types import SimpleNamespace

import pytest

from hunterqa.engagement import (RunGate, create_plan, digest, load_plan, prepare_package,
                                pinned_request, run_assessment, utcnow)
from hunterqa.cli import main


@pytest.fixture
def files(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({
        "program": "Owned fixture", "platform": "private",
        "authorization_reference": "Fixture permission reference",
        "acknowledged_authorization": True, "allowed_hosts": ["fixture.example.test"],
        "allowed_paths": ["/app"], "excluded_paths": ["/app/delete"],
        "methods": ["HEAD", "GET"], "allowed_ports": [443],
        "max_requests": 4, "interval_seconds": 0.5,
    }))
    plan = {"schema_version": 1, "policy_sha256": hashlib.sha256(profile.read_bytes()).hexdigest(),
            "authorization_reference": "Fixture permission reference",
            "expires_at": (utcnow() + timedelta(hours=1)).isoformat(),
            "dedicated_test_account": False, "browser_isolated": False,
            "steps": [{"mode": "observe", "url": "https://fixture.example.test/app", "method": "GET"}]}
    path = tmp_path / "plan.json"
    def save():
        path.write_text(json.dumps(plan))
        return digest(plan)
    save()
    return SimpleNamespace(profile=profile, path=path, plan=plan, save=save,
                           stop=tmp_path / "STOP")


def run(files, **kwargs):
    return run_assessment(files.profile, files.path, files.save(), files.stop,
                          authorized=True, sleeper=lambda _: None, **kwargs)


@pytest.mark.parametrize("mode", ["observe", "waf-canary", "auth-check"])
def test_fixed_modes_do_not_export_secrets(files, monkeypatch, mode):
    step = files.plan["steps"][0]
    step.update(mode=mode, method="POST" if mode == "auth-check" else "GET", expected_status=200)
    files.plan["dedicated_test_account"] = True
    monkeypatch.setenv("HUNTERQA_TEST_USERNAME", "dedicated-user")
    monkeypatch.setenv("HUNTERQA_TEST_PASSWORD", "secret-password")
    calls = []
    def transport(policy, url, method, *, body, headers):
        calls.append((method, body, headers))
        return {"status": 200, "headers": [("Set-Cookie", "session=secret-cookie")],
                "body": b"private page contents"}
    result = run(files, transport=transport)
    assert result["requests"] == 1
    assert result["observations"][0]["expected_status_matches"] is True
    assert result["claims"]["verified_vulnerabilities"] == 0
    exported = json.dumps(result)
    for secret in ("dedicated-user", "secret-password", "secret-cookie", "private page contents", "fixture.example.test"):
        assert secret not in exported
    if mode == "auth-check":
        assert calls[0][1] == b"username=dedicated-user&password=secret-password"
    if mode == "waf-canary":
        assert calls[0][2] == {"X-HunterQA-Test": "approved-benign-canary"}


@pytest.mark.parametrize("change", [
    {"url": "https://other.example.test/app"}, {"url": "https://fixture.example.test/app/delete"},
    {"url": "https://fixture.example.test/app?secret=value"}, {"method": "DELETE"},
    {"payload": "arbitrary"}, {"mode": "exploit"}, {"mode": []},
    {"mode": "auth-check", "method": "POST"},
    {"mode": "browser"}, {"expected_status": True},
])
def test_all_steps_preflight_before_network(files, change):
    files.plan["steps"].append({**files.plan["steps"][0], **change})
    calls = []
    with pytest.raises((ValueError, TypeError)):
        run(files, transport=lambda *a, **kw: calls.append(1))
    assert not calls


def test_approval_expiry_and_profile_binding(files):
    approval = files.save()
    with pytest.raises(PermissionError):
        run_assessment(files.profile, files.path, approval, files.stop)
    files.plan["steps"][0]["method"] = "HEAD"
    files.save()
    with pytest.raises(PermissionError):
        run_assessment(files.profile, files.path, approval, files.stop, authorized=True)
    for expires in (utcnow() - timedelta(seconds=1), utcnow() + timedelta(days=2)):
        files.plan["expires_at"] = expires.isoformat()
        files.save()
        with pytest.raises(ValueError):
            load_plan(files.profile, files.path)
    files.plan["expires_at"] = (utcnow() + timedelta(hours=1)).isoformat()
    files.save()
    files.profile.write_text(files.profile.read_text() + " ")
    with pytest.raises(ValueError, match="exact scope"):
        load_plan(files.profile, files.path)


@pytest.mark.parametrize("status", [301, 302, 307, 401, 403, 429, 500, 503])
def test_stop_responses_are_not_retried(files, status):
    files.plan["steps"] *= 3
    result = run(files, transport=lambda *a, **kw: {"status": status, "headers": [], "body": b""})
    assert result["requests"] == 1
    assert result["stopped"] is True
    assert len(result["observations"]) == 1


def test_stop_file_prevents_network(files):
    files.stop.touch()
    result = run(files, transport=lambda *a, **kw: pytest.fail("Network after stop"))
    assert result["requests"] == 0
    assert result["stopped"] is True


def test_stop_during_wait_and_budget(files):
    policy, plan = load_plan(files.profile, files.path)
    gate = RunGate(policy, plan, files.stop, sleeper=lambda _: files.stop.touch())
    gate.admit()
    with pytest.raises(PermissionError):
        gate.admit()
    assert gate.count == 1
    files.stop.unlink()
    gate = RunGate(policy, plan, files.stop, sleeper=lambda _: None)
    for _ in range(policy.max_requests):
        gate.admit()
    with pytest.raises(PermissionError, match="budget"):
        gate.admit()


def test_single_credential_submission_and_https(files):
    files.plan["dedicated_test_account"] = True
    files.plan["steps"][0].update(mode="auth-check", method="POST")
    files.plan["steps"] *= 2
    files.save()
    with pytest.raises(ValueError, match="one credential"):
        load_plan(files.profile, files.path)


def test_plan_creation_cli_does_not_approve_or_execute(files, capsys):
    output = files.path.parent / "created.json"
    main(["engagement-plan", "--profile", str(files.profile), "--url", "https://fixture.example.test/app",
          "--mode", "waf-canary", "--expected-status", "403", "--out", str(output)])
    assert "Saved:" in capsys.readouterr().out
    _, plan = load_plan(files.profile, output)
    assert plan["steps"][0]["expected_status"] == 403
    assert plan["steps"][0]["mode"] == "waf-canary"
    with pytest.raises(ValueError):
        create_plan(files.profile, [], ttl_minutes=0)
    with pytest.raises(ValueError):
        create_plan(files.profile, ["https://fixture.example.test/app"],
                    mode="browser", login_url="https://elsewhere.example.test/login",
                    browser_isolated=True, dedicated_test_account=True)


def test_duplicate_keys_are_rejected(files):
    files.path.write_text('{"schema_version":1,"schema_version":1}')
    with pytest.raises(ValueError, match="Duplicate"):
        load_plan(files.profile, files.path)
    files.save()
    files.profile.write_text('{"program":"one","program":"two"}')
    with pytest.raises(ValueError, match="Duplicate"):
        load_plan(files.profile, files.path)


def test_pinned_transport_does_not_follow_redirects(files, monkeypatch):
    policy, _ = load_plan(files.profile, files.path)
    calls = []
    class Connection:
        def __init__(self, host, port, ip, timeout):
            assert (host, port, ip, timeout) == ("fixture.example.test", 443, "1.1.1.1", 5)
        def request(self, method, path, **kwargs):
            calls.append((method, path, kwargs))
        def getresponse(self):
            return SimpleNamespace(status=302, getheaders=lambda: [("Location", "https://elsewhere.test/")],
                                   read=lambda limit: b"redirect")
        def close(self):
            calls.append("closed")
    monkeypatch.setattr("hunterqa.engagement.resolve_pinned", lambda *a: "1.1.1.1")
    monkeypatch.setattr("hunterqa.engagement._PinnedHTTPS", Connection)
    result = pinned_request(policy, "https://fixture.example.test/app", "GET")
    assert result["status"] == 302
    assert len(calls) == 2
    assert calls[0][1] == "/app"
    assert calls[-1] == "closed"


def test_dns_rejection_prevents_connection(files, monkeypatch):
    policy, _ = load_plan(files.profile, files.path)
    def reject(*a):
        raise ValueError("Unsafe DNS answer")
    monkeypatch.setattr("hunterqa.engagement.resolve_pinned", reject)
    monkeypatch.setattr("hunterqa.engagement._PinnedHTTPS", lambda *a, **kw: pytest.fail("Connection after DNS rejection"))
    with pytest.raises(ValueError, match="DNS"):
        pinned_request(policy, "https://fixture.example.test/app", "GET")


def test_errors_never_export_exception_contents(files):
    def transport(*a, **kw):
        raise RuntimeError("secret-password https://private-target.test")
    result = run(files, transport=transport)
    assert result["observations"][0]["error_type"] == "RuntimeError"
    assert "secret-password" not in json.dumps(result)


def test_cli_preflight_is_offline_and_existing_output_prevents_run(files, capsys, monkeypatch):
    main(["engagement-preflight", "--profile", str(files.profile), "--plan", str(files.path)])
    preview = json.loads(capsys.readouterr().out)
    assert preview["network_requests"] == 0
    assert preview["approval_sha256"] == files.save()
    output = files.path.parent / "result.json"
    output.write_text("existing private evidence")
    monkeypatch.setattr("hunterqa.engagement.run_assessment", lambda *a, **kw: pytest.fail("Run despite existing output"))
    with pytest.raises(FileExistsError):
        main(["engagement-run", "--profile", str(files.profile), "--plan", str(files.path),
              "--approve-plan", files.save(), "--stop-file", str(files.stop), "--out", str(output), "--authorized"])
    assert output.read_text() == "existing private evidence"


def test_package_uses_existing_validated_dossier_gate(files, monkeypatch):
    with pytest.raises(PermissionError):
        prepare_package(files.profile, files.path, kind="disclosure", authorized=True)
    with pytest.raises(ValueError):
        prepare_package(files.profile, files.path, kind="disclosure", reviewed=True, authorized=True)
    monkeypatch.setattr("hunterqa.verification_v12.disclosure_draft", lambda *a, **kw: "Reviewed private draft")
    result = prepare_package(files.profile, files.path, kind="cve-request", reviewed=True,
                             authorized=True, assigned_cve="CVE-2026-12345")
    assert result["submitted"] is False
    assert result["assignment_verified"] is False
    assert result["externally_assigned_cve"] == "CVE-2026-12345"
    with pytest.raises(ValueError):
        prepare_package(files.profile, files.path, kind="cve-request", reviewed=True,
                        authorized=True, assigned_cve="made-up")


@pytest.mark.skipif(os.environ.get("HUNTERQA_ENGAGEMENT_BROWSER_CI") != "1",
                    reason="Opt-in real Chromium with fully intercepted synthetic traffic")
@pytest.mark.parametrize("login_status", [200, 302, 401, 429])
def test_real_chromium_intercepted_login(files, monkeypatch, login_status):
    pytest.importorskip("playwright.sync_api")
    files.plan.update(dedicated_test_account=True, browser_isolated=True)
    files.plan["steps"][0].update(mode="browser", login_url="https://fixture.example.test/app/login")
    monkeypatch.setenv("HUNTERQA_TEST_USERNAME", "disposable-fixture-user")
    monkeypatch.setenv("HUNTERQA_TEST_PASSWORD", "disposable-fixture-password")
    calls = []
    def transport(policy, url, method, *, body, headers):
        assert "HUNTERQA_TEST_USERNAME" not in os.environ
        assert "HUNTERQA_TEST_PASSWORD" not in os.environ
        calls.append((url, method, body))
        if method == "GET":
            page = (b'<form method="POST" action="/app/login"><input name="username">'
                    b'<input name="password" type="password"><button type="submit">Login</button></form>'
                    b'<img src="https://out-of-scope.example.test/tracker">'
                    b'<script>fetch("https://out-of-scope.example.test/script")</script>')
            return {"status": 200, "headers": [("Content-Type", "text/html")], "body": page}
        assert url == "https://fixture.example.test/app/login"
        assert b"disposable-fixture-password" in body
        return {"status": login_status, "headers": [("Location", "https://out-of-scope.example.test/")],
                "body": b"private account content"}
    result = run(files, transport=transport)
    assert len(calls) == 2
    assert result["requests"] == 2
    assert result["observations"][0]["authentication"] == "attempted_unverified"
    assert result["stopped"] is (login_status != 200)
    assert "disposable-fixture" not in json.dumps(result)
