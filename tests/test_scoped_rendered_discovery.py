"""Independent rendered-route labels; real Chromium never contacts a target."""
import hashlib
import json
import os
from types import SimpleNamespace

import pytest

from hunterqa.cli import main
from hunterqa.engagement import create_plan, digest, load_plan, run_assessment
from hunterqa.scoped_rendered_discovery import candidate, measure, url_hash

START = "https://fixture.example.test/app"
OPTIONS = {"max_pages": 3, "max_depth": 1, "settle_ms": 50}


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    profile = tmp_path / "scope.json"
    profile.write_text(json.dumps({
        "program": "Owned synthetic rendered fixture", "platform": "private",
        "authorization_reference": "Owned synthetic intercepted responses only",
        "acknowledged_authorization": True, "allowed_hosts": ["fixture.example.test", "other.example.test"],
        "allowed_paths": ["/app"], "excluded_paths": ["/app/delete"],
        "methods": ["GET"], "allowed_ports": [443], "max_requests": 20,
        "interval_seconds": 0.5,
    }), encoding="utf-8")
    plan = create_plan(profile, [START], mode="browser-discovery", browser_isolated=True,
                       discovery=dict(OPTIONS))
    path = tmp_path / "plan.json"
    def save():
        path.write_text(json.dumps(plan), encoding="utf-8")
        return digest(plan)
    save()
    return SimpleNamespace(profile=profile, path=path, plan=plan, save=save, root=tmp_path,
                           stop=tmp_path / "STOP")


@pytest.mark.parametrize("options", [None, {}, {**OPTIONS, "max_pages": True},
    {**OPTIONS, "max_pages": 11}, {**OPTIONS, "max_depth": -1},
    {**OPTIONS, "settle_ms": 2001}, {**OPTIONS, "settle_ms": 1.5},
    {**OPTIONS, "script": "run arbitrary code"}])
def test_bounds_rejected_before_any_browser(case, options):
    case.plan["steps"][0]["discovery"] = options
    with pytest.raises(ValueError):
        load_plan(case.profile, _save_path(case))


def _save_path(case):
    case.save()
    return case.path


@pytest.mark.parametrize("change", [{"browser_isolated": False}, {"dedicated_test_account": False}])
def test_isolation_and_login_attestations_required(case, change):
    case.plan["steps"][0]["login_url"] = START + "/login"
    case.plan.update({"dedicated_test_account": True, **change})
    with pytest.raises(ValueError):
        load_plan(case.profile, _save_path(case))


def test_discovery_options_cannot_expand_legacy_mode(case):
    case.plan["steps"][0]["mode"] = "browser"
    with pytest.raises(ValueError, match="only"):
        load_plan(case.profile, _save_path(case))


def test_bounds_are_fingerprint_bound_and_stop_prevents_launch(case):
    approval = case.save()
    case.plan["steps"][0]["discovery"]["max_pages"] = 4
    case.save()
    with pytest.raises(PermissionError):
        run_assessment(case.profile, case.path, approval, case.stop, authorized=True)
    case.stop.touch()
    result = run_assessment(case.profile, case.path, case.save(), case.stop, authorized=True,
                            browser_provider=lambda: pytest.fail("Browser launched after stop"))
    assert result["stopped"] and result["requests"] == 0


@pytest.mark.parametrize("url", ["https://other.example.test/app", "http://fixture.example.test/app",
    START + "/delete", START + "?secret=token", "javascript:alert(1)",
    "https://fixture.example.test:444/app", "https://fixture.example.test/app/%2e%2e/out"])
def test_candidate_keeps_original_origin_scope_and_query_restrictions(case, url):
    policy, _ = load_plan(case.profile, case.path)
    with pytest.raises(ValueError):
        candidate(policy, START, url)


def test_fragment_deduplication(case):
    policy, _ = load_plan(case.profile, case.path)
    assert candidate(policy, START, START + "#section") == START


def test_reference_scoring_has_missing_labels_without_false_positive_claims():
    reference = {"schema_version": 1, "expected_url_sha256": [url_hash(START), url_hash(START + "/missing")]}
    report = {"engine": "hunterqa_approved_assessment", "stopped": False, "observations": [{
        "mode": "browser-discovery", "discovery": {"mode": "scoped-https-rendered-anchors",
        "discovered_url_sha256": [url_hash(START), url_hash(START + "/unlabelled")]}}]}
    result = measure(report, reference)
    assert result["reference_matches"] == result["reference_missing"] == result["unlabelled_discovered"] == 1
    assert result["reference_discovery_recall"] == 0.5
    assert result["coverage_complete"] is False and result["network_requests"] == 0
    reference["expected_url_sha256"] *= 2
    with pytest.raises(ValueError):
        measure(report, reference)


def test_cli_plan_defaults_and_offline_reference_report(case):
    out = case.root / "created.json"
    main(["engagement-plan", "--profile", str(case.profile), "--url", START,
          "--mode", "browser-discovery", "--browser-isolated", "--max-pages", "2", "--out", str(out)])
    assert json.loads(out.read_text())["steps"][0]["discovery"]["max_pages"] == 2
    with pytest.raises(ValueError):
        main(["engagement-plan", "--profile", str(case.profile), "--url", START,
              "--max-pages", "2", "--out", str(case.root / "invalid.json")])
    report = case.root / "report.json"
    report.write_text(json.dumps({"engine": "hunterqa_approved_assessment", "stopped": False,
        "observations": [{"mode": "browser-discovery", "discovery": {
            "mode": "scoped-https-rendered-anchors", "discovered_url_sha256": [url_hash(START)]}}]}))
    reference = case.root / "reference.json"
    reference.write_text(json.dumps({"schema_version": 1, "expected_url_sha256": [url_hash(START)]}))
    output = case.root / "coverage.json"
    main(["engagement-discovery-coverage", "--report", str(report), "--reference", str(reference), "--out", str(output)])
    assert json.loads(output.read_text())["reference_discovery_recall"] == 1.0


real_browser = pytest.mark.skipif(os.environ.get("HUNTERQA_ENGAGEMENT_BROWSER_CI") != "1",
                                reason="Opt-in Chromium with fully intercepted fixture responses")


@real_browser
@pytest.mark.parametrize("login", [False, True])
def test_real_rendered_links_session_and_reference_recall(case, monkeypatch, login):
    pytest.importorskip("playwright.sync_api")
    if login:
        case.plan["dedicated_test_account"] = True
        case.plan["steps"][0]["login_url"] = START + "/login"
        monkeypatch.setenv("HUNTERQA_TEST_USERNAME", "fixture-user")
        monkeypatch.setenv("HUNTERQA_TEST_PASSWORD", "fixture-secret")
    calls = []
    def transport(policy, url, method, *, body, headers):
        assert "HUNTERQA_TEST_PASSWORD" not in os.environ
        calls.append((url, method, dict(headers)))
        outgoing = [("Content-Type", "text/html")]
        if method == "POST":
            assert url == START + "/login" and b"fixture-secret" in body
            outgoing.append(("Set-Cookie", "session=private-cookie; Secure; HttpOnly; Path=/app"))
            data = "Logged in"
        elif login and "session=private-cookie" not in headers.get("cookie", ""):
            data = '<form method="POST" action="/app/login"><input name="username"><input name="password"><button type="submit">Login</button></form>'
        elif url == START:
            data = '''<script src="/app/code.js"></script><form action="/app/delete" method="POST"></form>
                <a href="/app/delete">excluded</a><a href="https://other.example.test/app">other admitted host</a>
                <a href="/app?secret=value">query</a><a href="/app#fragment">duplicate</a>'''
        elif url == START + "/code.js":
            outgoing = [("Content-Type", "application/javascript")]
            data = '''setTimeout(() => {
                for (const path of ['/app/one', '/app/two']) {
                    let a=document.createElement('a'); a.href=path; document.body.append(a);
                }
                fetch('https://other.example.test/app');
                fetch('/app/delete');
                fetch('/app', {method:'POST',body:'unapproved'});
            }, 10);'''
        else:
            assert url in {START + "/one", START + "/two"}
            data = '<a href="/app">back</a>'
        return {"status": 200, "headers": outgoing, "body": data.encode()}
    result = run_assessment(case.profile, case.path, case.save(), case.stop, authorized=True,
                            transport=transport)
    assert result["stopped"] is False, result["observations"][0].get("error_type", "stopped")
    discovery = result["observations"][0]["discovery"]
    assert discovery["pages_visited"] == 3
    # Labels are defined independently of the crawler and its output.
    labels = [hashlib.sha256(url.encode()).hexdigest() for url in (START, START + "/one", START + "/two")]
    score = measure(result, {"schema_version": 1, "expected_url_sha256": labels})
    assert score["reference_discovery_recall"] == 1.0 and score["unlabelled_discovered"] == 0
    assert all(url.startswith(START) and url != START + "/delete" for url, _, _ in calls)
    assert sum(method == "POST" for _, method, _ in calls) == int(login)
    if login:
        assert any(url == START + "/one" and "private-cookie" in headers.get("cookie", "") for url, _, headers in calls)
    for secret in ("private-cookie", "fixture-secret", "fixture-user", "fixture.example.test", "<script"):
        assert secret not in json.dumps(result)


@real_browser
@pytest.mark.parametrize("status", [302, 403, 429, 500])
def test_real_stop_response_never_follows_redirect_or_retries(case, status):
    pytest.importorskip("playwright.sync_api")
    calls = []
    def transport(*args, **kwargs):
        calls.append(1)
        return {"status": status, "headers": [("Location", "https://other.example.test/app")], "body": b""}
    result = run_assessment(case.profile, case.path, case.save(), case.stop, authorized=True, transport=transport)
    assert result["stopped"] and len(calls) == result["requests"] == 1


@real_browser
def test_real_preserves_all_owner_csp_policies(case):
    pytest.importorskip("playwright.sync_api")
    # Two CSP policies must both survive. The first forbids scripts even though
    # the second permits them; the tool may not replace the stronger first one.
    calls = []
    def transport(policy, url, method, **kwargs):
        calls.append(url)
        return {"status": 200, "headers": [("Content-Type", "text/html"),
            ("Content-Security-Policy", "script-src 'none'"),
            ("Content-Security-Policy", "script-src 'self' 'unsafe-inline'")],
            "body": b"<body><script>let a=document.createElement('a');a.href='/app/unexpected';document.body.append(a)</script>"}
    result = run_assessment(case.profile, case.path, case.save(), case.stop, authorized=True, transport=transport)
    assert not result["stopped"] and calls == [START]
    assert result["observations"][0]["discovery"]["discovered_url_sha256"] == [url_hash(START)]


@real_browser
@pytest.mark.parametrize("reason", ["budget", "stop-file", "depth", "page-limit"])
def test_real_bounds_prevent_further_navigation(case, reason):
    pytest.importorskip("playwright.sync_api")
    if reason == "budget":
        data = json.loads(case.profile.read_text())
        data["max_requests"] = 1
        case.profile.write_text(json.dumps(data))
        new_plan = create_plan(case.profile, [START], mode="browser-discovery", browser_isolated=True,
                               discovery=dict(OPTIONS))
        case.plan.clear()
        case.plan.update(new_plan)
    elif reason == "depth":
        case.plan["steps"][0]["discovery"]["max_depth"] = 0
    elif reason == "page-limit":
        case.plan["steps"][0]["discovery"]["max_pages"] = 1
    calls = []
    def transport(policy, url, method, **kwargs):
        calls.append(url)
        if reason == "stop-file":
            case.stop.touch()
        return {"status": 200, "headers": [("Content-Type", "text/html")],
                "body": b"<body><script>let a=document.createElement('a');a.href='/app/one';document.body.append(a)</script>"}
    result = run_assessment(case.profile, case.path, case.save(), case.stop, authorized=True, transport=transport)
    assert calls == [START] and result["requests"] == 1
    if reason in {"budget", "stop-file"}:
        assert result["stopped"]
    else:
        discovery = result["observations"][0]["discovery"]
        assert discovery["limit_reached"] and discovery["pages_visited"] == 1
        assert len(discovery["discovered_url_sha256"]) == 2


@real_browser
def test_real_page_script_cannot_choose_another_login_account(case, monkeypatch):
    pytest.importorskip("playwright.sync_api")
    case.plan["dedicated_test_account"] = True
    case.plan["steps"][0]["login_url"] = START + "/login"
    monkeypatch.setenv("HUNTERQA_TEST_USERNAME", "designated-user")
    monkeypatch.setenv("HUNTERQA_TEST_PASSWORD", "designated-password")
    calls = []
    def transport(policy, url, method, **kwargs):
        calls.append(method)
        return {"status": 200, "headers": [("Content-Type", "text/html")], "body": b'''<script>
            fetch('/app/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
            body:'username=another-account&password=guess'}).catch(()=>{});
            </script>'''}
    result = run_assessment(case.profile, case.path, case.save(), case.stop, authorized=True, transport=transport)
    assert result["stopped"] and calls == ["GET"]
    assert result["observations"][0]["authentication"] == "not_attempted"
