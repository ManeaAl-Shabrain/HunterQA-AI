"""Independent rendered-route labels; real Chromium never contacts a target."""
import asyncio
import hashlib
import json
import os
import time
from types import SimpleNamespace

import pytest

from hunterqa.cli import main
from hunterqa.engagement import create_plan, digest, load_plan, run_assessment
from hunterqa.scoped_rendered_discovery import candidate, crawl, measure, url_hash, validate_options

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


@real_browser
def test_real_unresponsive_dom_evaluation_times_out_and_closes(case):
    pytest.importorskip("playwright.async_api")
    def transport(*args, **kwargs):
        return {"status": 200, "headers": [("Content-Type", "text/html")], "body": b'''<body>
            <a href="/app/one">link</a><script>
            Object.defineProperty(HTMLAnchorElement.prototype, 'href', {get() {while(true) {}}});
            </script>'''}
    started = time.monotonic()
    result = run_assessment(case.profile, case.path, case.save(), case.stop, authorized=True, transport=transport)
    assert time.monotonic() - started < 20
    assert result["stopped"] and result["requests"] == 1
    assert result["observations"][0]["error_type"] == "TimeoutError"


@real_browser
def test_real_parallel_login_requests_reserve_only_one_submission(case, monkeypatch):
    pytest.importorskip("playwright.async_api")
    case.plan["dedicated_test_account"] = True
    case.plan["steps"][0]["login_url"] = START + "/login"
    monkeypatch.setenv("HUNTERQA_TEST_USERNAME", "designated-user")
    monkeypatch.setenv("HUNTERQA_TEST_PASSWORD", "designated-password")
    calls = []
    def transport(policy, url, method, **kwargs):
        calls.append(method)
        return {"status": 200, "headers": [("Content-Type", "text/html")], "body": b'''<script>
            const options={method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
                body:'username=designated-user&password=designated-password'};
            Promise.allSettled([fetch('/app/login', options), fetch('/app/login', options)]);
            </script>'''}
    result = run_assessment(case.profile, case.path, case.save(), case.stop, authorized=True, transport=transport)
    assert calls.count("POST") == 1 and result["requests"] == 2
    assert result["stopped"]  # No conventional login form exists in this fixture.


@pytest.mark.parametrize("routes", [None, [], ["/a", "/a"], ["/a"] * 11, [1], [{}],
    ["# /a"], ["#/a"], ["!/a"], ["a"], ["//a"], ["/a//b"], ["/a/../b"],
    ["/a?secret=x"], ["/a#b"], ["/a%2fb"], ["/a b"], ["/a\nb"], ["/é"], ["/" + "x" * 256]])
def test_explicit_hash_route_selection_rejects_ambiguous_unbounded_values(case, routes):
    case.plan["steps"][0]["discovery"]["hash_routes"] = routes
    with pytest.raises(ValueError):
        load_plan(case.profile, _save_path(case))


@pytest.mark.parametrize("route", ["/", "/overview", "/Case_1/nested-2/", "/" + "x" * 255])
def test_exact_hash_route_selection_is_case_sensitive_and_bounded(case, route):
    policy, _ = load_plan(case.profile, case.path)
    validate_options({**OPTIONS, "hash_routes": [route]})
    assert candidate(policy, START, START + "#" + route, hash_routes=[route]) == START + "#" + route


@pytest.mark.parametrize("url", [START + "#/other", START + "#/private?x=1", START + "#/Private",
    START + "/child#/private", "https://other.example.test/app#/private", START + "?x=1#/private",
    START + "#section", START + "#/private#extra", START + "#%2Fprivate"])
def test_hash_routes_do_not_expand_document_origin_path_query_or_exact_selection(case, url):
    policy, _ = load_plan(case.profile, case.path)
    with pytest.raises(ValueError):
        candidate(policy, START, url, hash_routes=["/private"])


def test_start_document_comparison_handles_browser_default_port_normalization(case):
    policy, _ = load_plan(case.profile, case.path)
    assert candidate(policy, "https://fixture.example.test:443/app", START + "#/a", hash_routes=["/a"]) == START + "#/a"


def test_hash_route_approval_binding_and_cli_plan(case, tmp_path):
    output = tmp_path / "hash-plan.json"
    main(["engagement-plan", "--profile", str(case.profile), "--url", START, "--mode", "browser-discovery",
          "--browser-isolated", "--hash-route", "/first", "--hash-route", "/second", "--out", str(output)])
    plan = json.loads(output.read_text())
    assert plan["steps"][0]["discovery"]["hash_routes"] == ["/first", "/second"]
    old = digest(plan)
    plan["steps"][0]["discovery"]["hash_routes"] = ["/changed"]
    output.write_text(json.dumps(plan))
    with pytest.raises(PermissionError):
        run_assessment(case.profile, output, old, case.stop, authorized=True,
            browser_provider=lambda: pytest.fail("Changed routes launched browser"))


def test_hash_routes_cannot_be_attached_to_other_engagement_modes(case):
    with pytest.raises(ValueError, match="only"):
        create_plan(case.profile, [START], mode="browser", browser_isolated=True,
            discovery={**OPTIONS, "hash_routes": ["/first"]})


class FakeRenderedPage:
    def __init__(self, snapshots, *, no_response=False, move_during_snapshot=False):
        self.url, self.snapshots = START, snapshots
        self.no_response, self.move_during_snapshot, self.navigated = no_response, move_during_snapshot, []
    async def goto(self, url, **kwargs):
        self.navigated.append(url)
        self.url = url
        return None if self.no_response else SimpleNamespace(status=200)
    async def wait_for_timeout(self, value):
        pass
    async def evaluate(self, script):
        if self.move_during_snapshot:
            self.url = START + "#/unapproved"
        return {"links": self.snapshots.get(self.url, []), "forms": 0}


def fake_crawl(case, page, **options):
    policy, _ = load_plan(case.profile, case.path)
    return asyncio.run(crawl(page, policy, {"url": START, "discovery": {**OPTIONS, **options}},
        SimpleNamespace(check=lambda: None)))


def test_null_navigation_response_only_for_reviewed_same_document_transition(case):
    page = FakeRenderedPage({START: [START + "#/private-state"]}, no_response=True)
    report = fake_crawl(case, page, hash_routes=["/private-state"])
    assert report["pages_visited"] == 2 and report["hash_states_visited"] == 1
    assert report["pages"][1]["navigation_kind"] == "same-document-fragment"
    assert report["hash_routes_selected"] == 1
    assert "/private-state" not in json.dumps(report) and "hash_routes" not in report


def test_null_navigation_response_for_new_document_still_stops(case):
    page = FakeRenderedPage({START: [START + "/child"]}, no_response=True)
    with pytest.raises(RuntimeError, match="no response"):
        fake_crawl(case, page, hash_routes=["/private-state"])


def test_unapproved_route_change_during_snapshot_stops(case):
    page = FakeRenderedPage({}, move_during_snapshot=True)
    with pytest.raises(ValueError):
        fake_crawl(case, page, hash_routes=["/private-state"])


def test_discovered_and_visited_reference_coverage_are_distinct(case):
    page = FakeRenderedPage({START: [START + "#/first", START + "#/second"]})
    discovery = fake_crawl(case, page, max_pages=1, hash_routes=["/first", "/second"])
    report = {"engine": "hunterqa_approved_assessment", "stopped": False,
        "observations": [{"mode": "browser-discovery", "discovery": discovery}]}
    result = measure(report, {"schema_version": 1, "expected_url_sha256": [url_hash(u) for u in (START, START + "#/first", START + "#/second")]})
    assert result["reference_discovery_recall"] == 1.0 and result["reference_visit_recall"] == 1 / 3
    assert result["visited_reference_matches"] == result["visited_count"] == 1
    assert result["visited_reference_missing"] == 2 and discovery["limit_reached"]


@pytest.mark.parametrize("pages", [[], [None], [{"url_sha256": "bad"}], [{"url_sha256": url_hash(START)}] * 2,
    [{"url_sha256": url_hash(START + "/unknown")}], [{"url_sha256": url_hash(str(i))} for i in range(11)]])
def test_visit_metrics_reject_invalid_duplicate_and_unobserved_rows(pages):
    report = {"engine": "hunterqa_approved_assessment", "stopped": False, "observations": [{"mode": "browser-discovery",
        "discovery": {"mode": "scoped-https-rendered-anchors", "discovered_url_sha256": [url_hash(START)], "pages": pages}}]}
    with pytest.raises(ValueError):
        measure(report, {"schema_version": 1, "expected_url_sha256": [url_hash(START)]})


def test_legacy_inventory_has_unknown_visit_metrics():
    report = {"engine": "hunterqa_approved_assessment", "stopped": False, "observations": [{"mode": "browser-discovery",
        "discovery": {"mode": "scoped-https-rendered-anchors", "discovered_url_sha256": [url_hash(START)]}}]}
    result = measure(report, {"schema_version": 1, "expected_url_sha256": [url_hash(START)]})
    assert result["reference_discovery_recall"] == 1.0 and result["reference_visit_recall"] is None
    assert result["visited_reference_matches"] is None and result["visited_count"] is None


def spa_transport(calls, *, login=False, auto_route=None, fetch_each=False, stop=None):
    def transport(policy, url, method, *, body, headers):
        calls.append((url, method, dict(headers)))
        outgoing = [("Content-Type", "text/html")]
        if method == "POST":
            assert login and url == START + "/login" and b"fixture-secret" in body
            outgoing.append(("Set-Cookie", "session=owned-cookie; Secure; HttpOnly; Path=/app"))
            data = "Owned login"
        elif login and "session=owned-cookie" not in headers.get("cookie", ""):
            data = '<form method="post" action="/app/login"><input name="username"><input name="password"><button type="submit">Login</button></form>'
        elif url == START:
            data = '''<body><script>
              function render(){
                let route=location.hash;
                let links=route==='#/first'?['#/second']:['#/first'];
                document.body.replaceChildren();
                for(let href of [...links,'#/unselected','/app/child#/first','https://other.example.test/app#/first']){
                  let a=document.createElement('a');a.href=href;document.body.append(a);
                }
                FETCH_EACH
              }
              addEventListener('hashchange',render); render(); AUTO_ROUTE
            </script>'''
            data = data.replace("FETCH_EACH", "fetch('/app/ping').catch(()=>{});" if fetch_each else "")
            data = data.replace("AUTO_ROUTE", "location.hash=" + json.dumps(auto_route) + ";" if auto_route else "")
        elif url == START + "/child":
            data = "<body>Owned ordinary child</body>"
        else:
            assert url == START + "/ping"
            if stop:
                stop.touch()
            data = "Owned data"
        return {"status": 200, "headers": outgoing, "body": data.encode()}
    return transport


@real_browser
@pytest.mark.parametrize("login", [False, True])
def test_real_selected_spa_states_no_extra_document_requests_and_private_routes(case, monkeypatch, login):
    case.plan["steps"][0]["discovery"] = {**OPTIONS, "max_depth": 2, "hash_routes": ["/first", "/second"]}
    if login:
        case.plan["dedicated_test_account"] = True
        case.plan["steps"][0]["login_url"] = START + "/login"
        monkeypatch.setenv("HUNTERQA_TEST_USERNAME", "fixture-user")
        monkeypatch.setenv("HUNTERQA_TEST_PASSWORD", "fixture-secret")
    calls = []
    result = run_assessment(case.profile, case.path, case.save(), case.stop, authorized=True,
        transport=spa_transport(calls, login=login))
    assert not result["stopped"], result
    discovery = result["observations"][0]["discovery"]
    assert discovery["pages_visited"] == 3 and discovery["hash_states_visited"] == 2
    assert [p["navigation_kind"] for p in discovery["pages"]] == ["initial-document", "same-document-fragment", "same-document-fragment"]
    assert discovery["discovered_url_sha256"] == sorted(url_hash(u) for u in (START, START + "#/first", START + "#/second"))
    assert len(calls) == (3 if login else 1) and all("#" not in u for u, _, _ in calls)
    score = measure(result, {"schema_version": 1, "expected_url_sha256": [url_hash(u) for u in (START, START + "#/first", START + "#/second")]})
    assert score["reference_visit_recall"] == score["reference_discovery_recall"] == 1.0
    for private in ("/first", "/second", "fixture-secret", "owned-cookie", "fixture.example.test"):
        assert private not in json.dumps(result)


@real_browser
@pytest.mark.parametrize("bound", ["depth", "pages"])
def test_real_hash_states_count_against_existing_depth_and_page_bounds(case, bound):
    options = {**OPTIONS, "max_depth": 2, "hash_routes": ["/first", "/second"]}
    options["max_depth" if bound == "depth" else "max_pages"] = 0 if bound == "depth" else 1
    case.plan["steps"][0]["discovery"] = options
    calls = []
    result = run_assessment(case.profile, case.path, case.save(), case.stop, authorized=True, transport=spa_transport(calls))
    discovery = result["observations"][0]["discovery"]
    assert not result["stopped"] and len(calls) == 1 and discovery["pages_visited"] == 1
    assert discovery["hash_states_visited"] == 0 and discovery["limit_reached"]


@real_browser
def test_real_unapproved_autonomous_hash_change_stops_inventory(case):
    case.plan["steps"][0]["discovery"]["hash_routes"] = ["/first"]
    result = run_assessment(case.profile, case.path, case.save(), case.stop, authorized=True,
        transport=spa_transport([], auto_route="/unselected"))
    assert result["stopped"] and "discovery" not in result["observations"][0]


@real_browser
@pytest.mark.parametrize("reason", ["request-budget", "stop-file"])
def test_real_hash_navigation_does_not_bypass_network_or_stop_controls(case, reason):
    options = {**OPTIONS, "max_depth": 2, "hash_routes": ["/first", "/second"]}
    if reason == "request-budget":
        profile = json.loads(case.profile.read_text())
        profile["max_requests"] = 1
        case.profile.write_text(json.dumps(profile))
        new_plan = create_plan(case.profile, [START], mode="browser-discovery", browser_isolated=True, discovery=options)
        case.plan.clear()
        case.plan.update(new_plan)
    else:
        case.plan["steps"][0]["discovery"] = options
    calls = []
    result = run_assessment(case.profile, case.path, case.save(), case.stop, authorized=True,
        transport=spa_transport(calls, fetch_each=True, stop=case.stop if reason == "stop-file" else None))
    assert result["stopped"] and len(calls) <= 2
    assert all(url in (START, START + "/ping") and method == "GET" for url, method, _ in calls)


@real_browser
def test_real_legacy_discovery_still_ignores_hash_routes(case):
    calls = []
    result = run_assessment(case.profile, case.path, case.save(), case.stop, authorized=True, transport=spa_transport(calls))
    discovery = result["observations"][0]["discovery"]
    assert discovery["hash_states_visited"] == discovery["hash_routes_selected"] == 0
    assert len(calls) == 2  # Legacy fragment stripping follows the ordinary /app/child link.
