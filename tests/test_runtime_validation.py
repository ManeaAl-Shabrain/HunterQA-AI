"""Fixed runtime validation admission, controls, privacy and independent labels."""
from copy import deepcopy
import json
import os
import time
from types import SimpleNamespace

import pytest

from hunterqa.cli import main
from hunterqa.engagement import create_plan, digest, load_plan, run_assessment
from hunterqa import runtime_validation as checks
from hunterqa import runtime_validation_lab as lab

URL = "https://fixture.example.test/canary"
CONTRACT = {"parameter": "q", "owned_test_endpoint": True, "canary_marker": lab.PUBLIC_MARKER}


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    profile = tmp_path / "scope.json"
    profile.write_text(json.dumps({"program": "Synthetic contract tests", "platform": "private",
        "authorization_reference": "Owned synthetic responses only", "acknowledged_authorization": True,
        "allowed_hosts": ["fixture.example.test"], "allowed_paths": ["/canary"], "excluded_paths": [],
        "methods": ["GET", "HEAD"], "allowed_ports": [443], "max_requests": 5, "interval_seconds": 0.5}))
    plan = create_plan(profile, [URL], mode="sql-canary-check", validation=dict(CONTRACT))
    path = tmp_path / "plan.json"
    def save():
        path.write_text(json.dumps(plan))
        return digest(plan)
    save()
    return SimpleNamespace(root=tmp_path, profile=profile, path=path, plan=plan, save=save, stop=tmp_path / "STOP")


def run(case, transport):
    return run_assessment(case.profile, case.path, case.save(), case.stop, authorized=True,
                          transport=transport, sleeper=lambda _: None)


@pytest.mark.parametrize("change", [{"owned_test_endpoint": False}, {"parameter": "q&other"},
    {"parameter": "q" * 65}, {"parameter": True}, {"canary_marker": "a private marker"},
    {"payload": "caller-supplied SQL"}])
def test_contract_rejected_before_any_traffic(case, change):
    case.plan["steps"][0]["validation"].update(change)
    with pytest.raises(ValueError):
        run(case, lambda *a, **kw: pytest.fail("Traffic before valid contract"))


@pytest.mark.parametrize("change", [{"method": "HEAD"}, {"method": "POST"}, {"expected_status": 200},
    {"url": URL + "?q=unreviewed"}, {"url": "https://other.example.test/canary"},
    {"login_url": URL}, {"validation": None}, {"discovery": {"max_pages": 3}}])
def test_runtime_step_cannot_expand_contract(case, change):
    case.plan["steps"][0].update(change)
    with pytest.raises((ValueError, TypeError)):
        run(case, lambda *a, **kw: pytest.fail("Unexpected traffic"))


def test_fingerprint_binds_marker_and_requests_are_reserved(case):
    approval = case.save()
    case.plan["steps"][0]["validation"]["canary_marker"] = "HUNTERQA_CANARY_FEDCBA9876543210"
    case.save()
    with pytest.raises(PermissionError):
        run_assessment(case.profile, case.path, approval, case.stop, authorized=True)
    case.plan["steps"] *= 2
    with pytest.raises(ValueError):
        run(case, lambda *a, **kw: pytest.fail("Multiple runtime steps accepted"))


def test_budget_and_xss_isolation_are_required(case):
    raw = json.loads(case.profile.read_text())
    raw["max_requests"] = 4
    case.profile.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="five"):
        create_plan(case.profile, [URL], mode="sql-canary-check", validation=CONTRACT)
    raw["max_requests"] = 5
    case.profile.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="isolation"):
        create_plan(case.profile, [URL], mode="xss-canary-check",
                    validation={"parameter": "q", "owned_test_endpoint": True})
    with pytest.raises(ValueError):
        create_plan(case.profile, [URL], mode="observe", validation=CONTRACT)


@pytest.mark.parametrize("signals,state", [([False, True, False, True, False], "matched"),
    ([False] * 5, "not_observed"), ([True] * 5, "inconclusive"),
    ([False, True, False, False, False], "inconclusive"),
    ([False, True, True, True, False], "inconclusive")])
def test_sql_controls_and_repeats_prevent_reflection_and_unstable_claims(case, signals, state):
    calls = []
    def transport(policy, url, method, *, body, headers, query):
        assert url == URL and method == "GET" and body is None and not headers
        assert query == {"q": checks.SQL_INPUTS[len(calls)]}
        present = signals[len(calls)]
        calls.append(query)
        return {"status": 200, "headers": [], "body": lab.PUBLIC_MARKER.encode() if present else b"private-body"}
    report = run(case, transport)
    validation = report["observations"][0]["validation"]
    assert validation["state"] == state and report["requests"] == 5
    assert checks.retained_state(validation, "sql", False) == state
    exported = json.dumps(report)
    for value in (lab.PUBLIC_MARKER, "private-body", "OR 'hq'", "fixture.example.test"):
        assert value not in exported
    assert report["claims"]["verified_vulnerabilities"] == 0


@pytest.mark.parametrize("status", [302, 401, 403, 404, 429, 500])
def test_non_200_stops_without_retries_or_further_probes(case, status):
    calls = []
    def transport(*args, **kwargs):
        calls.append(1)
        return {"status": status, "headers": [("Location", "https://elsewhere.example.test/")], "body": b""}
    report = run(case, transport)
    assert report["requests"] == len(calls) == 1 and report["stopped"]
    assert report["observations"][0]["validation"]["state"] == "inconclusive"


def test_stop_during_cases_retains_partial_receipts(case):
    def transport(*args, **kwargs):
        case.stop.touch()
        return {"status": 200, "headers": [], "body": b""}
    report = run(case, transport)
    validation = report["observations"][0]["validation"]
    assert report["requests"] == 1 and report["stopped"]
    assert len(validation["receipts"]) == 1 and validation["state"] == "inconclusive"


def test_transport_error_and_body_limit_are_private(case):
    def fail(*args, **kwargs):
        raise RuntimeError("private-account-and-response")
    report = run(case, fail)
    assert "private-account" not in json.dumps(report)
    assert report["observations"][0]["validation"]["error_type"] == "RuntimeError"
    policy, _ = load_plan(case.profile, case.path)
    result = checks.check_sql(policy, case.plan["steps"][0], _gate(case),
                             transport=lambda *a, **kw: {"status": 200, "body": b"a" * 1_048_577})
    assert result["state"] == "inconclusive" and result["error_type"] == "ValueError"


def _gate(case):
    from hunterqa.engagement import RunGate
    policy, plan = load_plan(case.profile, case.path)
    return RunGate(policy, plan, case.stop, sleeper=lambda _: None)


def test_saved_state_is_recomputed_from_receipts(case):
    index = [0]
    def transport(*args, **kwargs):
        signal = checks.EXPECTED_PATTERN[index[0]]
        index[0] += 1
        return {"status": 200, "headers": [], "body": lab.PUBLIC_MARKER.encode() if signal else b""}
    validation = run(case, transport)["observations"][0]["validation"]
    for key, value in (("state", "not_observed"), ("control_cases_passed", False),
                       ("customer_vulnerability_confirmed", True), ("review_required", False),
                       ("scope", "customer confirmed")):
        changed = deepcopy(validation)
        changed[key] = value
        with pytest.raises(ValueError):
            checks.retained_state(changed, "sql", False)
    changed = deepcopy(validation)
    changed["receipts"][0]["canary_present"] = "false"
    with pytest.raises(ValueError):
        checks.retained_state(changed, "sql", False)


def test_independent_labels_measure_misses_false_positives_and_abstentions():
    labels = json.loads(lab.LABELS.read_bytes())
    runs = [{"id": c["id"], "kind": c["kind"], "state": c["expected_state"]} for c in labels["cases"]]
    assert lab.measure(labels, runs)["all_cases_matched"]
    runs[0]["state"] = "not_observed"
    runs[1]["state"] = "matched"
    runs[3]["state"] = "inconclusive"
    result = lab.measure(labels, runs)
    assert result["by_class"]["sql"]["false_negatives"] == 1
    assert result["by_class"]["sql"]["false_positives"] == 1
    assert result["by_class"]["xss"]["inconclusive_positive"] == 1
    assert result["by_class"]["xss"]["positive_miss_rate"] == 1
    assert not result["all_cases_matched"]


def test_cli_creates_reviewable_contract_without_network(case):
    out = case.root / "cli-plan.json"
    main(["engagement-plan", "--profile", str(case.profile), "--url", URL,
          "--mode", "sql-canary-check", "--parameter", "q", "--owned-test-endpoint",
          "--canary-marker", lab.PUBLIC_MARKER, "--out", str(out)])
    assert json.loads(out.read_text())["steps"][0]["validation"] == CONTRACT
    with pytest.raises(PermissionError):
        lab.benchmark(case.root / "not-authorized")
    assert not (case.root / "not-authorized").exists()


@pytest.mark.skipif(os.environ.get("HUNTERQA_ENGAGEMENT_BROWSER_CI") != "1", reason="Owned HTTP plus real Chromium")
def test_owned_http_and_real_browser_baseline_is_verifiable_without_replaying(case, monkeypatch):
    pytest.importorskip("playwright.async_api")
    root = case.root / "runtime-lab"
    report = lab.benchmark(root, authorized=True)
    assert report["all_cases_matched"] and report["network_requests"] == report["server_requests"] == 30
    for kind in ("sql", "xss"):
        score = report["by_class"][kind]
        assert (score["true_positives"], score["false_positives"], score["false_negatives"], score["true_negatives"]) == (1, 0, 0, 2)
    def no_network(*args, **kwargs):
        pytest.fail("Verification launched a browser or server")
    monkeypatch.setattr(lab, "owned_service", no_network)
    verified = lab.verify(root)
    assert verified["passed"] and verified["network_requests"] == 0 and not verified["fresh_validation_performed"]
    benchmark_path = root / "benchmark.json"
    original_benchmark = benchmark_path.read_text()
    for key, value in (("fixture_version", "wrong"), ("all_cases_matched", False),
                       ("network_requests", 0), ("customer_vulnerabilities_confirmed", True),
                       ("source_identity_sha256", "0" * 64)):
        changed = json.loads(original_benchmark)
        changed[key] = value
        benchmark_path.write_text(json.dumps(changed))
        with pytest.raises(ValueError):
            lab.verify(root)
    benchmark_path.write_text(original_benchmark)
    plan_path = root / "sql-literal.plan.json"
    original_plan = plan_path.read_text()
    changed = json.loads(original_plan)
    changed["steps"][0]["validation"]["parameter"] = "different"
    plan_path.write_text(json.dumps(changed))
    with pytest.raises(ValueError):
        lab.verify(root)
    plan_path.write_text(original_plan)
    saved = json.loads((root / "sql-literal.result.json").read_text())
    saved["observations"][0]["validation"]["state"] = "not_observed"
    (root / "sql-literal.result.json").write_text(json.dumps(saved))
    with pytest.raises(ValueError):
        lab.verify(root)
    with pytest.raises(FileExistsError):
        lab.benchmark(root, authorized=True)


@pytest.mark.skipif(os.environ.get("HUNTERQA_ENGAGEMENT_BROWSER_CI") != "1", reason="Real isolated Chromium controls")
@pytest.mark.parametrize("behavior", ["uniform", "unstable", "redirect", "timeout", "stop", "plain-text"])
def test_real_xss_controls_cannot_promote_inconclusive_results(case, monkeypatch, behavior):
    pytest.importorskip("playwright.async_api")
    token = "a" * 32
    monkeypatch.setattr(checks.secrets, "token_hex", lambda _: token)
    monkeypatch.setenv("HUNTERQA_TEST_PASSWORD", "never-forward-this-secret")
    plan = create_plan(case.profile, [URL], mode="xss-canary-check", browser_isolated=True,
                       validation={"parameter": "q", "owned_test_endpoint": True})
    case.plan.clear()
    case.plan.update(plan)
    calls = []
    def transport(policy, url, method, *, body, headers, query):
        assert "HUNTERQA_TEST_PASSWORD" not in os.environ
        assert url == URL and method == "GET" and body is None and not headers
        index = len(calls)
        calls.append(query)
        outgoing = [("Content-Type", "text/plain" if behavior == "plain-text" else "text/html")]
        if behavior == "redirect":
            return {"status": 302, "headers": [("Location", "https://other.example.test/")], "body": b""}
        if behavior == "stop":
            case.stop.touch()
        if behavior == "timeout":
            body = "<script>Object.defineProperty(globalThis,'__hunterqa_runtime',{get(){while(true){}}})</script>"
        elif behavior == "uniform":
            body = "<script>globalThis.__hunterqa_runtime='" + token + "'</script>"
        elif behavior == "unstable" and index == 3:
            body = "Repeat deliberately does not execute"
        else:
            body = "<body>" + query["q"]
        body += '<img src="https://other.example.test/track"><iframe src="/canary"></iframe>'
        return {"status": 200, "headers": outgoing, "body": body.encode()}
    started = time.monotonic()
    report = run(case, transport)
    assert time.monotonic() - started < 25
    validation = report["observations"][0]["validation"]
    assert validation["state"] == ("not_observed" if behavior == "plain-text" else "inconclusive")
    assert checks.retained_state(validation, "xss", report["stopped"]) == validation["state"]
    assert len(calls) == (1 if behavior in {"redirect", "timeout", "stop"} else 5)
    for secret in (token, "never-forward-this-secret", "<svg", "other.example.test"):
        assert secret not in json.dumps(report)
