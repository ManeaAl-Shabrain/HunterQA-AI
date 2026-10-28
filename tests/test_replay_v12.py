"""Tests never contact a third-party target."""
import hashlib
import json
import pytest
from hunterqa.replay_v12 import replay_har_head


@pytest.fixture
def local(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({
        "program": "Approved fixture lab", "platform": "local-lab",
        "authorization_reference": "Owned disposable evidence fixture",
        "acknowledged_authorization": True,
        "allowed_hosts": ["app.example.test"],
        "methods": ["HEAD"], "max_requests": 2, "interval_seconds": 0.5,
    }))
    data = tmp_path / "imported.json"
    record = {
        "engine": "hunterqa_authorized_bounty_observation",
        "mode": "offline_har_import", "program": "Approved fixture lab",
        "platform": "local-lab",
        "policy_sha256": hashlib.sha256(profile.read_bytes()).hexdigest(),
        "observations": [
            {"url": "https://app.example.test/a", "method": "HAR", "status": 200},
            {"url": "https://app.example.test/b", "method": "HAR", "status": 200},
        ],
    }
    data.write_text(json.dumps(record))
    return profile, data


def test_replay_approved_head_exactly_once_per_url(local):
    profile, data = local
    calls, intervals = [], []
    def fake_transport(policy, url, method):
        calls.append((url, method))
        return {"status": 200, "headers": [
            ("Set-Cookie", "token=DO-NOT-STORE"),
            ("Authorization", "top-secret"),
            ("Content-Type", "text/html"),
            ("Location", "https://evil.test/redirect"),
        ]}
    result = replay_har_head(profile, data, authorized=True,
                             transport=fake_transport, sleeper=intervals.append)
    assert len(calls) == 2
    assert all(method == "HEAD" for _, method in calls)
    assert intervals == [0.5]
    assert result["summary"]["requests_attempted"] == 2
    assert result["summary"]["confirmed_zero_days"] == 0
    as_json = json.dumps(result)
    for hidden in ["DO-NOT-STORE", "top-secret", "evil.test", "app.example.test"]:
        assert hidden not in as_json
    assert result["comparisons"][0]["observed_header_names"] == ["content-type"]


def test_out_of_scope_entry_aborts_all_network_before_any_calls(local):
    profile, data = local
    raw = json.loads(data.read_text())
    raw["observations"][1]["url"] = "https://out-of-scope.test/private"
    data.write_text(json.dumps(raw))
    calls = []
    with pytest.raises(ValueError, match="outside exact"):
        replay_har_head(profile, data, authorized=True,
            transport=lambda *a, **kw: calls.append(True))
    assert calls == []


def test_policy_hash_mismatch_aborts_before_network(local):
    profile, data = local
    raw = json.loads(data.read_text())
    raw["policy_sha256"] = "0" * 64
    data.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="exact approved"):
        replay_har_head(profile, data, authorized=True,
            transport=lambda *a, **kw: pytest.fail("Network attempted"))


@pytest.mark.parametrize("code", [401, 403, 405, 429, 500, 503])
def test_denied_or_unstable_endpoint_stops_immediately(local, code):
    profile, data = local
    seen = []
    def transport(policy, url, method):
        seen.append(url)
        return {"status": code, "headers": []}
    result = replay_har_head(profile, data, authorized=True,
                             transport=transport, sleeper=lambda _: None)
    assert len(seen) == 1
    assert result["summary"]["requests_attempted"] == 1


def test_no_authorization_flag_no_replay(local):
    profile, data = local
    with pytest.raises(PermissionError):
        replay_har_head(profile, data)


def test_replay_does_not_accept_original_raw_har(local):
    profile, data = local
    data.write_text(json.dumps({"log": {"entries": []}}))
    with pytest.raises(ValueError, match="sanitized"):
        replay_har_head(profile, data, authorized=True)


def test_replay_deduplicates_and_caps_total_requests(local):
    profile, data = local
    raw = json.loads(data.read_text())
    raw["observations"].append(raw["observations"][0])
    data.write_text(json.dumps(raw))
    hits = []
    replay_har_head(profile, data, authorized=True,
        transport=lambda policy, url, method: (hits.append(url) or {"status": 200, "headers": []}),
        sleeper=lambda _: None)
    assert len(hits) == 2
    raw["observations"].append({"url": "https://app.example.test/c", "status": 200})
    data.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="budget"):
        replay_har_head(profile, data, authorized=True,
            transport=lambda *a, **kw: pytest.fail("Exceeded budget"))


def test_baseline_status_must_be_integer(local):
    profile, data = local
    raw = json.loads(data.read_text())
    raw["observations"][0]["status"] = "200"
    data.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="baseline"):
        replay_har_head(profile, data, authorized=True)
