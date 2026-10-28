import json
import pytest

from hunterqa.bounty import assess


@pytest.fixture
def profile_and_targets(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    profile = tmp_path / "policy.json"
    profile.write_text(json.dumps({
        "program": "Authorized test server", "platform": "local-lab",
        "authorization_reference": "Explicit owned fixture approval",
        "acknowledged_authorization": True, "allowed_hosts": ["app.example.test"],
        "methods": ["HEAD"], "max_requests": 3, "interval_seconds": 0.5,
    }))
    targets = tmp_path / "targets.txt"
    targets.write_text("https://app.example.test/a\nhttps://app.example.test/b\n")
    return profile, targets


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_fail_closed_stops_on_denial_and_server_instability(profile_and_targets, status):
    policy, targets = profile_and_targets
    hits = []
    def fake_transport(profile, url, method):
        hits.append(url)
        return {"url": url, "method": method, "status": status, "headers": []}
    result = assess(policy, targets, method="HEAD", authorized=True,
                    transport=fake_transport, sleeper=lambda _: None)
    assert len(hits) == 1
    assert len(result["observations"]) == 1
    assert result["observations"][0]["status"] == status


def test_success_still_respects_single_request_per_allowed_url(profile_and_targets):
    policy, targets = profile_and_targets
    hits = []
    pauses = []
    def fake_transport(profile, url, method):
        hits.append(url)
        return {"url": url, "method": method, "status": 200, "headers": []}
    result = assess(policy, targets, method="HEAD", authorized=True,
                    transport=fake_transport, sleeper=pauses.append)
    assert len(hits) == 2
    assert len(pauses) == 1
    assert pauses[0] >= 0.5
    assert result["claims"]["confirmed_zero_days"] == 0
