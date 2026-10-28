"""Synthetic AWS API contracts only; no live cloud account is contacted."""
import hashlib
import json
from datetime import timedelta

import pytest

from hunterqa.cloud_account import TARGETS, credentials, execute_account
from hunterqa.engagement import utcnow
from hunterqa.workflow_network import inspect_network


@pytest.fixture
def request_data(tmp_path, monkeypatch):
    pytest.importorskip("botocore")
    pytest.importorskip("defusedxml")
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    scope = tmp_path / "account.json"
    scope.write_text(json.dumps({"schema_version": 1, "account_id": "123456789012"}))
    secrets = tmp_path / "aws-credentials.json"
    secrets.write_text(json.dumps({"access_key_id": "ASIA" + "A" * 16,
        "secret_access_key": "S" * 40, "session_token": "PRIVATE_SESSION_TOKEN_FIXTURE",
        "expires_at": (utcnow() + timedelta(hours=1)).isoformat()}))
    return {"policy": {"program": "Synthetic AWS fixture", "platform": "private",
        "authorization_reference": "Original offline synthetic cloud fixture authorization",
        "acknowledged_authorization": True, "allowed_hosts": ["sts.amazonaws.com", "iam.amazonaws.com"],
        "allowed_paths": ["/"], "methods": ["GET"], "allowed_ports": [443],
        "max_requests": 2, "interval_seconds": 0.5},
        "step": {"targets": TARGETS[:], "requests": 2},
        "binding": {"file": str(scope), "secret_file": str(secrets),
            "secret_file_sha256": hashlib.sha256(secrets.read_bytes()).hexdigest()},
        "network_log": str(tmp_path / "network.jsonl"), "interval_seconds": 0.5}


def response(body, status=200):
    return {"status": status, "headers": [("Content-Type", "text/xml")], "body": body.encode()}


def identity(account="123456789012"):
    return response(f'<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
        f'<GetCallerIdentityResult><Account>{account}</Account><Arn>arn:aws:sts::{account}:assumed-role/fixture/test</Arn>'
        '</GetCallerIdentityResult></GetCallerIdentityResponse>')


def summary(counters):
    entries = "".join(f"<entry><key>{k}</key><value>{v}</value></entry>" for k, v in counters.items())
    return response('<GetAccountSummaryResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">'
        f'<GetAccountSummaryResult><SummaryMap>{entries}</SummaryMap></GetAccountSummaryResult></GetAccountSummaryResponse>')


@pytest.mark.parametrize("counters,rules", [
    ({"AccountMFAEnabled": 1, "AccountPasswordPresent": 1, "AccountAccessKeysPresent": 0}, set()),
    ({"AccountMFAEnabled": 0, "AccountPasswordPresent": 1, "AccountAccessKeysPresent": 1},
     {"cloud.aws.root-mfa-review", "cloud.aws.root-keys-review"}),
    ({"AccountMFAEnabled": 0, "AccountPasswordPresent": 0, "AccountAccessKeysPresent": 0}, set()),
])
def test_only_fixed_read_apis_are_signed_and_secret_free(request_data, counters, rules):
    calls = []

    def transport(policy, target, method, *, body, headers):
        assert target == TARGETS[len(calls)] and method == "POST"
        assert headers["Authorization"].startswith("AWS4-HMAC-SHA256 ")
        assert headers["X-Amz-Security-Token"] == "PRIVATE_SESSION_TOKEN_FIXTURE"
        calls.append(body)
        return identity() if len(calls) == 1 else summary(counters)

    result = execute_account(request_data, transport=transport, sleeper=lambda _: None)
    assert calls == [b"Action=GetCallerIdentity&Version=2011-06-15", b"Action=GetAccountSummary&Version=2010-05-08"]
    assert result["cloud_summary"]["identity_matched"] and result["cloud_summary"]["summary_observed"]
    assert {row["rule_id"] for row in result["findings"]} == rules
    assert "PRIVATE_SESSION_TOKEN_FIXTURE" not in json.dumps(result)
    assert "ASIA" + "A" * 16 not in json.dumps(result)
    assert all(row["verification_status"] == "unverified" for row in result["findings"])
    from pathlib import Path
    journal = inspect_network(Path(request_data["network_log"]), TARGETS, transport="aws-query")
    assert journal["intents"] == journal["responses"] == 2
    with pytest.raises(ValueError, match="method"):
        inspect_network(Path(request_data["network_log"]), TARGETS)


def test_wrong_account_stops_before_iam(request_data):
    calls = []

    def transport(*args, **kwargs):
        calls.append(args[1])
        return identity("999999999999")

    result = execute_account(request_data, transport=transport)
    assert calls == TARGETS[:1]
    assert result["safety_stop"] and not result["cloud_summary"]["identity_matched"]
    assert not result["cloud_summary"]["summary_observed"] and not result["findings"]


@pytest.mark.parametrize("status", [302, 403, 429, 503])
def test_failure_stops_without_retry_or_redirect(request_data, status):
    calls = []

    def transport(*args, **kwargs):
        calls.append(args[1])
        return response("private error details must not appear in reports", status)

    result = execute_account(request_data, transport=transport)
    assert len(calls) == 1 and result["safety_stop"]
    assert "private error details" not in json.dumps(result)


def test_secret_rotation_between_requests_stops_before_next_api(request_data):
    from pathlib import Path
    path = Path(request_data["binding"]["secret_file"])
    calls = []

    def transport(*args, **kwargs):
        calls.append(args[1])
        path.write_text("{}")
        return identity()

    with pytest.raises(PermissionError, match="changed"):
        execute_account(request_data, transport=transport, sleeper=lambda _: None)
    assert len(calls) == 1


def test_xml_entities_are_rejected_without_network_expansion(request_data):
    from defusedxml.common import EntitiesForbidden
    xml = '<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///private">]><x>&secret;</x>'
    with pytest.raises(EntitiesForbidden):
        execute_account(request_data, transport=lambda *args, **kwargs: response(xml))


def test_long_lived_keys_and_expired_sessions_are_rejected(request_data):
    from pathlib import Path
    path = Path(request_data["binding"]["secret_file"])
    value = json.loads(path.read_text())
    value["access_key_id"] = "AKIA" + "A" * 16
    path.write_text(json.dumps(value))
    binding = {**request_data["binding"], "secret_file_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    with pytest.raises(ValueError, match="temporary"):
        credentials(binding)
    value["access_key_id"] = "ASIA" + "A" * 16
    value["expires_at"] = (utcnow() - timedelta(seconds=1)).isoformat()
    path.write_text(json.dumps(value))
    binding["secret_file_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(PermissionError, match="expire"):
        credentials(binding)


def test_cloud_setup_is_offline_and_binds_fixed_endpoints_without_secrets(request_data, tmp_path):
    from hunterqa.assessment_setup import setup_assessment
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps(request_data["policy"]))
    review = setup_assessment(profile, "aws-account-audit", tmp_path / "config",
        input_file=request_data["binding"]["file"], secret_file=request_data["binding"]["secret_file"], authorized=True)
    protocol = json.loads((tmp_path / "config" / "protocol.json").read_text())
    assert protocol["steps"][0]["targets"] == TARGETS
    assert review["preflight"]["network_requests"] == 0
    assert "PRIVATE_SESSION_TOKEN_FIXTURE" not in json.dumps(review)
    assert review["preflight"]["pending_checkpoints"] == ["assess"]
