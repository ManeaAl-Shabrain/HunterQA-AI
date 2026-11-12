"""Fixed read API mock contracts, signing, scope and evidence; never actual AWS."""
import hashlib
import json
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest

from hunterqa import assessment_sessions, assessment_modes, aws_inventory as aws
from hunterqa.engagement import utcnow

pytest.importorskip("botocore", reason="Optional cloud signing dependency")
ACCOUNT = "123456789012"
TOKEN = "Public-owned-AWS-token-fixture-only"


@pytest.fixture
def owned(tmp_path, monkeypatch):
    root, private = tmp_path / "cases", tmp_path / "private"
    root.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(root))
    monkeypatch.setenv("HUNTERQA_ASSESSMENT_SECRET_ROOT", str(private))
    monkeypatch.delenv("HUNTERQA_QUOTA_LEDGER", raising=False)
    data = {"schema_version": 1, "provider": "aws", "account_id": ACCOUNT, "region": "us-east-1",
        "authorization_reference": "Owned AWS request shape fixture", "acknowledged_authorization": True,
        "expires_at": (utcnow() + timedelta(minutes=10)).isoformat(), "max_pages": 1, "page_size": 5,
        "max_resources": 100, "interval_seconds": 0.5, "timeout_seconds": 60}
    path, vault, key = root / "aws.json", private / "aws.json", private / "aws.key"
    path.write_text(json.dumps(data))
    headers = {"X-AWS-Access-Key-ID": "ASIA" + "A" * 16, "X-AWS-Secret-Access-Key": "B" * 40, "X-AWS-Session-Token": TOKEN}
    assessment_sessions.create(vault, key, json.dumps({"schema_version": 1, "expires_at": data["expires_at"], "actors": {
        name: {"origin": origin, "headers": headers, "cookies": [], "local_storage": {}} for name, origin in aws.targets(data).items()}}).encode(), authorized=True, purpose="aws-signing")
    return data, (path, vault, key), root


def response(action, *, account=ACCOUNT, region="us-east-1", next_token="", unsafe=True):
    if action == "GetCallerIdentity":
        body = f'<GetCallerIdentityResponse><GetCallerIdentityResult><Account>{account}</Account><Arn>arn:aws:sts::{account}:assumed-role/owned/reader</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>'
    elif action == "DescribeInstances":
        tokens = "optional" if unsafe else "required"
        body = f'<DescribeInstancesResponse><reservationSet><item><ownerId>{account}</ownerId><instancesSet><item><instanceId>i-01234567</instanceId><instanceState><name>running</name></instanceState><metadataOptions><httpTokens>{tokens}</httpTokens><httpEndpoint>enabled</httpEndpoint></metadataOptions></item></instancesSet></item></reservationSet><nextToken>{next_token}</nextToken></DescribeInstancesResponse>'
    elif action == "DescribeSecurityGroups":
        source = "0.0.0.0/0" if unsafe else "10.0.0.0/8"
        body = f'<DescribeSecurityGroupsResponse><securityGroupInfo><item><ownerId>{account}</ownerId><groupId>sg-01234567</groupId><ipPermissions><item><ipProtocol>tcp</ipProtocol><fromPort>22</fromPort><toPort>22</toPort><ipRanges><item><cidrIp>{source}</cidrIp></item></ipRanges></item></ipPermissions></item></securityGroupInfo></DescribeSecurityGroupsResponse>'
    else:
        body = f'<ListAllMyBucketsResult><Buckets><Bucket><Name>owned-fixture-bucket</Name><BucketRegion>{region}</BucketRegion></Bucket></Buckets><ContinuationToken>{next_token}</ContinuationToken></ListAllMyBucketsResult>'
    return {"status": 200, "body": body.encode()}


def execute(owned, mutate=None, *, evidence=False):
    data, paths, root = owned
    calls = []
    def transport(url, method, body, headers, **kwargs):
        kwargs["before_send"]()
        params = parse_qs(body.decode()) if body else parse_qs(urlsplit(url).query)
        action = params.get("Action", ["ListBuckets"])[0]
        calls.append((action, url, method, params, headers))
        value = response(action)
        return mutate(action, value) if mutate else value
    approval = aws.preflight(*paths)["approval_sha256"]
    result = aws.inventory(*paths, approval, authorized=True, transport=transport, sleeper=lambda _: None,
        evidence_dir=root / "raw" if evidence else None)
    return result, calls


def test_three_resource_kinds_reuse_existing_rules_with_redacted_verifiable_evidence(owned, monkeypatch):
    import botocore.session
    monkeypatch.setattr(botocore.session, "get_session", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("SDK discovery")))
    result, calls = execute(owned, evidence=True)
    assert result["execution_source"] == "DEMO" and result["synthetic"] and not result["real_provider_verified"]
    assert not result["stopped"] and result["account_context_matched"] and result["visible_pagination_exhausted"]
    assert [c[0] for c in calls] == ["GetCallerIdentity", *aws.ACTIONS]
    assert {r["kind"] for r in result["resources"]} == {"virtual-machine", "security-group", "storage-bucket"}
    assert {r["rule_id"] for r in result["findings"]} == {"cloud-review.aws.compute.imds-v2-required", "cloud-review.aws.network.internet-admin-ports"}
    text = json.dumps(result)
    assert TOKEN not in text and ACCOUNT not in text and "owned-fixture-bucket" not in text and "i-01234567" not in text
    assert all(any(k.lower() == "authorization" for k in call[4]) for call in calls)
    root = owned[2] / "raw"
    for receipt in result["receipts"]:
        assert hashlib.sha256((root / receipt["evidence_file"]).read_bytes()).hexdigest() == receipt["body_sha256"]
    shared = assessment_modes.envelope("cloud", "DEMO", result, [{"sha256": r["body_sha256"]} for r in result["receipts"]], origin="generated-synthetic")
    assert all(row["evidence_ids"] for row in shared["findings"])


def test_parameterized_safe_cloud_configuration_does_not_produce_selected_findings(owned):
    result, _ = execute(owned, lambda action, value: response(action, unsafe=False))
    assert not result["stopped"] and not result["findings"]


@pytest.mark.parametrize("action,expected_calls", [("GetCallerIdentity", 1), ("DescribeInstances", 2), ("DescribeSecurityGroups", 3)])
def test_wrong_account_stops_before_later_actions(owned, action, expected_calls):
    result, calls = execute(owned, lambda selected, value: response(selected, account="999999999999") if selected == action else value)
    assert result["stopped"] and result["error_type"] == "PermissionError" and len(calls) == expected_calls


def test_cross_region_s3_response_and_denied_apis_are_not_treated_as_secure(owned):
    result, _ = execute(owned, lambda action, value: response(action, region="us-west-2") if action == "ListBuckets" else value)
    assert result["stopped"] and result["error_type"] == "PermissionError"
    result, calls = execute(owned, lambda action, value: {"status": 403, "body": b"<Error/>"} if action == "DescribeInstances" else value)
    assert result["stopped"] and len(calls) == 2 and result["services"]["DescribeInstances"]["visible_pages_exhausted"] is False


@pytest.mark.parametrize("change", ["expiry", "region", "unknown", "page-size", "budget", "authorization"])
def test_contract_validation_precedes_any_traffic(owned, change):
    data, paths, _ = owned
    if change == "expiry":
        data["expires_at"] = (utcnow() - timedelta(seconds=1)).isoformat()
    elif change == "region":
        data["region"] = "us-east-1.attacker.test"
    elif change == "unknown":
        data["endpoint_url"] = "http://127.0.0.1"
    elif change == "page-size":
        data["page_size"] = 1000
    elif change == "budget":
        data["max_pages"] = 6
    else:
        data["acknowledged_authorization"] = False
    paths[0].write_text(json.dumps(data))
    with pytest.raises(ValueError):
        aws.preflight(*paths)


def test_authorization_stop_changed_scope_and_pagination_bounds(owned):
    data, paths, root = owned
    approval = aws.preflight(*paths)["approval_sha256"]
    with pytest.raises(PermissionError):
        aws.inventory(*paths, approval)
    with pytest.raises(PermissionError):
        aws.inventory(*paths, "0" * 64, authorized=True)
    (root / "stop").write_text("stop")
    result, calls = execute(owned)
    assert result["stopped"] and not calls
    (root / "stop").unlink()
    def changed(action, value):
        data["max_resources"] = 50
        paths[0].write_text(json.dumps(data))
        return value
    result, calls = execute(owned, changed)
    assert result["stopped"] and len(calls) == 1 and result["receipts"][0]["body_sha256"]
    result, calls = execute(owned, lambda action, value: response(action, next_token="opaque") if action == "DescribeInstances" else value)
    assert not result["stopped"] and result["services"]["DescribeInstances"]["outcome"] == "page-limit"
    assert not result["visible_pagination_exhausted"]


def test_xml_entities_and_unexpected_documents_are_rejected(owned):
    for raw in (b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>', b"<unexpected/>"):
        result, _ = execute(owned, lambda action, value: {"status": 200, "body": raw} if action == "DescribeInstances" else value)
        assert result["stopped"] and not result["resources"]


def test_signing_vault_cannot_be_loaded_as_web_session_even_after_metadata_stripping(owned):
    _, (_, vault, key), _ = owned
    with pytest.raises(ValueError):
        assessment_sessions.load(vault, key)
    with pytest.raises(ValueError):
        assessment_sessions.load(vault, key, purpose="directory-reader")
    wrapper = json.loads(vault.read_text())
    wrapper.pop("purpose")
    vault.write_text(json.dumps(wrapper))
    with pytest.raises(ValueError, match="context"):
        assessment_sessions.load(vault, key)
