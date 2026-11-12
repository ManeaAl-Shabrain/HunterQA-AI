"""Encrypted temporary token sources; all provider responses here are synthetic."""
import json
from datetime import timedelta

import pytest

from hunterqa import assessment_sessions as sessions, assessment_collect, azure_inventory, gcp_inventory, gcp_permissions
from hunterqa.cloud_inventory_common import token_provider
from hunterqa.engagement import utcnow

TOKEN = "synthetic-token-01234567890123456789"
SUB = "11111111-2222-3333-4444-555555555555"
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


@pytest.fixture
def roots(tmp_path, monkeypatch):
    source, secret = tmp_path / "source", tmp_path / "secret"
    source.mkdir(mode=0o700)
    secret.mkdir(mode=0o700)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(source))
    monkeypatch.setenv("HUNTERQA_ASSESSMENT_SECRET_ROOT", str(secret))
    monkeypatch.delenv("HUNTERQA_OPERATOR_ROOT", raising=False)
    monkeypatch.delenv("HUNTERQA_QUOTA_LEDGER", raising=False)
    return source, secret


def vault(roots, provider, *, origin=None, token=TOKEN, name="vault"):
    hosts = {"azure-arm": "https://management.azure.com"} if provider == "azure" else {
        "gcp-context": "https://cloudresourcemanager.googleapis.com", "gcp-assets": "https://cloudasset.googleapis.com"}
    data = {"schema_version": 1, "expires_at": (utcnow() + timedelta(minutes=10)).isoformat(), "actors": {
        key: {"origin": origin or host, "headers": {"Authorization": token}, "cookies": [], "local_storage": {}}
        for key, host in hosts.items()}}
    path, key = roots[1] / (name + ".json"), roots[1] / "key"
    sessions.create(path, key, json.dumps(data).encode(), authorized=True, purpose=provider + "-token")
    return path, key


@pytest.mark.parametrize("provider", ["azure", "gcp"])
def test_token_stays_encrypted_and_cannot_be_used_as_web_session(roots, provider):
    path, key = vault(roots, provider)
    raw, binding = token_provider(provider, path, key)()
    assert json.loads(raw)["access_token"] == TOKEN and len(binding) == 64
    assert TOKEN not in path.read_text() and TOKEN not in key.read_text()
    with pytest.raises(ValueError):
        sessions.load(path, key)
    other = "gcp" if provider == "azure" else "azure"
    with pytest.raises(ValueError):
        token_provider(other, path, key)()


@pytest.mark.parametrize("provider", ["azure", "gcp"])
def test_origin_or_bearer_header_prefix_is_rejected(roots, provider):
    path, key = vault(roots, provider, origin="https://unapproved.invalid")
    with pytest.raises(ValueError):
        token_provider(provider, path, key)()
    path, key = vault(roots, provider, token="Bearer " + TOKEN, name="prefixed")
    with pytest.raises(ValueError):
        token_provider(provider, path, key)()


def test_encrypted_azure_source_is_rechecked_before_next_request(roots):
    path, key = vault(roots, "azure")
    source = roots[0] / "contract.json"
    source.write_text(json.dumps({"schema_version": 1, "provider": "azure", "subscription_id": SUB, "tenant_id": TENANT,
        "authorization_reference": "Owned synthetic contract", "acknowledged_authorization": True,
        "expires_at": (utcnow() + timedelta(minutes=5)).isoformat(), "max_pages": 1,
        "page_size": 2, "max_resources": 4, "interval_seconds": 0.5}))
    calls = []
    def transport(target, token, *, before_send):
        before_send()
        assert token == TOKEN
        calls.append(target)
        # Rotate the encrypted document without changing its valid token.
        data, _ = sessions.load_document(path, key, purpose="azure-token")
        from hunterqa.identity_policy import seal
        wrapper = {"schema_version": 1, "purpose": "azure-token", "ciphertext": seal(key.read_text().strip(), sessions.PURPOSES["azure-token"], data)}
        path.write_text(json.dumps(wrapper))
        return {"status": 200, "body": json.dumps({"id": "/subscriptions/" + SUB, "subscriptionId": SUB, "tenantId": TENANT}).encode()}
    result = azure_inventory.inventory(source, None, authorized=True, credential_provider=token_provider("azure", path, key),
        transport=transport, sleeper=lambda _: None)
    assert len(calls) == 1 and result["outcome"] == "authorization-stopped"
    assert result["synthetic"] and result["execution_source"] == "DEMO" and not result["real_provider_verified"]
    assert TOKEN not in json.dumps(result)


@pytest.mark.parametrize("permission_query", [False, True])
def test_encrypted_gcp_source_uses_original_read_only_collectors(roots, permission_query):
    path, key = vault(roots, "gcp")
    data = {"schema_version": 1, "provider": "gcp", "project_id": "owned-fixture-123", "project_number": "123456789012",
        "expected_parent": None, "authorization_reference": "Owned synthetic contract", "acknowledged_authorization": True,
        "expires_at": (utcnow() + timedelta(minutes=5)).isoformat(), "interval_seconds": 0.5}
    if permission_query:
        data["permissions"] = ["resourcemanager.projects.get"]
    else:
        data.update(max_pages=1, page_size=2, max_resources=4, read_time=(utcnow() - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    source = roots[0] / "contract.json"
    source.write_text(json.dumps(data))
    def get(target, token, *, before_send):
        before_send()
        assert token == TOKEN
        body = {"name": "projects/123456789012", "projectId": "owned-fixture-123", "state": "ACTIVE"} if "cloudresourcemanager" in target else {"assets": [], "readTime": data["read_time"]}
        return {"status": 200, "body": json.dumps(body).encode()}
    def post(number, permissions, token, *, before_send):
        before_send()
        assert token == TOKEN
        return {"status": 200, "body": json.dumps({"permissions": permissions}).encode()}
    options = {"authorized": True, "credential_provider": token_provider("gcp", path, key), "sleeper": lambda _: None}
    result = gcp_permissions.check_permissions(source, None, context_transport=get, permission_transport=post, **options) if permission_query else gcp_inventory.inventory(source, None, transport=get, **options)
    assert result["requests_completed"] == 2 and result["execution_source"] == "DEMO" and result["synthetic"]
    assert not result["real_provider_verified"] and TOKEN not in json.dumps(result)


def test_shared_facade_selects_one_credential_source(roots, monkeypatch):
    path, key = vault(roots, "azure")
    def delegate(source, credentials, *, authorized, credential_provider):
        assert credentials is None and authorized
        assert json.loads(credential_provider()[0])["access_token"] == TOKEN
        return {"synthetic": True}
    monkeypatch.setattr(azure_inventory, "inventory", delegate)
    assert assessment_collect.execute("azure-inventory", "contract", mode="LIVE", authorized=True, session_file=path, session_key=key)["synthetic"]
    with pytest.raises(ValueError):
        assessment_collect.execute("azure-inventory", "contract", mode="LIVE", authorized=True, credentials="ambiguous", session_file=path, session_key=key)
