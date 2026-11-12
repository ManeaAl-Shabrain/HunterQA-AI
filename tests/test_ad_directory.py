"""Mock LDAP semantics separately from actual owned TLS credential confinement."""
import json
from datetime import timedelta
from types import SimpleNamespace

import pytest

from hunterqa import ad_directory as ad, assessment_sessions
from hunterqa.engagement import digest, utcnow
from tests.test_tls_inspection import certificates as certificates, server

pytest.importorskip("ldap3", reason="Optional directory connector dependency")


@pytest.fixture
def owned(tmp_path, monkeypatch):
    approved, private = tmp_path / "inputs", tmp_path / "private"
    approved.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(approved))
    monkeypatch.setenv("HUNTERQA_ASSESSMENT_SECRET_ROOT", str(private))
    monkeypatch.delenv("HUNTERQA_QUOTA_LEDGER", raising=False)
    vault, key = private / "directory.json", private / "directory.key"
    data = {"schema_version": 1, "authorization_reference": "Owned directory reader fixture", "acknowledged_authorization": True,
        "expires_at": (utcnow() + timedelta(minutes=10)).isoformat(), "server_ip": "127.0.0.1", "server_port": 636,
        "allow_private_network": True, "mode": "LAB", "tls_server_name": "localhost", "base_dn": "DC=owned,DC=test",
        "ca_file": None, "max_pages": 2, "page_size": 50, "timeout_seconds": 10, "minimum_password_length": 14}
    plan = approved / "directory.json"
    def configure(**changes):
        data.update(changes)
        plan.write_text(json.dumps(data))
        if not vault.exists():
            assessment_sessions.create(vault, key, json.dumps({"schema_version": 1, "expires_at": data["expires_at"], "actors": {
                "directory": {"origin": f'https://localhost:{data["server_port"]}', "headers": {
                    "X-LDAP-Bind-DN": "CN=reader,CN=Users,DC=owned,DC=test", "Authorization": "Public-directory-fixture-2026!"},
                    "cookies": [], "local_storage": {}}}}).encode(), authorized=True)
        return plan, vault, key
    configure()
    return data, configure, (plan, vault, key)


def entries():
    return [{"type": "searchResEntry", "dn": "DC=owned,DC=test", "raw_attributes": {
        "objectClass": [b"top", b"domainDNS"], "minPwdLength": [b"7"], "lockoutThreshold": [b"0"]}},
        {"type": "searchResEntry", "dn": "CN=sample,CN=Users,DC=owned,DC=test", "raw_attributes": {
            "objectClass": [b"top", b"user"], "userAccountControl": [b"544"], "adminCount": [b"1"], "memberOf": [b"CN=Readers,DC=owned,DC=test"]}}]


def test_normalized_actual_attribute_analysis_reuses_existing_account_rules():
    snapshot = {"schema_version": 1, "collected_at": utcnow().isoformat(), "entries": ad.normalize(entries()), "minimum_password_length": 14}
    report = ad.analyze(snapshot)
    rules = {r["rule_id"] for r in report["findings"]}
    assert rules >= {"ad-review.password-not-required", "ad-directory.password-length-policy", "ad-directory.lockout-policy-review", "ad-directory.protected-account-review"}
    assert report["inventory"]["accounts"] == report["inventory"]["domains"] == 1
    assert "CN=sample" not in json.dumps(snapshot) + json.dumps(report)
    assert snapshot["entries"][1]["id"] == digest("cn=sample,cn=users,dc=owned,dc=test")
    snapshot["entries"][0]["attributes"]["minpwdlength"] = 20
    snapshot["entries"][0]["attributes"]["lockoutthreshold"] = 5
    snapshot["entries"][1]["attributes"].update(useraccountcontrol=512, admincount=0)
    assert not ad.analyze(snapshot)["findings"]


@pytest.mark.parametrize("change", ["scope", "expiry", "public-lab", "pages", "page-size", "mode", "unknown", "plaintext"])
def test_invalid_scope_rejected_without_connecting(owned, monkeypatch, change):
    import ldap3
    data, configure, paths = owned
    def no_connect(*args, **kwargs):
        raise AssertionError("Invalid scope connected")
    monkeypatch.setattr(ldap3, "Connection", no_connect)
    if change == "scope":
        data["base_dn"] = "DC=owned,DC=test)(objectClass=*)"
    elif change == "expiry":
        data["expires_at"] = (utcnow() - timedelta(seconds=1)).isoformat()
    elif change == "public-lab":
        data["server_ip"] = "8.8.8.8"
    elif change == "pages":
        data["max_pages"] = 6
    elif change == "page-size":
        data["page_size"] = True
    elif change == "mode":
        data["mode"] = "DEMO"
    elif change == "unknown":
        data["follow_referrals"] = True
    else:
        data["tls_server_name"] = "ldap://localhost"
    configure()
    with pytest.raises(ValueError):
        ad.preflight(*paths)


def test_mock_collection_refuses_referrals_and_automatic_queries(owned, monkeypatch):
    import ldap3
    data, _, paths = owned
    options, calls = {}, []
    class Fake:
        def __init__(self, server, **kwargs):
            options.update(kwargs)
            self.strategy = SimpleNamespace(close=lambda: calls.append("close"))
            self.result, self.response = {}, []
            self.socket = None
        def open(self, **kwargs):
            calls.append("open")
        def bind(self):
            calls.append("bind")
            return True
        def search(self, base, query, scope, **kwargs):
            calls.append((base, query, kwargs))
            self.result = {"result": 0}
            self.response = [{"type": "searchResEntry", "raw_attributes": {"defaultNamingContext": [data["base_dn"].encode()]}}] if not base else entries()
    monkeypatch.setattr(ldap3, "Connection", Fake)
    approval = ad.preflight(*paths)["approval_sha256"]
    snapshot, receipt = ad.collect(*paths, approval, authorized=True)
    assert receipt["complete"] and receipt["operations"] == 4 and receipt["pages"] == 1
    assert len(snapshot["entries"]) == 2
    assert options["read_only"] and not options["auto_referrals"] and not options["auto_range"] and not options["use_referral_cache"]
    assert all(call[2]["dereference_aliases"] == ldap3.DEREF_NEVER for call in calls if isinstance(call, tuple))
    assert calls[-2][2]["controls"] == [("1.2.840.113556.1.4.1339", True, None)]
    assert calls[-1] == "close" and not receipt["real_provider_verified"]


def test_stop_and_contract_approval_precede_network(owned, monkeypatch):
    import ldap3
    _, _, paths = owned
    def no_connect(*args, **kwargs):
        raise AssertionError("Stopped directory connected")
    monkeypatch.setattr(ldap3, "Connection", no_connect)
    approval = ad.preflight(*paths)["approval_sha256"]
    with pytest.raises(PermissionError):
        ad.collect(*paths, approval)
    with pytest.raises(PermissionError):
        ad.collect(*paths, "0" * 64, authorized=True)
    (paths[0].parent / "stop").write_text("stop")
    snapshot, receipt = ad.collect(*paths, approval, authorized=True)
    assert receipt["operations"] == 0 and receipt["error_type"] == "PermissionError" and not snapshot["entries"]


@pytest.mark.parametrize("variant", ["valid", "mismatch", "expired"])
def test_actual_tls_gates_credential_transmission_but_does_not_claim_ad_validation(owned, certificates, variant):
    data, configure, paths = owned
    # Change the fresh vault origin to the ephemeral server's exact port.
    paths[1].unlink()
    with server(certificates, variant) as (port, received, sni):
        ca = paths[0].parent / "ca.pem"
        ca.write_bytes(certificates["ca"])
        configure(server_port=port, ca_file=str(ca))
        approval = ad.preflight(*paths)["approval_sha256"]
        _, receipt = ad.collect(*paths, approval, authorized=True)
    assert not receipt["complete"] and receipt["error_type"] and not receipt["real_provider_verified"]
    if variant == "valid":
        assert received and b"Public-directory-fixture-2026!" in b"".join(received)
    else:
        assert not received
    assert sni == ["localhost"]
