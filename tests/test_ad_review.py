"""Owned synthetic declarations only; no Windows domain or security tool needed."""
import copy
import hashlib
import json
from datetime import datetime, timezone

import pytest

from hunterqa.ad_review import MAX_BYTES, SECTIONS, review_evidence, review_file
from hunterqa.cli import main

NOW = datetime(2026, 10, 29, 12, tzinfo=timezone.utc)


def evidence():
    return {"schema_version": 1, "collected_at": "2026-10-29T11:00:00Z",
        "accounts": [{"id": "account-one", "enabled": True, "kind": "user", "tier0": False,
            "is_domain_controller": False, "user_account_control": 512, "spn_count": 0}],
        "domain_controllers": [{"id": "dc-one", "smb_signing_required": True,
            "ldap_signing_required": True, "ldap_channel_binding": "always", "smb1_enabled": False}],
        "acl_grants": [{"id": "grant-one", "principal_tier": "ordinary", "target_tier": "tier0",
            "target_kind": "domain", "effect": "allow", "rights": []}],
        "certificate_templates": [{"id": "template-one", "published": True, "broad_enrollment": False,
            "enrollee_supplies_subject": False, "authentication_eku": True,
            "manager_approval": True, "authorized_signatures": 1}],
        "trusts": [{"id": "trust-one", "kind": "external", "sid_filtering_enabled": True, "selective_authentication": True}],
        "hybrid_accounts": [{"id": "hybrid-one", "enabled": True, "synchronized": True,
            "on_prem_privileged": True, "entra_privileged": False}]}


def rules(data):
    return {f["rule_id"] for f in review_evidence(data, now=NOW)["findings"]}


def test_quiet_declared_fixture_is_not_domain_security_proof():
    report = review_evidence(evidence(), now=NOW)
    assert not report["findings"]
    assert report["network_requests"] == report["external_tools_executed"] == 0
    assert not report["all_skills_automated"]
    assert report["real_world_effectiveness"] == "unverified"
    assert report["evidence_freshness"] == "within-24h-declared"
    assert {s["id"] for s in report["skills"]} == {"offensive-active-directory", "offensive-netexec"}
    assert all(s["status"] == "partial-offline-review" for s in report["skills"])


@pytest.mark.parametrize("flag,key", [
    (0x400000, "preauth-disabled"), (0x20, "password-not-required"),
    (0x80, "reversible-storage"), (0x200000, "des-only"),
    (0x10000, "password-never-expires"), (0x80000, "unconstrained-delegation"),
    (0x1000000, "protocol-transition"),
])
def test_account_bit_flags_and_disabled_negative_control(flag, key):
    data = evidence()
    account = data["accounts"][0]
    account["user_account_control"] |= flag
    assert rules(data) == {"ad-review." + key}
    account["enabled"] = False
    account["user_account_control"] |= 2
    assert not rules(data)


def test_dc_and_managed_service_exceptions_and_privilege_context():
    data = evidence()
    account = data["accounts"][0]
    account.update(kind="computer", is_domain_controller=True, user_account_control=0x80000)
    assert not rules(data)
    account.update(kind="gmsa", is_domain_controller=False, user_account_control=0x10000)
    assert not rules(data)
    account.update(kind="service", tier0=True, spn_count=1, user_account_control=512)
    assert rules(data) == {"ad-review.tier0-delegation-protection", "ad-review.privileged-service-identity"}
    account["user_account_control"] |= 0x100000
    assert rules(data) == {"ad-review.privileged-service-identity"}


def test_conflicting_account_state_does_not_emit_speculative_account_flags():
    data = evidence()
    data["accounts"][0]["user_account_control"] = 2 | 0x400000
    assert rules(data) == {"ad-review.account-state-conflict"}
    data["accounts"][0].update(enabled=False, user_account_control=512)
    assert rules(data) == {"ad-review.account-state-conflict"}


@pytest.mark.parametrize("field,value,key", [
    ("smb_signing_required", False, "smb-signing"),
    ("ldap_signing_required", False, "ldap-signing"),
    ("ldap_channel_binding", "never", "ldap-channel-binding"),
    ("ldap_channel_binding", "when-supported", "ldap-channel-binding-conditional"),
    ("smb1_enabled", True, "smb1"),
])
def test_domain_controller_policy_cues(field, value, key):
    data = evidence()
    data["domain_controllers"][0][field] = value
    report = review_evidence(data, now=NOW)
    assert {f["rule_id"] for f in report["findings"]} == {"ad-review." + key}
    assert report["findings"][0]["skill"] == "offensive-netexec"


@pytest.mark.parametrize("right", ["GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "AddMember", "WriteSPN", "ForceChangePassword"])
def test_selected_acl_grant_is_not_effective_access_proof(right):
    data = evidence()
    grant = data["acl_grants"][0]
    grant["rights"] = [right]
    assert rules(data) == {"ad-review.tier0-acl-grant"}
    grant["effect"] = "deny"
    assert not rules(data)
    grant["effect"] = "unknown"
    assert not rules(data)


def test_replication_pair_requires_selected_domain_allow_grant():
    data = evidence()
    grant = data["acl_grants"][0]
    grant["rights"] = ["ReplicatingDirectoryChanges", "ReplicatingDirectoryChangesAll"]
    assert rules(data) == {"ad-review.replication-grant"}
    grant["target_kind"] = "group"
    assert not rules(data)
    grant["target_kind"] = "domain"
    grant["rights"].pop()
    assert not rules(data)


@pytest.mark.parametrize("break_field,break_value", [("published", False), ("broad_enrollment", False), ("enrollee_supplies_subject", False), ("authentication_eku", False), ("manager_approval", True), ("authorized_signatures", 1)])
def test_certificate_compound_cue_and_negative_prerequisites(break_field, break_value):
    data = evidence()
    template = data["certificate_templates"][0]
    template.update(published=True, broad_enrollment=True, enrollee_supplies_subject=True,
        authentication_eku=True, manager_approval=False, authorized_signatures=0)
    assert rules(data) == {"ad-review.certificate-enrollment-review"}
    template[break_field] = break_value
    assert not rules(data)
    template[break_field] = None
    assert not rules(data)


def test_trust_and_hybrid_declarations_keep_context():
    data = evidence()
    trust = data["trusts"][0]
    trust.update(sid_filtering_enabled=False, selective_authentication=False)
    data["hybrid_accounts"][0]["entra_privileged"] = True
    assert rules(data) == {"ad-review.trust-sid-filtering", "ad-review.trust-authentication-scope", "ad-review.hybrid-dual-privilege"}
    trust["kind"] = "intra-forest"
    data["hybrid_accounts"][0]["synchronized"] = None
    assert not rules(data)


def test_all_unknown_records_and_missing_sections_remain_unassessed():
    data = evidence()
    for section, (_, fields) in SECTIONS.items():
        data[section] = [{"id": section.replace("_", "-"), **{k: None for k in fields}}]
    report = review_evidence(data, now=NOW)
    assert not report["findings"]
    assert all(o["status"] == "insufficient-evidence" for o in report["observations"])
    assert all(s["status"] == "insufficient-evidence" for s in report["skills"])
    data["domain_controllers"] = []
    report = review_evidence(data, now=NOW)
    assert report["skills"][1]["status"] == "not-assessed"
    assert report["sections"]["domain_controllers"]["status"] == "not-assessed"


@pytest.mark.parametrize("timestamp,expected", [(None, "unknown"), ("2026-10-20T00:00:00Z", "older-than-24h-review"), ("2026-10-30T00:00:00Z", "future-clock-review"), ("2026-10-29T14:00:00+03:00", "within-24h-declared")])
def test_declared_collection_freshness(timestamp, expected):
    data = evidence()
    data["collected_at"] = timestamp
    assert review_evidence(data, now=NOW)["evidence_freshness"] == expected


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(schema_version=True),
    lambda d: d.update(domain="PRIVATE-FIXTURE"),
    lambda d: d.update(collected_at="PRIVATE-FIXTURE"),
    lambda d: d["accounts"][0].update(password="PRIVATE-FIXTURE"),
    lambda d: d["accounts"][0].update(enabled=1),
    lambda d: d["accounts"][0].update(user_account_control=True),
    lambda d: d["accounts"][0].update(user_account_control=-1),
    lambda d: d["domain_controllers"][0].update(id="account-one"),
    lambda d: d["acl_grants"][0].update(rights=["GenericAll", "GenericAll"]),
    lambda d: d["acl_grants"][0].update(rights=["ExecutePayload"]),
    lambda d: d["accounts"][0].pop("kind"),
    lambda d: d.update(accounts=[copy.deepcopy(d["accounts"][0])] * 201),
    lambda d: d.update(**{k: [] for k in SECTIONS}),
])
def test_schema_rejects_secrets_unknown_fields_and_bad_bounds(mutate):
    data = evidence()
    mutate(data)
    with pytest.raises(ValueError) as exc:
        review_evidence(data, now=NOW)
    assert "PRIVATE-FIXTURE" not in str(exc.value)


def test_findings_cap_is_visible_and_does_not_skip_observations(monkeypatch):
    import hunterqa.ad_review as module
    monkeypatch.setattr(module, "MAX_FINDINGS", 1)
    data = evidence()
    data["accounts"][0]["user_account_control"] |= 0x20 | 0x80
    report = review_evidence(data, now=NOW)
    assert report["truncated"] and report["candidates_not_retained"] == 1
    assert len(report["findings"]) == 1 and len(report["observations"]) == 6


def test_review_never_queries_network_or_executes_tools(monkeypatch):
    import socket
    import subprocess
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: pytest.fail("No network"))
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("No external tools"))
    report = review_evidence(evidence(), now=NOW)
    assert not report["findings"]
    serialized = json.dumps(report)
    assert '"user_account_control"' not in serialized  # Known source values are not copied.
    assert '"smb_signing_required"' not in serialized


def test_cli_scope_authorization_create_only_exact_receipt_and_sarif(tmp_path, monkeypatch, capsys):
    from hunterqa.sarif_export import export_sarif
    path, output = tmp_path / "evidence.json", tmp_path / "report.json"
    data = evidence()
    data["accounts"][0]["user_account_control"] |= 0x20
    second = copy.deepcopy(data["accounts"][0])
    second["id"] = "account-two"
    data["accounts"].append(second)
    raw = json.dumps(data).encode()
    path.write_bytes(raw)
    with pytest.raises(PermissionError):
        review_file(path)
    monkeypatch.delenv("HUNTERQA_APPROVED_ROOTS", raising=False)
    with pytest.raises(ValueError):
        review_file(path, authorized=True)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    args = ["ad-review", "--input", str(path), "--out", str(output), "--authorized"]
    main(args)
    report = json.loads(output.read_text())
    assert report["input_sha256"] == hashlib.sha256(raw).hexdigest()
    assert path.read_bytes() == raw
    assert all(f["verification_status"] == "unverified" for f in report["findings"])
    sarif = export_sarif(output)["runs"][0]["results"]
    assert {r["properties"]["assessmentCase"] for r in sarif} == {"account-one", "account-two"}
    assert sarif[0]["partialFingerprints"] != sarif[1]["partialFingerprints"]
    with pytest.raises(FileExistsError):
        main(args)
    capsys.readouterr()
    main(["ad-review-catalog"])
    assert len(json.loads(capsys.readouterr().out)["skills"]) == 2


@pytest.mark.parametrize("raw", [b'{', b'{"id":1,"id":2}', b'{"value":NaN}', b'\xff'])
def test_malformed_json_messages_withhold_contents(tmp_path, monkeypatch, raw):
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    with pytest.raises(ValueError, match="contents withheld"):
        review_file(path, authorized=True)


def test_oversize_and_outside_input_output_rejected(tmp_path, monkeypatch):
    private = tmp_path / "private"
    private.mkdir()
    path = private / "input.json"
    path.write_text(json.dumps(evidence()))
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(private))
    with pytest.raises(ValueError):
        main(["ad-review", "--input", str(path), "--out", str(tmp_path / "outside.json"), "--authorized"])
    outside = tmp_path / "outside-input.json"
    outside.write_text(json.dumps(evidence()))
    with pytest.raises(ValueError):
        review_file(outside, authorized=True)
    path.write_bytes(b" " * (MAX_BYTES + 1))
    with pytest.raises(ValueError):
        review_file(path, authorized=True)


def test_published_template_reports_insufficient_evidence():
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "templates" / "HunterQA-ad-review-template.json"
    report = review_evidence(json.loads(path.read_text()), now=NOW)
    assert not report["findings"]
    assert report["evidence_freshness"] == "unknown"
    assert all(s["status"] == "insufficient-evidence" for s in report["skills"])


def test_symlinked_evidence_rejected(tmp_path, monkeypatch):
    path = tmp_path / "source.json"
    path.write_text(json.dumps(evidence()))
    link = tmp_path / "link.json"
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    try:
        link.symlink_to(path)
    except OSError:
        pytest.skip("OS does not allow creating symlinks")
    with pytest.raises(ValueError, match="Symlink"):
        review_file(link, authorized=True)
