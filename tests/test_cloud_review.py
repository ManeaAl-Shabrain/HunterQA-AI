"""Synthetic cloud JSON and declared policy controls; no cloud accounts needed."""
import copy
import hashlib
import json

import pytest

from hunterqa.cli import main
from hunterqa.cloud_review import COMMON, MAX_BYTES, PROVIDERS, fields_for, review_evidence, review_file

QUIET = {
    "identity": {"principal_kind": "human", "privileged": False, "mfa_enforced": True, "long_lived_keys_present": False},
    "storage": {"public_access": False, "encrypted_at_rest": True, "https_only": True, "access_logging": True},
    "network": {"internet_admin_ports": False, "public_database_endpoint": False, "flow_logs_enabled": True},
    "audit": {"control_plane_logging": True, "data_access_logging": True, "retention_reviewed": True, "log_protection_reviewed": True},
    "federation": {"issuer_validated": True, "audience_restricted": True, "subject_restricted": True, "trust_scope_reviewed": True},
    "permissions": {"wildcard_actions_allowed": False, "unrestricted_resources": False, "privileged_assignment": False, "assignment_scope_reviewed": True},
}
CHANGED = {
    "identity": ({"privileged": True, "mfa_enforced": False}, "privileged-mfa"),
    "storage": ({"public_access": True}, "public-access"),
    "network": ({"internet_admin_ports": True}, "internet-admin-ports"),
    "audit": ({"control_plane_logging": False}, "control-plane-logging"),
    "federation": ({"audience_restricted": False}, "audience-restricted"),
    "permissions": ({"wildcard_actions_allowed": True}, "wildcard-actions-allowed"),
}


def evidence(provider="aws", area="storage", **updates):
    return {"schema_version": 1, "records": [{"id": "owned-one", "provider": provider, "area": area,
        "observations": {k: updates.get(k) for k in fields_for(provider, area)}}]}


def rules(report):
    return {f["rule_id"] for f in report["findings"]}


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("area", (*COMMON, "compute"))
def test_positive_and_negative_controls_for_all_twenty_one_views(provider, area):
    if area == "compute":
        quiet = {"aws": {"imds_v2_required": True, "metadata_hop_limit_reviewed": True, "instance_role_scope_reviewed": True},
            "azure": {"managed_identity_scope_reviewed": True, "encryption_at_host_enabled": True, "public_ip_present": False},
            "gcp": {"secure_boot_enabled": True, "service_account_scope_reviewed": True, "os_login_enabled": True}}[provider]
        change = {"aws": ("imds_v2_required", "imds-v2-required"), "azure": ("encryption_at_host_enabled", "encryption-at-host-enabled"), "gcp": ("secure_boot_enabled", "secure-boot-enabled")}[provider]
        changed, expected = {change[0]: False}, change[1]
    else:
        quiet, (changed, expected) = QUIET[area], CHANGED[area]
    baseline = review_evidence(evidence(provider, area, **quiet))
    assert not baseline["findings"]
    assert baseline["providers"][provider]["status"] == "partial-offline-review"
    assert baseline["network_requests"] == baseline["external_tools_executed"] == 0
    assert baseline["real_world_effectiveness"] == "unverified" and not baseline["all_skills_automated"]
    positive = review_evidence(evidence(provider, area, **{**quiet, **changed}))
    assert rules(positive) == {"cloud-review." + provider + "." + area + "." + expected}


def test_unknown_observations_and_identity_applicability():
    report = review_evidence(evidence())
    assert report["providers"]["aws"]["status"] == "insufficient-evidence"
    assert report["providers"]["gcp"]["status"] == "not-assessed"
    assert not report["findings"]
    assert not review_evidence(evidence("aws", "identity", principal_kind="workload", privileged=True, mfa_enforced=False))["findings"]
    assert "cloud-review.aws.identity.privileged-mfa" in rules(review_evidence(evidence("aws", "identity", principal_kind="root", privileged=False, mfa_enforced=False)))
    with pytest.raises(ValueError):
        review_evidence(evidence("azure", "identity", principal_kind="root"))


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(schema_version=True), lambda d: d.update(secret="PRIVATE-FIXTURE"),
    lambda d: d.update(records=[]), lambda d: d["records"][0].update(provider="other"),
    lambda d: d["records"][0].update(area="execute-cloud-command"),
    lambda d: d["records"][0].update(tenant="PRIVATE-FIXTURE"),
    lambda d: d["records"][0]["observations"].update(public_access=1),
    lambda d: d["records"][0]["observations"].update(extra="PRIVATE-FIXTURE"),
    lambda d: d["records"].append(copy.deepcopy(d["records"][0])),
])
def test_strict_schema_and_sanitized_errors(mutate):
    data = evidence()
    mutate(data)
    with pytest.raises(ValueError) as exc:
        review_evidence(data)
    assert "PRIVATE-FIXTURE" not in str(exc.value)


def test_case_and_candidate_bounds(monkeypatch):
    import hunterqa.cloud_review as module
    row = evidence(public_access=True, encrypted_at_rest=False)["records"][0]
    with pytest.raises(ValueError):
        review_evidence({"schema_version": 1, "records": [{**copy.deepcopy(row), "id": "case-" + str(i)} for i in range(11)]})
    monkeypatch.setattr(module, "MAX_FINDINGS", 1)
    report = review_evidence({"schema_version": 1, "records": [row]})
    assert report["truncated"] and report["candidates_not_retained"] == 1


def native(tmp_path, monkeypatch, mode, data):
    path = tmp_path / "provider.json"
    path.write_text(json.dumps(data))
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    return path, review_file(path, authorized=True, mode=mode)


@pytest.mark.parametrize("statement,expected", [
    ({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::PRIVATE-BUCKET/*"}, set()),
    ({"Effect": "Deny", "Action": "*", "Resource": "*", "Principal": "*"}, set()),
    ({"Effect": "Allow", "Action": "*", "Resource": "*"}, {"all-actions"}),
    ({"Effect": "Allow", "Action": "s3:*", "Resource": "*"}, {"action-pattern"}),
    ({"Effect": "Allow", "Action": "s3:GetObject", "Principal": {"AWS": "*"}}, {"public-principal"}),
    ({"Effect": "Allow", "Action": "iam:PassRole", "Resource": "PRIVATE-ROLE"}, {"pass-role"}),
    ({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}, {"inverted-selector"}),
    ({"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity", "Principal": {"Federated": "PRIVATE-ISSUER"}}, {"federation-conditions"}),
])
def test_native_aws_statement_cues_and_deny_control(tmp_path, monkeypatch, statement, expected):
    _, report = native(tmp_path, monkeypatch, "aws-iam", {"Version": "2012-10-17", "Statement": statement})
    assert rules(report) == {"cloud-review.aws.iam." + k for k in expected}
    assert "PRIVATE-" not in json.dumps(report)


def test_aws_conditions_are_retained_as_context_not_evaluated(tmp_path, monkeypatch):
    data = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {"StringEquals": {"PRIVATE-CONDITION": "PRIVATE-VALUE"}}},
        {"Effect": "Deny", "Action": "*", "Resource": "*"}]}
    _, report = native(tmp_path, monkeypatch, "aws-iam", data)
    assert rules(report) == {"cloud-review.aws.iam.all-actions"}
    assert report["records"][0]["conditions_present"] is True
    assert "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("role,members,expected", [
    ("roles/viewer", ["user:PRIVATE@example.test"], set()),
    ("roles/storage.objectViewer", ["allUsers"], {"public-principal"}),
    ("roles/viewer", ["allAuthenticatedUsers"], {"public-principal"}),
    ("roles/owner", ["user:PRIVATE@example.test"], {"basic-role"}),
    ("roles/editor", ["user:PRIVATE@example.test"], {"basic-role"}),
    ("roles/iam.serviceAccountTokenCreator", ["serviceAccount:PRIVATE@example.test"], {"service-identity-control"}),
    ("roles/iam.serviceAccountKeyAdmin", ["user:PRIVATE@example.test"], {"service-identity-control"}),
])
def test_native_gcp_binding_cues(tmp_path, monkeypatch, role, members, expected):
    _, report = native(tmp_path, monkeypatch, "gcp-iam", {"version": 3, "bindings": [{"role": role, "members": members, "condition": {"title": "PRIVATE", "expression": "PRIVATE-CEL"}}]})
    assert rules(report) == {"cloud-review.gcp.iam." + k for k in expected}
    assert report["records"][0]["conditions_present"]
    assert "PRIVATE" not in json.dumps(report)


def nsg(**updates):
    props = {"access": "Allow", "direction": "Inbound", "protocol": "Tcp", "priority": 200,
        "sourceAddressPrefix": "Internet", "destinationPortRange": "22"}
    props.update(updates)
    return {"name": "PRIVATE-NSG", "id": "/PRIVATE/SUBSCRIPTION", "properties": {"securityRules": [{"name": "PRIVATE-RULE", "properties": props}]}}


@pytest.mark.parametrize("updates,flagged", [
    ({}, True), ({"access": "Deny"}, False), ({"direction": "Outbound"}, False),
    ({"protocol": "Udp"}, False), ({"destinationPortRange": "443"}, False),
    ({"destinationPortRange": "3000-4000"}, True), ({"destinationPortRange": "*"}, True),
    ({"sourceAddressPrefix": "10.0.0.0/8"}, False), ({"sourceAddressPrefix": "::/0"}, True),
    ({"sourceAddressPrefix": None, "sourceAddressPrefixes": ["0.0.0.0/0"], "destinationPortRange": None, "destinationPortRanges": ["443", "3389"]}, True),
])
def test_native_azure_selected_port_and_scope_controls(tmp_path, monkeypatch, updates, flagged):
    _, report = native(tmp_path, monkeypatch, "azure-nsg", nsg(**updates))
    assert bool(report["findings"]) is flagged
    assert "PRIVATE" not in json.dumps(report)


def test_azure_deny_precedence_and_actual_reachability_are_not_claimed(tmp_path, monkeypatch):
    data = nsg()
    denial = copy.deepcopy(data["properties"]["securityRules"][0])
    denial["properties"].update(access="Deny", priority=100)
    data["properties"]["securityRules"].insert(0, denial)
    _, report = native(tmp_path, monkeypatch, "azure-nsg", data)
    assert len(report["findings"]) == 1 and len(report["records"]) == 2
    assert report["findings"][0]["verification_status"] == "unverified"


@pytest.mark.parametrize("mode,data", [
    ("aws-iam", {"Statement": []}),
    ("aws-iam", {"Statement": {"Effect": "Allow", "Action": "*", "NotAction": "iam:*"}}),
    ("aws-iam", {"Statement": {"Effect": "Allow", "Action": "*", "Condition": "PRIVATE"}}),
    ("gcp-iam", {"denyRules": []}),
    ("gcp-iam", {"version": True, "bindings": [{"role": "roles/viewer", "members": ["allUsers"]}]}),
    ("gcp-iam", {"bindings": [{"role": "roles/viewer", "members": "allUsers"}]}),
    ("azure-nsg", nsg(priority=True)),
    ("azure-nsg", nsg(destinationPortRange="70000")),
    ("azure-nsg", nsg(destinationPortRange="", destinationPortRanges=["22", "PRIVATE-INVALID"])),
    ("azure-nsg", nsg(sourceAddressPrefix="[parameters('PRIVATE')]")),
    ("azure-nsg", nsg(sourceAddressPrefixes=["*"])),
    ("azure-nsg", nsg(sourceAddressPrefix=None, sourceAddressPrefixes="*")),
])
def test_unsupported_native_scope_and_values_are_rejected(tmp_path, monkeypatch, mode, data):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(data))
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    with pytest.raises(ValueError) as exc:
        review_file(path, authorized=True, mode=mode)
    assert "PRIVATE" not in str(exc.value)


def test_no_ambient_credentials_network_or_tool_execution(tmp_path, monkeypatch):
    import socket
    import subprocess
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: pytest.fail("No DNS"))
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("No external tools"))
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "PRIVATE-FAKE-KEY")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/PRIVATE/NEVER-OPEN")
    _, report = native(tmp_path, monkeypatch, "aws-iam", {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})
    assert report["network_requests"] == report["external_tools_executed"] == 0
    assert "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("mode,data", [
    ("normalized", evidence(public_access=True)),
    ("aws-iam", {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}),
    ("gcp-iam", {"bindings": [{"role": "roles/viewer", "members": ["allUsers"]}]}),
    ("azure-nsg", nsg()),
])
def test_cli_authorization_roots_private_receipts_nonoverwrite_and_sarif(tmp_path, monkeypatch, capsys, mode, data):
    from hunterqa.sarif_export import export_sarif
    path, output = tmp_path / "input.json", tmp_path / "report.json"
    raw = json.dumps(data).encode()
    path.write_bytes(raw)
    with pytest.raises(PermissionError):
        review_file(path, mode=mode)
    monkeypatch.delenv("HUNTERQA_APPROVED_ROOTS", raising=False)
    with pytest.raises(ValueError):
        review_file(path, authorized=True, mode=mode)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    args = ["cloud-review" if mode == "normalized" else "cloud-policy-review", "--input", str(path), "--out", str(output), "--authorized"]
    if mode != "normalized":
        args += ["--mode", mode]
    main(args)
    report = json.loads(output.read_text())
    assert report["input_sha256"] == hashlib.sha256(raw).hexdigest() and path.read_bytes() == raw
    assert export_sarif(output)["runs"][0]["results"]
    with pytest.raises(FileExistsError):
        main(args)
    capsys.readouterr()
    main(["cloud-review-catalog"])
    assert json.loads(capsys.readouterr().out)["skills"][0]["id"] == "offensive-cloud"
    path.write_bytes(b" " * (MAX_BYTES + 1))
    with pytest.raises(ValueError):
        review_file(path, authorized=True, mode=mode)


@pytest.mark.parametrize("raw", [b'{', b'{"secret":"PRIVATE","secret":"PRIVATE"}', b'{"value":NaN}', b'\xffPRIVATE'])
def test_malformed_cloud_json_withholds_contents(tmp_path, monkeypatch, raw):
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    with pytest.raises(ValueError, match="contents withheld"):
        review_file(path, authorized=True)


@pytest.mark.parametrize("mode,data", [
    ("normalized", evidence()),
    ("aws-iam", {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}),
    ("gcp-iam", {"bindings": [{"role": "roles/viewer", "members": ["allUsers"]}]}),
    ("azure-nsg", nsg()),
])
def test_scope_rejects_outside_input_output_and_symlinks(tmp_path, monkeypatch, mode, data):
    root = tmp_path / "private"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(data))
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(root))
    with pytest.raises(ValueError):
        review_file(outside, authorized=True, mode=mode)
    source = root / "input.json"
    source.write_text(json.dumps(data))
    args = ["cloud-review" if mode == "normalized" else "cloud-policy-review", "--input", str(source), "--out", str(tmp_path / "forbidden-output.json"), "--authorized"]
    if mode != "normalized":
        args += ["--mode", mode]
    with pytest.raises(ValueError):
        main(args)
    assert not (tmp_path / "forbidden-output.json").exists()
    link = root / "linked.json"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("OS does not allow creating symlinks")
    with pytest.raises(ValueError, match="Symlink"):
        review_file(link, authorized=True, mode=mode)


def test_public_template_reports_unknown_for_all_providers():
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "templates" / "HunterQA-cloud-review-template.json"
    report = review_evidence(json.loads(path.read_text()))
    assert len(report["records"]) == 21 and not report["findings"]
    assert all(p["status"] == "insufficient-evidence" for p in report["providers"].values())
    assert not report["provider_enforcement_verified"]
    assert not report["effective_permissions_calculated"]
    assert not report["resource_reachability_verified"]


def test_native_source_receipts_distinguish_sarif_cases_without_exporting_resources(tmp_path, monkeypatch):
    from hunterqa.sarif_export import export_sarif
    cases = []
    for identifier in ("PRIVATE-ONE", "PRIVATE-TWO"):
        _, report = native(tmp_path, monkeypatch, "aws-iam", {"Statement": {"Effect": "Allow", "Action": "*", "Resource": identifier}})
        serialized = json.dumps(report)
        assert identifier not in serialized
        output = tmp_path / (identifier + ".json")
        output.write_text(serialized)
        cases.append(export_sarif(output)["runs"][0]["results"][0])
    assert cases[0]["properties"]["assessmentCase"] != cases[1]["properties"]["assessmentCase"]
    assert cases[0]["partialFingerprints"] != cases[1]["partialFingerprints"]


def test_unknown_policy_mode_never_opens_a_file(tmp_path):
    with pytest.raises(ValueError):
        review_file(tmp_path / "does-not-exist", authorized=True, mode="execute-sdk")
