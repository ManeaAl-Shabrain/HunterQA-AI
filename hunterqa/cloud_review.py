"""Offline cloud posture declarations and selected provider-policy syntax checks."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

from .bounty import _approved_file
from .source_files import read_bounded

MAX_BYTES = 1_048_576
MAX_FINDINGS = 500
ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
PROVIDERS = ("aws", "azure", "gcp")
COMMON = {
    "identity": {"principal_kind": ("human", "workload", "root", "unknown"), "privileged": "bool", "mfa_enforced": "bool", "long_lived_keys_present": "bool"},
    "storage": {"public_access": "bool", "encrypted_at_rest": "bool", "https_only": "bool", "access_logging": "bool"},
    "network": {"internet_admin_ports": "bool", "public_database_endpoint": "bool", "flow_logs_enabled": "bool"},
    "audit": {"control_plane_logging": "bool", "data_access_logging": "bool", "retention_reviewed": "bool", "log_protection_reviewed": "bool"},
    "federation": {"issuer_validated": "bool", "audience_restricted": "bool", "subject_restricted": "bool", "trust_scope_reviewed": "bool"},
    "permissions": {"wildcard_actions_allowed": "bool", "unrestricted_resources": "bool", "privileged_assignment": "bool", "assignment_scope_reviewed": "bool"},
}
COMPUTE = {
    "aws": {"imds_v2_required": "bool", "metadata_hop_limit_reviewed": "bool", "instance_role_scope_reviewed": "bool"},
    "azure": {"managed_identity_scope_reviewed": "bool", "encryption_at_host_enabled": "bool", "public_ip_present": "bool"},
    "gcp": {"secure_boot_enabled": "bool", "service_account_scope_reviewed": "bool", "os_login_enabled": "bool"},
}
RULES = {
    "storage": (("public_access", True, "Storage access is declared public", "Review intended publication, effective access controls and approved data classification.", "WARNING"),
        ("encrypted_at_rest", False, "Storage encryption at rest is declared disabled", "Verify provider defaults, key management and effective encryption policy.", "WARNING"),
        ("https_only", False, "Storage transport is not declared HTTPS-only", "Review supported transport restrictions and application compatibility.", "WARNING"),
        ("access_logging", False, "Storage access logging is declared unavailable", "Review appropriate access audit coverage, retention and cost.", "INFO")),
    "network": (("internet_admin_ports", True, "Administrative ports are declared internet-accessible", "Review actual routes, rule order, source restrictions and authorized administration paths.", "WARNING"),
        ("public_database_endpoint", True, "Database endpoint is declared public", "Review intended exposure and actual authentication/network controls; a public endpoint alone is not proof of unauthorized access.", "INFO"),
        ("flow_logs_enabled", False, "Selected network flow logging is declared disabled", "Review required network telemetry and supported provider coverage.", "INFO")),
    "audit": tuple((f, False, title, "Review effective audit scope, exceptions, retention and independent log protection.", "INFO" if f != "control_plane_logging" else "WARNING") for f, title in (
        ("control_plane_logging", "Control-plane audit logging is declared disabled"), ("data_access_logging", "Data-access audit logging is declared disabled"),
        ("retention_reviewed", "Audit retention has not been declared reviewed"), ("log_protection_reviewed", "Audit log protection has not been declared reviewed"))),
    "federation": tuple((f, False, title, "Independently review trusted issuers, audiences, subject constraints and the actual relying-party configuration.", "WARNING") for f, title in (
        ("issuer_validated", "Federation issuer validation is declared absent"), ("audience_restricted", "Federation audience restriction is declared absent"),
        ("subject_restricted", "Federation subject restriction is declared absent"), ("trust_scope_reviewed", "Federation trust scope has not been declared reviewed"))),
    "permissions": (("wildcard_actions_allowed", True, "Selected permissions declare wildcard actions", "Review conditions, resource scope, denies and permission boundaries; this does not establish effective privilege.", "INFO"),
        ("unrestricted_resources", True, "Selected permissions declare unrestricted resource scope", "Review service/action applicability and narrow scope where supported.", "INFO"),
        ("privileged_assignment", True, "Selected identity declares a privileged assignment", "Review least privilege and approved administrative requirements; privilege alone is not a vulnerability.", "INFO"),
        ("assignment_scope_reviewed", False, "Permission assignment scope has not been declared reviewed", "Review actual inheritance, conditions, denies and organizational controls.", "INFO")),
}
REFERENCES = ["https://github.com/SnailSploit/Claude-Red/tree/main/Skills/cloud",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html",
    "https://cloud.google.com/iam/docs/roles-overview",
    "https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview",
    "https://cloud.google.com/compute/shielded-vm/docs/shielded-vm",
    "https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption-overview",
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"]


def fields_for(provider, area):
    return COMPUTE[provider] if area == "compute" else COMMON[area]


def catalog():
    return [{"id": "offensive-cloud", "implementation": "offline-selected-multicloud-policy-review",
        "live_api_execution_available": False, "active_exploitation_available": False,
        "native_input_modes": ["aws-iam", "gcp-iam", "azure-nsg"],
        "providers": {p: {area: {f: "boolean-or-null" if kind == "bool" else [*kind, None]
            for f, kind in fields_for(p, area).items()} for area in (*COMMON, "compute")} for p in PROVIDERS},
        "required_evidence": "Private owner-normalized declarations or selected resolved provider JSON exports; effective permissions, reachability and provider enforcement require independent validation"}]


def _decode(raw):
    def pairs(entries):
        data = {}
        for k, v in entries:
            if k in data:
                raise ValueError("Duplicate key")
            data[k] = v
        return data

    def constant(_):
        raise ValueError("Non-finite JSON")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Invalid cloud JSON; contents withheld") from None


def _failure():
    raise ValueError("Unsupported cloud evidence shape or value; contents withheld")


def validate_evidence(data):
    if not isinstance(data, dict) or set(data) != {"schema_version", "records"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        _failure()
    if not isinstance(data["records"], list) or not 1 <= len(data["records"]) <= 210:
        _failure()
    ids, counts = set(), {}
    for r in data["records"]:
        if not isinstance(r, dict) or set(r) != {"id", "provider", "area", "observations"}:
            _failure()
        if not isinstance(r["id"], str) or not ID.fullmatch(r["id"]) or r["id"] in ids:
            _failure()
        ids.add(r["id"])
        if r["provider"] not in PROVIDERS or not isinstance(r["area"], str) or r["area"] not in (*COMMON, "compute"):
            _failure()
        pair = r["provider"], r["area"]
        counts[pair] = counts.get(pair, 0) + 1
        if counts[pair] > 10:
            _failure()
        fields, obs = fields_for(*pair), r["observations"]
        if not isinstance(obs, dict) or set(obs) != set(fields):
            _failure()
        for f, kind in fields.items():
            v = obs[f]
            if v is not None and not (type(v) is bool if kind == "bool" else isinstance(v, str) and v in kind):
                _failure()
        if r["area"] == "identity" and r["provider"] != "aws" and obs["principal_kind"] == "root":
            _failure()
    return data


def _base_report():
    return {"engine": "cloud-evidence-review", "schema_version": 1, "category": "Cloud",
        "skill": "offensive-cloud", "reviewed_at": datetime.now(timezone.utc).isoformat(),
        "findings": [], "records": [], "network_requests": 0, "external_tools_executed": 0,
        "provider_enforcement_verified": False, "effective_permissions_calculated": False,
        "resource_reachability_verified": False,
        "all_skills_automated": False, "real_world_effectiveness": "unverified", "references": REFERENCES,
        "truncated": False, "candidates_not_retained": 0,
        "limitations": ["Selected local declarations or syntax cues only; no cloud account/resource collection or provider connection",
            "No ambient credentials, metadata requests, SDK/CLI execution, role assumption, token creation or resource mutation",
            "No effective IAM/RBAC calculation, policy simulation, role chaining, resource reachability or complete standards coverage",
            "Conditions, denies, permission boundaries, organizational controls, inherited policies and provider defaults require independent review",
            "No account, tenant, project, resource, principal identifiers, addresses, credentials or raw source values are exported; use neutral IDs",
            "Missing/unknown evidence is unassessed; quiet findings do not prove security or owner consent"]}


def _add(report, case, provider, key, title, fix, severity="WARNING"):
    if len(report["findings"]) >= MAX_FINDINGS:
        report["truncated"] = True
        report["candidates_not_retained"] += 1
        return
    report["findings"].append({"rule_id": "cloud-review." + provider + "." + key.replace("_", "-"),
        "skill": "offensive-cloud", "test_case": case, "provider": provider,
        "title": title, "severity": severity, "cwe": "CWE-284", "message": title + ". " + fix,
        "remediation": fix, "code": "", "file_path": "external-evidence", "line_start": 1, "line_end": 1,
        "engine": "cloud-evidence-review", "verification_status": "unverified"})


def _provider_summary(report):
    report["providers"] = {}
    for p in PROVIDERS:
        rows = [r for r in report["records"] if r["provider"] == p]
        report["providers"][p] = {"records_reviewed": len(rows), "status": "not-assessed" if not rows else (
            "insufficient-evidence" if all(r["status"] == "insufficient-evidence" for r in rows) else "partial-offline-review")}
    return report


def review_evidence(data):
    validate_evidence(data)
    report = _base_report()
    for r in data["records"]:
        p, area, obs = r["provider"], r["area"], r["observations"]

        def cue(key, title, fix, severity="WARNING"):
            _add(report, r["id"], p, area + "." + key, title, fix, severity)

        for f, bad, title, fix, severity in RULES.get(area, ()):
            if obs[f] is not None and obs[f] == bad:
                cue(f, title, fix, severity)
        if area == "identity":
            if (obs["principal_kind"] == "root" or obs["principal_kind"] == "human" and obs["privileged"] is True) and obs["mfa_enforced"] is False:
                cue("privileged-mfa", "Privileged human identity lacks declared MFA enforcement", "Review actual identity/conditional-access policy and approved exceptions.")
            if obs["long_lived_keys_present"] is True:
                cue("long-lived-keys", "Selected identity declares long-lived credentials", "Review short-lived workload identity options, rotation and credential scope; no credential values are requested.", "INFO")
        if area == "compute":
            special = {"aws": (("imds_v2_required", False, "AWS compute does not declare IMDSv2 required", "WARNING"), ("metadata_hop_limit_reviewed", False, "AWS metadata hop-limit policy has not been declared reviewed", "INFO"), ("instance_role_scope_reviewed", False, "AWS instance role scope has not been declared reviewed", "INFO")),
                "azure": (("managed_identity_scope_reviewed", False, "Azure managed identity scope has not been declared reviewed", "INFO"), ("encryption_at_host_enabled", False, "Azure encryption at host is not declared enabled", "INFO"), ("public_ip_present", True, "Azure compute declares a public IP", "INFO")),
                "gcp": (("secure_boot_enabled", False, "GCP Secure Boot is not declared enabled", "INFO"), ("service_account_scope_reviewed", False, "GCP attached service account scope has not been declared reviewed", "INFO"), ("os_login_enabled", False, "GCP OS Login is not declared enabled", "INFO"))}
            for f, bad, title, severity in special[p]:
                if obs[f] is not None and obs[f] == bad:
                    cue(f, title, "Independently review provider-specific effective configuration, supported alternatives and compatibility.", severity)
        unknown = [f for f in obs if obs[f] is None or obs[f] == "unknown"]
        report["records"].append({"case": r["id"], "provider": p, "area": area, "unknown_fields": unknown,
            "status": "insufficient-evidence" if len(unknown) == len(obs) else "partial-declared-evidence"})
    return _provider_summary(report)


def _text(v):
    return isinstance(v, str) and 0 < len(v) <= 4096 and not any(ord(c) < 32 for c in v)


def _strings(v):
    values = [v] if isinstance(v, str) else v
    if not isinstance(values, list) or not 1 <= len(values) <= 100 or not all(_text(s) for s in values):
        _failure()
    return values


def _native_record(report, provider, receipt, index, **metadata):
    case = provider + "-policy-" + receipt[:12] + "-" + str(index)
    report["records"].append({"case": case, "provider": provider, "status": "selected-native-syntax-only", **metadata})
    return case


def _aws(data, report, receipt):
    if not isinstance(data, dict) or not set(data) <= {"Version", "Id", "Statement"} or "Statement" not in data:
        _failure()
    rows = data["Statement"] if isinstance(data["Statement"], list) else [data["Statement"]]
    if not 1 <= len(rows) <= 100:
        _failure()
    for i, r in enumerate(rows, 1):
        allowed = {"Sid", "Effect", "Action", "NotAction", "Resource", "NotResource", "Principal", "NotPrincipal", "Condition"}
        if not isinstance(r, dict) or not set(r) <= allowed or r.get("Effect") not in ("Allow", "Deny") or ("Action" in r) == ("NotAction" in r):
            _failure()
        for a, b in (("Resource", "NotResource"), ("Principal", "NotPrincipal")):
            if a in r and b in r:
                _failure()
        actions = _strings(r.get("Action", r.get("NotAction")))
        for k in ("Resource", "NotResource"):
            if k in r:
                _strings(r[k])
        if "Condition" in r and not isinstance(r["Condition"], dict):
            _failure()
        principal = r.get("Principal")
        principal_values = []
        for k in ("Principal", "NotPrincipal"):
            if k not in r:
                continue
            if isinstance(r[k], dict):
                for v in r[k].values():
                    values = _strings(v)
                    if k == "Principal":
                        principal_values.extend(values)
            else:
                values = _strings(r[k])
                if k == "Principal":
                    principal_values.extend(values)
        case = _native_record(report, "aws", receipt, i, conditions_present=bool(r.get("Condition")))
        if r["Effect"] != "Allow":
            continue

        def cue(key, title, severity="WARNING"):
            _add(report, case, "aws", "iam." + key, title, "Review actual policy context, conditions, explicit denies, boundaries, organizational controls and effective permissions independently.", severity)

        if "NotAction" in r or "NotResource" in r or "NotPrincipal" in r:
            cue("inverted-selector", "Allow statement contains an inverted selector requiring independent interpretation", "INFO")
        if "Action" in r and any(a == "*" for a in actions):
            cue("all-actions", "Allow statement declares all actions")
        elif "Action" in r and any("*" in a or "?" in a for a in actions):
            cue("action-pattern", "Allow statement declares an action pattern", "INFO")
        if "*" in principal_values:
            cue("public-principal", "Allow statement contains a wildcard principal declaration")
        if "Action" in r and "iam:passrole" in {a.lower() for a in actions}:
            cue("pass-role", "Allow statement declares role-passing permission", "INFO")
        if "Action" in r and "sts:assumerolewithwebidentity" in {a.lower() for a in actions} and isinstance(principal, dict) and "Federated" in principal and not r.get("Condition"):
            cue("federation-conditions", "Web-identity trust statement has no declared condition constraints", "INFO")


def _gcp(data, report, receipt):
    if not isinstance(data, dict) or not set(data) <= {"version", "bindings", "auditConfigs", "etag"} or "bindings" not in data:
        _failure()
    if "version" in data and (type(data["version"]) is not int or data["version"] not in (0, 1, 3)):
        _failure()
    rows = data["bindings"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 100:
        _failure()
    for i, r in enumerate(rows, 1):
        if not isinstance(r, dict) or not {"role", "members"} <= set(r) or not set(r) <= {"role", "members", "condition"} or not _text(r["role"]):
            _failure()
        if not isinstance(r["members"], list):
            _failure()
        members = _strings(r["members"])
        if "condition" in r and not isinstance(r["condition"], dict):
            _failure()
        case = _native_record(report, "gcp", receipt, i, conditions_present=bool(r.get("condition")))
        if any(m in ("allUsers", "allAuthenticatedUsers") for m in members):
            _add(report, case, "gcp", "iam.public-principal", "IAM binding declares a broad public principal class", "Review resource publication, conditions and effective access; this does not prove public data access.")
        if r["role"] in ("roles/owner", "roles/editor"):
            _add(report, case, "gcp", "iam.basic-role", "IAM binding declares a broad basic role", "Review actual inherited policy, conditions and least-privilege alternatives.", "INFO")
        if r["role"] in ("roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountKeyAdmin"):
            _add(report, case, "gcp", "iam.service-identity-control", "IAM binding declares selected service-identity control permissions", "Review actual target scope, conditions and approved identity administration; no tokens or keys are created.", "INFO")


def _port(v):
    if v == "*":
        return True
    if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", v):
        _failure()
    ends = [int(p) for p in v.split("-")]
    lo, hi = ends[0], ends[-1]
    if not 0 <= lo <= hi <= 65535:
        _failure()
    return any(lo <= p <= hi for p in (22, 3389, 5985, 5986))


def _azure(data, report, receipt):
    if not isinstance(data, dict) or not isinstance(data.get("properties"), dict) or "securityRules" not in data["properties"]:
        _failure()
    rows = data["properties"]["securityRules"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 100:
        _failure()
    for i, row in enumerate(rows, 1):
        if not isinstance(row, dict) or not isinstance(row.get("properties"), dict):
            _failure()
        r = row["properties"]
        if r.get("access") not in ("Allow", "Deny") or r.get("direction") not in ("Inbound", "Outbound") or r.get("protocol") not in ("Tcp", "Udp", "Icmp", "Esp", "Ah", "*"):
            _failure()
        if type(r.get("priority")) is not int or not 100 <= r["priority"] <= 4096:
            _failure()

        def either(single, plural):
            a, b = r.get(single), r.get(plural)
            has_a, has_b = a is not None and a != "", b is not None and b != []
            if has_a and has_b:
                _failure()
            if has_a and not isinstance(a, str) or has_b and not isinstance(b, list):
                _failure()
            return _strings(a if has_a else b)

        sources = either("sourceAddressPrefix", "sourceAddressPrefixes")
        ports = either("destinationPortRange", "destinationPortRanges")
        if any("[" in s or "]" in s for s in sources):
            _failure()  # Unresolved ARM expressions are not live-export values.
        admin = any([_port(p) for p in ports])
        case = _native_record(report, "azure", receipt, i)
        if r["access"] == "Allow" and r["direction"] == "Inbound" and r["protocol"] in ("Tcp", "*") and admin and any(s.lower() in ("*", "internet", "0.0.0.0/0", "::/0") for s in sources):
            _add(report, case, "azure", "nsg.internet-admin", "NSG rule declares broad-source inbound access to selected administrative ports", "Review rule priority, higher-priority denies, routes, destination scope, attached controls and actual reachability independently.")


def review_file(path, *, authorized=False, mode="normalized"):
    if not authorized:
        raise PermissionError("Cloud evidence review requires explicit authorization")
    if mode not in ("normalized", "aws-iam", "gcp-iam", "azure-nsg"):
        _failure()
    raw = read_bounded(_approved_file(path), MAX_BYTES)
    data, receipt = _decode(raw), hashlib.sha256(raw).hexdigest()
    if mode == "normalized":
        report = review_evidence(data)
    else:
        report = _base_report()
        {"aws-iam": _aws, "gcp-iam": _gcp, "azure-nsg": _azure}[mode](data, report, receipt)
        _provider_summary(report)
        report["limitations"].extend(["Native readers cover selected declarations, not complete document validity, custom roles, effective permissions or provider enforcement",
            "AWS conditions/variables and GCP CEL expressions are not evaluated; Azure rule ordering, default rules, routes and application security groups are not resolved",
            "Native receipt-derived case IDs change when input bytes change; input identifiers and raw values are withheld"])
    report.update(input_sha256=receipt, input_mode=mode)
    return report
