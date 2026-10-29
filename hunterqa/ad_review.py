"""Offline normalized AD evidence review. No directory queries or tool execution."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

from .bounty import _approved_file
from .source_files import read_bounded

MAX_BYTES = 1_048_576
MAX_FINDINGS = 1000
ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
RIGHTS = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "AddMember", "WriteSPN",
    "ForceChangePassword", "ReplicatingDirectoryChanges", "ReplicatingDirectoryChangesAll",
    "ReplicatingDirectoryChangesInFilteredSet"}
SECTIONS = {
    "accounts": (200, {"enabled": "bool", "kind": ("user", "service", "computer", "gmsa", "unknown"),
        "tier0": "bool", "is_domain_controller": "bool", "user_account_control": "uac", "spn_count": "count"}),
    "domain_controllers": (100, {"smb_signing_required": "bool", "ldap_signing_required": "bool",
        "ldap_channel_binding": ("always", "when-supported", "never", "unknown"), "smb1_enabled": "bool"}),
    "acl_grants": (200, {"principal_tier": ("ordinary", "privileged", "unknown"),
        "target_tier": ("tier0", "other", "unknown"), "target_kind": ("domain", "group", "user", "computer", "gpo", "other", "unknown"),
        "effect": ("allow", "deny", "unknown"), "rights": "rights"}),
    "certificate_templates": (100, {"published": "bool", "broad_enrollment": "bool", "enrollee_supplies_subject": "bool",
        "authentication_eku": "bool", "manager_approval": "bool", "authorized_signatures": "count"}),
    "trusts": (100, {"kind": ("external", "forest", "intra-forest", "unknown"),
        "sid_filtering_enabled": "bool", "selective_authentication": "bool"}),
    "hybrid_accounts": (100, {"enabled": "bool", "synchronized": "bool", "on_prem_privileged": "bool", "entra_privileged": "bool"}),
}
REFERENCES = ["https://github.com/SnailSploit/Claude-Red/tree/main/Skills/active-directory",
    "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties",
    "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server",
    "https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/accounts",
    "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview",
    "https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-insecure-adcs-certificate-enrollment"]


def catalog():
    return [{"id": "offensive-active-directory", "implementation": "offline-normalized-directory-policy-review",
        "active_exploitation_available": False,
        "required_evidence": "Owner-reviewed account flags, selected ACL grants, certificate template settings, trust and hybrid privilege declarations; effective access and exploitability remain unverified"},
        {"id": "offensive-netexec", "implementation": "offline-normalized-smb-ldap-policy-review",
        "external_tool_execution_available": False, "active_exploitation_available": False,
        "required_evidence": "Selected domain-controller SMB/LDAP policy declarations; no native NetExec output parser, collection, credentials or protocol authentication"}]


def _decode(raw):
    def pairs(entries):
        result = {}
        for key, value in entries:
            if key in result:
                raise ValueError("Duplicate field")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("Non-finite JSON number")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Invalid AD evidence JSON; contents withheld") from None


def _collected(value):
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("Expected a bounded timezone-aware collection timestamp or null")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() is None:
            raise ValueError("Timezone required")
        return parsed.timestamp()
    except (ValueError, OverflowError, OSError):
        raise ValueError("Invalid collection timestamp; contents withheld") from None


def validate_evidence(data):
    if not isinstance(data, dict) or set(data) != {"schema_version", "collected_at", *SECTIONS}:
        raise ValueError("AD evidence requires exact schema fields; contents withheld")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("Unsupported AD evidence schema version")
    _collected(data["collected_at"])
    ids, count = set(), 0
    for section, (maximum, fields) in SECTIONS.items():
        rows = data[section]
        if not isinstance(rows, list) or len(rows) > maximum:
            raise ValueError("AD section exceeds supported record bounds")
        count += len(rows)
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"id", *fields}:
                raise ValueError("AD record has missing or unknown fields; contents withheld")
            if not isinstance(row["id"], str) or not ID.fullmatch(row["id"]) or row["id"] in ids:
                raise ValueError("AD record IDs must be distinct neutral lowercase identifiers")
            ids.add(row["id"])
            for name, kind in fields.items():
                value = row[name]
                if value is None:
                    continue
                if isinstance(kind, tuple):
                    valid = isinstance(value, str) and value in kind
                elif kind == "bool":
                    valid = type(value) is bool
                elif kind in ("uac", "count"):
                    valid = type(value) is int and 0 <= value <= (0xFFFFFFFF if kind == "uac" else 10000)
                else:
                    valid = isinstance(value, list) and len(value) <= len(RIGHTS) and all(isinstance(v, str) and v in RIGHTS for v in value) and len(set(value)) == len(value)
                if not valid:
                    raise ValueError("AD record has an unsupported typed value; contents withheld")
    if not count:
        raise ValueError("Select at least one normalized AD evidence record")
    return data


def _account(row, cue):
    uac = row["user_account_control"]
    if row["enabled"] is not None and uac is not None and row["enabled"] == bool(uac & 2):
        cue("account-state-conflict", "Declared enabled state conflicts with the supplied UAC disable bit",
            "Reconcile the source snapshot before relying on account-policy observations.", "INFO")
        return
    if row["enabled"] is not True:
        return
    if uac is not None:
        for flag, key, title, fix in (
            (0x400000, "preauth-disabled", "Enabled account declares Kerberos preauthentication disabled", "Require preauthentication unless an independently reviewed compatibility exception applies."),
            (0x20, "password-not-required", "Enabled account declares password-not-required policy", "Review the account's password requirements; this flag does not prove an empty password."),
            (0x80, "reversible-storage", "Enabled account allows reversible password storage", "Remove reversible-storage exceptions after assessing application dependencies."),
            (0x200000, "des-only", "Enabled account declares DES-only Kerberos keys", "Review supported encryption types and migrate legacy dependencies."),
        ):
            if uac & flag:
                cue(key, title, fix)
        if uac & 0x10000 and row["kind"] in ("user", "service"):
            cue("password-never-expires", "Enabled user/service account declares a nonexpiring password", "Review rotation policy and managed service account options; approved exceptions require context.", "INFO")
        if uac & 0x80000 and row["is_domain_controller"] is False:
            cue("unconstrained-delegation", "Non-DC account declares unconstrained delegation", "Review service dependencies and replace unnecessary unconstrained delegation.")
        if uac & 0x1000000:
            cue("protocol-transition", "Account declares protocol-transition delegation", "Review the complete delegation policy and permitted service targets independently.", "INFO")
        if row["tier0"] is True and row["kind"] in ("user", "service", "gmsa") and not uac & 0x100000:
            cue("tier0-delegation-protection", "Tier-0 identity lacks the supplied account-not-delegated flag", "Review appropriate delegation protections and compatibility for this identity.", "INFO")
    if row["tier0"] is True and row["spn_count"] is not None and row["spn_count"] > 0 and row["kind"] in ("user", "service"):
        cue("privileged-service-identity", "Privileged user/service identity has declared SPNs", "Review service privilege separation and managed credentials; SPN presence does not establish an exploitable weakness.", "INFO")


def _controller(row, cue):
    for field, key, title, fix, undesired in (
        ("smb_signing_required", "smb-signing", "SMB signing is declared not required", "Review effective SMB signing policy and client compatibility before enforcing changes.", False),
        ("ldap_signing_required", "ldap-signing", "LDAP signing is declared not required", "Review effective LDAP signing requirements and unsigned-bind audit evidence.", False),
        ("smb1_enabled", "smb1", "Legacy SMB1 is declared enabled", "Inventory dependencies and retire SMB1 where supported.", True),
    ):
        if row[field] is undesired:
            cue(key, title, fix)
    if row["ldap_channel_binding"] == "never":
        cue("ldap-channel-binding", "LDAP channel binding is declared disabled", "Review LDAP-over-TLS channel binding policy and client support.")
    elif row["ldap_channel_binding"] == "when-supported":
        cue("ldap-channel-binding-conditional", "LDAP channel binding is declared conditional", "Review whether supported clients permit enforcing channel binding for this deployment.", "INFO")


def _other(section, row, cue):
    if section == "acl_grants" and row["effect"] == "allow" and row["principal_tier"] == "ordinary" and row["rights"]:
        rights = set(row["rights"])
        if row["target_tier"] == "tier0" and rights & {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "AddMember", "WriteSPN", "ForceChangePassword"}:
            cue("tier0-acl-grant", "Selected allow grant links an ordinary principal to a Tier-0 object", "Independently resolve object type, inheritance, deny entries, group membership and effective permissions; review least privilege.")
        if row["target_kind"] == "domain" and {"ReplicatingDirectoryChanges", "ReplicatingDirectoryChangesAll"} <= rights:
            cue("replication-grant", "Selected domain grant includes a directory replication rights pair", "Review legitimate replication/synchronization services and effective access; this does not prove usable replication access.")
    elif section == "certificate_templates":
        if all(row[k] is True for k in ("published", "broad_enrollment", "enrollee_supplies_subject", "authentication_eku")) and row["manager_approval"] is False and row["authorized_signatures"] == 0:
            cue("certificate-enrollment-review", "Template declarations combine broad enrollment and requester-supplied authentication identity", "Review actual EKUs, template and CA permissions, issuance restrictions and certificate mapping; this is not a confirmed ESC classification.")
    elif section == "trusts" and row["kind"] in ("external", "forest"):
        if row["sid_filtering_enabled"] is False:
            cue("trust-sid-filtering", "External/forest trust declares SID filtering disabled", "Review trust direction, effective filtering and approved trust exceptions independently.")
        if row["selective_authentication"] is False:
            cue("trust-authentication-scope", "External/forest trust does not declare selective authentication", "Review the intended trust authentication scope; broader authentication may be an approved design.", "INFO")
    elif section == "hybrid_accounts" and all(row[k] is True for k in ("enabled", "synchronized", "on_prem_privileged", "entra_privileged")):
        cue("hybrid-dual-privilege", "Enabled synchronized identity declares on-premises and Entra privileges", "Review separation of administrative identities, least privilege and approved privileged access policy.")


def review_evidence(data, *, now=None):
    validate_evidence(data)
    stamp = datetime.now(timezone.utc) if now is None else now
    if not isinstance(stamp, datetime) or stamp.utcoffset() is None:
        raise ValueError("AD review time must be timezone aware")
    findings, observations, sections = [], [], {}
    dropped = 0
    for section, (_, fields) in SECTIONS.items():
        start = len(findings)
        for row in data[section]:
            skill = "offensive-netexec" if section == "domain_controllers" else "offensive-active-directory"

            def cue(key, title, fix, severity="WARNING"):
                nonlocal dropped
                if len(findings) >= MAX_FINDINGS:
                    dropped += 1
                    return
                findings.append({"rule_id": "ad-review." + key, "skill": skill, "test_case": row["id"],
                    "evidence_section": section, "title": title, "severity": severity, "cwe": "CWE-284",
                    "message": title + ". " + fix, "remediation": fix, "code": "",
                    "file_path": "external-evidence", "line_start": 1, "line_end": 1,
                    "engine": "ad-evidence-review", "verification_status": "unverified"})

            unknown = [key for key in fields if row[key] is None or row[key] == "unknown"]
            observations.append({"case": row["id"], "section": section, "skill": skill,
                "unknown_fields": unknown, "status": "insufficient-evidence" if len(unknown) == len(fields) else "partial-declared-evidence"})
            if section == "accounts":
                _account(row, cue)
            elif section == "domain_controllers":
                _controller(row, cue)
            else:
                _other(section, row, cue)
        sections[section] = {"records": len(data[section]), "retained_candidates": len(findings) - start,
            "records_with_unknown_fields": sum(bool(o["unknown_fields"]) for o in observations if o["section"] == section),
            "status": "selected-records-only" if data[section] else "not-assessed"}
    collected = _collected(data["collected_at"])
    age = stamp.timestamp() - collected if collected is not None else None
    freshness = "unknown" if age is None else "future-clock-review" if age < -300 else "older-than-24h-review" if age > 86400 else "within-24h-declared"
    return {"engine": "ad-evidence-review", "schema_version": 1, "category": "Active Directory",
        "reviewed_at": stamp.astimezone(timezone.utc).isoformat(), "evidence_freshness": freshness,
        "skills": [{**s, "records_reviewed": sum(o["skill"] == s["id"] for o in observations),
            "status": "not-assessed" if not any(o["skill"] == s["id"] for o in observations) else "insufficient-evidence" if all(o["status"] == "insufficient-evidence" for o in observations if o["skill"] == s["id"]) else "partial-offline-review"} for s in catalog()],
        "sections": sections, "observations": observations, "findings": findings,
        "truncated": bool(dropped), "candidates_not_retained": dropped, "references": REFERENCES,
        "network_requests": 0, "external_tools_executed": 0, "all_skills_automated": False,
        "real_world_effectiveness": "unverified",
        "limitations": ["Only selected owner-normalized declarations; no native BloodHound, ADExplorer, NetExec, LDIF or directory dump parser",
            "Null and unknown values are unassessed, not secure defaults; disabled/skipped records do not establish safety",
            "No domain queries, authentication, ticket requests, credentials, hash cracking, relay, replication or directory changes",
            "No effective ACL calculation, membership expansion, attack-path execution or confirmed ESC1-15 classification",
            "No domain names, hostnames, account names, SIDs, DNs, secrets or raw source values are exported; use neutral record IDs",
            "All configuration, freshness and privilege declarations require independent verification; empty findings are not proof of security"]}


def review_file(path, *, authorized=False):
    if not authorized:
        raise PermissionError("AD evidence review requires explicit authorization")
    raw = read_bounded(_approved_file(path), MAX_BYTES)
    report = review_evidence(_decode(raw))
    report["input_sha256"] = hashlib.sha256(raw).hexdigest()
    return report
