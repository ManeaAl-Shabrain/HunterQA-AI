"""Bounded local IoT evidence, MQTT ACL syntax and U-Boot build review."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

from .bounty import _approved_file
from .source_files import read_bounded

MAX_BYTES = 1_048_576
MAX_LINES = 20000
MAX_LINE = 4096
MAX_FINDINGS = 500
ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
AREAS = {
    "hardware": ("debug_access_controlled", "sensitive_interfaces_reviewed", "physical_access_policy_reviewed"),
    "firmware": ("provenance_verified", "embedded_secrets_reviewed", "component_patch_reviewed"),
    "boot": ("boot_chain_verified", "trust_anchor_protected", "alternate_boot_paths_reviewed"),
    "updates": ("update_authenticity_verified", "rollback_policy_reviewed", "recovery_process_reviewed"),
    "mqtt": ("client_authentication_required", "topic_authorization_reviewed", "transport_protected"),
    "coap": ("peer_authentication_required", "resource_authorization_reviewed", "transport_or_object_security_reviewed"),
    "industrial": ("management_network_segmented", "write_operations_authorized", "safety_impact_reviewed"),
    "lifecycle": ("unique_credentials_verified", "decommissioning_reviewed", "security_event_logging_reviewed"),
    "ecosystem": ("companion_authorization_reviewed", "cloud_identity_scope_reviewed", "device_identity_binding_reviewed"),
}
MODES = ("normalized", "mqtt-acl", "uboot-config")
BUILD_FLAGS = ("CONFIG_FIT", "CONFIG_FIT_SIGNATURE", "CONFIG_LEGACY_IMAGE_FORMAT", "CONFIG_CMD_MEMORY")
REFERENCES = ["https://github.com/SnailSploit/Claude-Red/tree/main/Skills/iot",
    "https://mosquitto.org/man/mosquitto-conf-5.html",
    "https://docs.u-boot.org/en/latest/usage/fit/signature.html",
    "https://docs.u-boot.org/en/latest/usage/fit/verified-boot.html",
    "https://www.rfc-editor.org/rfc/rfc7252.html",
    "https://csrc.nist.gov/pubs/ir/8259/a/final"]


def catalog():
    return [{"id": "offensive-iot", "implementation": "offline-selected-iot-review",
        "fields": {a: list(fields) for a, fields in AREAS.items()},
        "native_input_modes": list(MODES[1:]), "uboot_selected_flags": list(BUILD_FLAGS),
        "device_execution_available": False, "active_exploitation_available": False,
        "required_evidence": "Private owner-normalized observations, a Mosquitto ACL file, or an owner-selected resolved U-Boot .config; hardware and runtime behavior remain unverified"}]


def _failure():
    raise ValueError("Unsupported IoT evidence syntax, type or bounds; contents withheld") from None


def _decode(raw):
    def pairs(entries):
        out = {}
        for key, value in entries:
            if key in out:
                _failure()
            out[key] = value
        return out

    def constant(_):
        _failure()

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Invalid IoT evidence JSON; contents withheld") from None


def validate_evidence(data):
    if not isinstance(data, dict) or set(data) != {"schema_version", "records"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        _failure()
    if not isinstance(data["records"], list) or not 1 <= len(data["records"]) <= 90:
        _failure()
    ids, counts = set(), {}
    for row in data["records"]:
        if not isinstance(row, dict) or set(row) != {"id", "area", "observations"}:
            _failure()
        if not isinstance(row["id"], str) or not ID.fullmatch(row["id"]) or row["id"] in ids:
            _failure()
        ids.add(row["id"])
        area = row["area"]
        if not isinstance(area, str) or area not in AREAS:
            _failure()
        counts[area] = counts.get(area, 0) + 1
        obs = row["observations"]
        if counts[area] > 10 or not isinstance(obs, dict) or set(obs) != set(AREAS[area]) or not all(v is None or type(v) is bool for v in obs.values()):
            _failure()
    return data


def _report():
    return {"engine": "iot-evidence-review", "schema_version": 1, "category": "IoT & Embedded", "skill": "offensive-iot",
        "reviewed_at": datetime.now(timezone.utc).isoformat(), "records": [], "findings": [],
        "network_requests": 0, "device_actions_executed": 0, "external_tools_executed": 0, "referenced_files_opened": 0,
        "runtime_enforcement_verified": False, "signature_verified": False, "all_skills_automated": False,
        "real_world_effectiveness": "unverified", "truncated": False, "candidates_not_retained": 0,
        "references": REFERENCES, "limitations": [
            "Selected offline declarations and syntax only; no hardware, radio, network or industrial controller interaction",
            "No firmware acquisition/unpacking, binary execution, secret extraction, credential testing, fault injection or boot modification",
            "No effective ACL evaluation, broker authentication, boot-chain verification, signed-image verification or complete standards coverage",
            "Missing evidence remains unknown; source declarations do not prove installed configuration, consent or exploitability",
            "Native identifiers, topics, users, unselected build values and source contents are withheld; protect private evidence and reports"]}


def _add(report, case, key, title, fix, *, severity="INFO", line=1):
    if len(report["findings"]) >= MAX_FINDINGS:
        report["truncated"] = True
        report["candidates_not_retained"] += 1
        return
    report["findings"].append({"rule_id": "iot-review." + key.replace("_", "-"), "skill": "offensive-iot",
        "test_case": case, "title": title, "severity": severity, "cwe": "CWE-693",
        "message": title + ". " + fix, "remediation": fix, "code": "", "file_path": "external-evidence",
        "line_start": line, "line_end": line, "engine": "iot-evidence-review", "verification_status": "unverified"})


def _finish(report):
    rows = report["records"]
    report["status"] = "insufficient-evidence" if not rows or all(r["status"] == "insufficient-evidence" for r in rows) else "partial-offline-review"
    return report


def review_evidence(data):
    validate_evidence(data)
    report = _report()
    active_controls = {"debug_access_controlled", "boot_chain_verified", "trust_anchor_protected", "update_authenticity_verified",
        "client_authentication_required", "transport_protected", "peer_authentication_required", "management_network_segmented",
        "write_operations_authorized", "unique_credentials_verified"}
    for row in data["records"]:
        obs, area = row["observations"], row["area"]
        for field, value in obs.items():
            if value is False:
                _add(report, row["id"], area + "." + field,
                    "IoT evidence declares an absent or unreviewed control: " + field.replace("_", " "),
                    "Independently review the applicable device design and owner evidence; this declaration does not demonstrate a vulnerability.",
                    severity="WARNING" if field in active_controls else "INFO")
        unknown = [f for f, v in obs.items() if v is None]
        report["records"].append({"case": row["id"], "area": area, "unknown_fields": unknown,
            "status": "insufficient-evidence" if len(unknown) == len(obs) else "partial-declared-evidence"})
    return _finish(report)


def _lines(raw):
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        _failure()
    if any(ord(c) < 32 and c not in "\r\n\t" for c in text) or "\x7f" in text:
        _failure()
    lines = text.splitlines()
    if len(lines) > MAX_LINES or any(len(line) > MAX_LINE for line in lines):
        _failure()
    return enumerate(lines, 1)


def _case(receipt, context, index):
    return "iot-" + receipt[:12] + "-" + context + "-" + str(index)


def _topic(value, pattern):
    if not value or len(value.encode("utf-8")) > 1024 or any(c.isspace() for c in value):
        _failure()  # This selected reader intentionally excludes whitespace-containing topics.
    levels = value.split("/")
    for i, level in enumerate(levels):
        if ("#" in level and (level != "#" or i != len(levels) - 1)) or ("+" in level and level != "+"):
            _failure()
        if "%" in level and (not pattern or level not in ("%u", "%c")):
            _failure()
    return levels


def _acl(raw, report, receipt):
    users, count = 0, 0
    for number, source in _lines(raw):
        if not source or source.startswith("#") or not source.strip():
            continue
        # Mosquitto comments require # in the first column; never strip inline comments.
        if source[0].isspace():
            _failure()
        parts = source.split(None, 1)
        if len(parts) != 2:
            _failure()
        directive, rest = parts
        if directive == "user":
            if not rest or len(rest) > 256 or rest != rest.strip():
                _failure()
            users += 1
            if users > 128:
                _failure()
            continue
        if directive not in ("topic", "pattern"):
            _failure()
        pieces = rest.split()
        access = "readwrite"
        if len(pieces) == 2 and pieces[0] in ("read", "write", "readwrite", "deny"):
            access, topic = pieces
        elif len(pieces) == 1:
            topic = pieces[0]
        else:
            _failure()
        levels = _topic(topic, directive == "pattern")
        count += 1
        if count > 400:
            _failure()
        case = _case(receipt, "acl", count)
        report["records"].append({"case": case, "context": "mqtt-acl", "line": number,
            "rule_kind": directive, "access": access, "scope": "pattern-global" if directive == "pattern" else ("user-section" if users else "before-user-section"),
            "status": "selected-native-syntax-only"})
        if access == "deny":
            continue
        if topic == "#":
            _add(report, case, "mqtt-acl.root-wildcard", "ACL declares a root multi-level wildcard allow rule",
                "Review intended topic scope, deny precedence and broker authentication; MQTT root wildcards do not include dollar-prefixed system topics.", line=number)
        elif access in ("write", "readwrite") and any(v in ("+", "#") for v in levels):
            _add(report, case, "mqtt-acl.wildcard-write", "ACL declares wildcard publishing scope",
                "Review intended publishing boundaries and independently evaluate effective authorization.", line=number)
        if directive == "pattern" and any(v in ("+", "#") for v in levels) and not any(v in ("%u", "%c") for v in levels):
            _add(report, case, "mqtt-acl.unbound-pattern", "Wildcard pattern lacks a selected username/client-ID substitution",
                "Review whether shared scope is intentional; pattern rules apply independently of user sections and client IDs are not proof of identity.", line=number)
        if directive == "topic" and not users:
            _add(report, case, "mqtt-acl.before-user", "Topic allow rule appears before a user section",
                "Review broker authentication and intended anonymous ACL scope; the ACL file alone does not prove anonymous connections are permitted.", line=number)
        if topic.startswith("$SYS/") and access in ("write", "readwrite"):
            _add(report, case, "mqtt-acl.system-write", "ACL declares publishing scope in the system namespace",
                "Review broker-supported system-topic behavior; this declaration does not prove system-topic writes are accepted.", line=number)
    report["source_review"] = {"acl_rules_reviewed": count, "user_sections_seen": users, "effective_permissions_computed": False}
    return _finish(report)


def _build(raw, report, receipt):
    seen, selected = set(), {}
    for number, source in _lines(raw):
        if not source:
            continue
        unset = re.fullmatch(r"# (CONFIG_[A-Z0-9_]+) is not set", source)
        if unset:
            key, value = unset[1], "n"
        elif source.startswith("#"):
            continue
        else:
            match = re.fullmatch(r"(CONFIG_[A-Z0-9_]+)=(.+)", source)
            if not match:
                _failure()
            key, value = match.groups()
        if key in seen:
            _failure()
        seen.add(key)
        if key in BUILD_FLAGS:
            if value not in ("y", "n"):
                _failure()
            selected[key] = (value == "y", number)
    case = _case(receipt, "build", 1)
    report["records"].append({"case": case, "context": "uboot-config", "unknown_fields": [k for k in BUILD_FLAGS if k not in selected],
        "status": "selected-native-syntax-only" if selected else "insufficient-evidence"})
    for key, bad, title, fix in (
        ("CONFIG_FIT_SIGNATURE", False, "Build explicitly disables FIT signature support", "Review intended boot format and alternative verification; disabled FIT support does not establish absence of every secure-boot mechanism."),
        ("CONFIG_LEGACY_IMAGE_FORMAT", True, "Build includes legacy image-format support", "Review allowed boot paths and mandatory verification; compiled support does not prove an unsigned boot path is reachable."),
        ("CONFIG_CMD_MEMORY", True, "Build includes memory-command support", "Review console access and intended maintenance features; compiled support does not prove unprivileged memory access.")):
        if key in selected and selected[key][0] == bad:
            _add(report, case, "uboot." + key.lower(), title, fix, line=selected[key][1])
    if selected.get("CONFIG_FIT_SIGNATURE", (None,))[0] is True:
        _add(report, case, "uboot.verification-policy", "Build declares FIT signature support; enforcement needs independent review",
            "Verify required keys, protected trust anchors, all selected boot paths and the actual signed artifact; enabling support alone does not prove verified boot.", line=selected["CONFIG_FIT_SIGNATURE"][1])
    report["source_review"] = {"selected_flags_seen": len(selected), "unselected_symbols_seen": len(seen) - len(selected),
        "build_fragments_merged": False, "artifact_or_boot_chain_verified": False}
    return _finish(report)


def review_file(path, *, authorized=False, mode="normalized"):
    if not authorized:
        raise PermissionError("IoT evidence review requires explicit authorization")
    if mode not in MODES:
        _failure()
    raw = read_bounded(_approved_file(path), MAX_BYTES)
    receipt = hashlib.sha256(raw).hexdigest()
    if mode == "normalized":
        report = review_evidence(_decode(raw))
    else:
        report = (_acl if mode == "mqtt-acl" else _build)(raw, _report(), receipt)
    report.update(input_sha256=receipt, input_mode=mode)
    return report
