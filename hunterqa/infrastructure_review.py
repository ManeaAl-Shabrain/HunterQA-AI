"""Offline defensive control review and a non-loading PE header reader."""
from __future__ import annotations

import hashlib
import json
import re
import struct
from datetime import datetime, timezone

from .bounty import _approved_file
from .source_files import read_bounded

MAX_BYTES = 4_194_304
MAX_FINDINGS = 500
ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
PROFILES = {
    "initial-access": ("attachment_controls_reviewed", "remote_access_mfa_required", "external_service_patch_reviewed"),
    "advanced-redteam": ("scope_verified", "segmentation_reviewed", "detection_response_exercised"),
    "edr-evasion": ("tamper_protection_enabled", "sensor_health_verified", "telemetry_coverage_reviewed"),
    "shellcode": ("dynamic_code_policy_reviewed", "unsigned_code_policy_reviewed", "execution_telemetry_reviewed"),
    "keylogger-arch": ("input_access_policy_reviewed", "sensitive_input_controls_reviewed", "collection_detection_reviewed"),
    "windows-mitigations": ("dep_policy_reviewed", "aslr_policy_reviewed", "cfg_policy_reviewed", "cet_policy_reviewed", "acg_policy_reviewed", "cig_policy_reviewed"),
    "windows-boundaries": ("least_privilege_reviewed", "integrity_boundary_reviewed", "sandbox_policy_reviewed", "broker_authorization_reviewed"),
}
FLAGS = {"high_entropy_va": 0x20, "dynamic_base": 0x40, "force_integrity": 0x80,
    "nx_compatible": 0x100, "no_seh": 0x400, "appcontainer": 0x1000, "guard_cf": 0x4000}
REFERENCES = ["https://github.com/SnailSploit/Claude-Red/tree/main/Skills/infrastructure",
    "https://learn.microsoft.com/en-us/windows/win32/debug/pe-format",
    "https://learn.microsoft.com/en-us/defender-endpoint/customize-exploit-protection"]


def catalog():
    return [{"id": "offensive-" + key, "implementation": "offline-defensive-control-review",
        "fields": list(fields), "active_exploitation_available": False, "evasion_execution_available": False,
        "native_pe_header_review_available": key == "windows-mitigations",
        "required_evidence": "Owner-normalized nullable control observations; PE header bits are optional static evidence, not process policy or proof of mitigation enforcement"}
        for key, fields in PROFILES.items()]


def _failure():
    raise ValueError("Unsupported infrastructure evidence shape, PE layout or bounds; contents withheld") from None


def _decode(raw):
    def pairs(entries):
        result = {}
        for key, value in entries:
            if key in result:
                _failure()
            result[key] = value
        return result

    def constant(_):
        _failure()

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Invalid infrastructure evidence JSON; contents withheld") from None


def validate_evidence(data):
    if not isinstance(data, dict) or set(data) != {"schema_version", "records"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        _failure()
    if not isinstance(data["records"], list) or not 1 <= len(data["records"]) <= 70:
        _failure()
    ids, counts = set(), {}
    for row in data["records"]:
        if not isinstance(row, dict) or set(row) != {"id", "skill", "observations"}:
            _failure()
        if not isinstance(row["id"], str) or not ID.fullmatch(row["id"]) or row["id"] in ids:
            _failure()
        ids.add(row["id"])
        skill = row["skill"]
        if not isinstance(skill, str) or not skill.startswith("offensive-") or skill[10:] not in PROFILES:
            _failure()
        key = skill[10:]
        counts[key] = counts.get(key, 0) + 1
        obs = row["observations"]
        if counts[key] > 10 or not isinstance(obs, dict) or set(obs) != set(PROFILES[key]) or not all(v is None or type(v) is bool for v in obs.values()):
            _failure()
    return data


def _report():
    return {"engine": "infrastructure-evidence-review", "schema_version": 1, "category": "Infrastructure & Red Team",
        "reviewed_at": datetime.now(timezone.utc).isoformat(), "records": [], "findings": [],
        "network_requests": 0, "external_tools_executed": 0, "binaries_loaded": 0, "referenced_files_opened": 0,
        "runtime_enforcement_verified": False, "signature_verified": False, "all_skills_automated": False,
        "real_world_effectiveness": "unverified", "truncated": False, "candidates_not_retained": 0,
        "references": REFERENCES, "limitations": [
            "Offline defensive control and selected header syntax review only; no live infrastructure assessment",
            "No EDR evasion, payload generation/injection, input capture, initial access, C2, lateral movement, persistence or boundary bypass execution",
            "PE headers do not establish loaded process policy, code instrumentation, OS/hardware support, signature validity or effective security",
            "No disassembly, emulation, dependency loading, unpacking, malware classification, exploitability proof or complete standards coverage",
            "Missing evidence remains unassessed; operator authorization is not independently verified owner consent",
            "Native names, paths, strings and section contents are withheld; use neutral IDs and protect private evidence"]}


def _add(report, case, skill, key, title, fix, *, severity="INFO"):
    if len(report["findings"]) >= MAX_FINDINGS:
        report["truncated"] = True
        report["candidates_not_retained"] += 1
        return
    report["findings"].append({"rule_id": "infrastructure-review." + key.replace("_", "-"), "skill": skill,
        "test_case": case, "title": title, "severity": severity, "cwe": "CWE-693",
        "message": title + ". " + fix, "remediation": fix, "code": "", "file_path": "external-evidence",
        "line_start": 1, "line_end": 1, "engine": "infrastructure-evidence-review", "verification_status": "unverified"})


def _finish(report):
    rows = report["records"]
    report["status"] = "insufficient-evidence" if not rows or all(r["status"] == "insufficient-evidence" for r in rows) else "partial-offline-review"
    return report


def review_evidence(data):
    validate_evidence(data)
    report = _report()
    for row in data["records"]:
        obs = row["observations"]
        for field, value in obs.items():
            if value is False:
                _add(report, row["id"], row["skill"], row["skill"][10:] + "." + field,
                    "Owner evidence declares an absent or unreviewed control: " + field.replace("_", " "),
                    "Independently review applicability, source evidence and actual enforcement; this declaration does not demonstrate compromise.",
                    severity="WARNING" if field in ("remote_access_mfa_required", "tamper_protection_enabled", "sensor_health_verified") else "INFO")
        unknown = [f for f, v in obs.items() if v is None]
        report["records"].append({"case": row["id"], "skill": row["skill"], "unknown_fields": unknown,
            "status": "insufficient-evidence" if len(unknown) == len(obs) else "partial-declared-evidence"})
    return _finish(report)


def _pe(raw, receipt):
    # Read scalar header fields only. Never map, load, execute or resolve imports.
    def scalar(fmt, offset):
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(raw):
            _failure()
        return struct.unpack_from(fmt, raw, offset)[0]

    if len(raw) < 64 or raw[:2] != b"MZ":
        _failure()
    pe = scalar("<I", 0x3C)
    if pe < 64 or pe + 24 > len(raw) or raw[pe:pe + 4] != b"PE\0\0":
        _failure()
    coff = pe + 4
    machine, sections = scalar("<H", coff), scalar("<H", coff + 2)
    optional_size, characteristics = scalar("<H", coff + 16), scalar("<H", coff + 18)
    if machine not in (0x14C, 0x8664, 0xAA64) or not 1 <= sections <= 96 or not characteristics & 0x2 or not 96 <= optional_size <= 4096:
        _failure()
    optional = coff + 20
    magic = scalar("<H", optional)
    if (machine == 0x14C and magic != 0x10B) or (machine != 0x14C and magic != 0x20B):
        _failure()
    is64 = magic == 0x20B
    fixed = 112 if is64 else 96
    if optional_size < fixed or optional + optional_size > len(raw):
        _failure()
    directories = scalar("<I", optional + fixed - 4)
    if directories > 16 or fixed + directories * 8 > optional_size:
        _failure()
    table = optional + optional_size
    headers = scalar("<I", optional + 60)
    if table + sections * 40 > len(raw) or not table + sections * 40 <= headers <= len(raw):
        _failure()
    report = _report()
    case = "infra-" + receipt[:12] + "-pe"
    skill = "offensive-windows-mitigations"
    flags = {k: bool(scalar("<H", optional + 70) & mask) for k, mask in FLAGS.items()}
    report["records"].append({"case": case, "skill": skill, "context": "pe-headers", "status": "selected-native-syntax-only",
        "machine": {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64"}[machine], "format": "PE32+" if is64 else "PE32",
        "declared_header_flags": flags, "section_count": sections})
    cues = []
    if not flags["dynamic_base"]:
        cues.append(("dynamic-base-absent", "PE header does not declare dynamic-base support", "Review relocations, mandatory ASLR policy and the actual loaded process; the bit alone does not prove predictable addresses."))
    if not flags["nx_compatible"] and not is64:
        cues.append(("nx-compatible-absent", "x86 PE header does not declare NX compatibility", "Review actual DEP policy and compatibility requirements; the file bit alone does not prove executable data pages."))
    if is64 and flags["dynamic_base"] and not flags["high_entropy_va"]:
        cues.append(("high-entropy-absent", "64-bit dynamic-base image lacks the high-entropy header bit", "Review architecture/OS support and loaded process policy; effective address entropy is not measured."))
    if not flags["guard_cf"]:
        cues.append(("guard-cf-absent", "PE header does not declare Control Flow Guard support", "Review the actual build, instrumentation, load configuration and process policy; applicability is not established."))
    else:
        cues.append(("guard-cf-declaration", "PE header declares CFG support requiring independent verification", "Code instrumentation, load configuration and runtime enforcement are not verified by this reader."))
    if flags["appcontainer"]:
        cues.append(("appcontainer-declaration", "PE header declares an AppContainer image", "Verify actual packaging, process token, capabilities and broker boundaries; a file bit does not prove isolation."))
    if flags["force_integrity"]:
        cues.append(("integrity-declaration", "PE header declares forced integrity checking", "Verify the actual signature, loader policy and trust chain separately; this reader does not validate signatures."))
    for key, title, fix in cues:
        _add(report, case, skill, "pe." + key, title, fix)
    spans = []
    for i in range(sections):
        section = table + i * 40
        size, pointer = scalar("<I", section + 16), scalar("<I", section + 20)
        if size:
            if pointer < headers or pointer + size > len(raw) or any(pointer < end and pointer + size > start for start, end in spans):
                _failure()
            spans.append((pointer, pointer + size))
        permissions = scalar("<I", section + 36)
        if permissions & 0xA0000000 == 0xA0000000:
            section_case = "infra-" + receipt[:12] + "-section-" + str(i + 1)
            report["records"].append({"case": section_case, "skill": skill, "context": "pe-section", "section_index": i + 1,
                "status": "selected-native-syntax-only", "raw_content_present": bool(size)})
            _add(report, section_case, skill, "pe.writable-executable-section", "Section header declares writable and executable characteristics",
                "Review intended layout, runtime page protections and approved exceptions; declared characteristics do not establish malicious code or live writable/executable memory.")
    report["source_review"] = {"file_headers_only": True, "native_source_line_locations_available": False,
        "load_config_or_relocations_verified": False, "cet_acg_cig_sehop_verified": False,
        "complete_pe_validity_checked": False, "dependencies_loaded": 0}
    return _finish(report)


def review_file(path, *, authorized=False, mode="normalized"):
    if not authorized:
        raise PermissionError("Infrastructure evidence review requires explicit authorization")
    if mode not in ("normalized", "pe-headers"):
        _failure()
    raw = read_bounded(_approved_file(path), MAX_BYTES)
    receipt = hashlib.sha256(raw).hexdigest()
    report = review_evidence(_decode(raw)) if mode == "normalized" else _pe(raw, receipt)
    report.update(input_sha256=receipt, input_mode=mode)
    return report
