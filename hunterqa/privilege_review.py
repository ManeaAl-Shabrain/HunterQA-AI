"""Offline privilege assurance and selected saved Linux/Windows inventory checks."""
from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone

from .bounty import _approved_file
from .source_files import read_bounded

MAX_BYTES = 1_048_576
MAX_FINDINGS = 500
ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
PROFILES = {
    "linux-privesc": ("sudo_policy_reviewed", "setid_files_reviewed", "file_capabilities_reviewed", "scheduled_jobs_reviewed", "service_permissions_reviewed", "namespace_boundaries_reviewed", "patch_status_reviewed"),
    "windows-privesc": ("service_permissions_reviewed", "service_paths_reviewed", "token_privileges_reviewed", "scheduled_tasks_reviewed", "installer_policy_reviewed", "dll_search_policy_reviewed", "patch_status_reviewed"),
}
REFERENCES = ["https://github.com/SnailSploit/Claude-Red/tree/main/Skills/privesc",
    "https://man7.org/linux/man-pages/man8/getcap.8.html", "https://man7.org/linux/man-pages/man7/capabilities.7.html",
    "https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service",
    "https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew"]


def catalog():
    return [{"id": "offensive-" + key, "implementation": "offline-privilege-assurance-review", "fields": list(fields),
        "native_input_modes": ["getcap-text"] if key == "linux-privesc" else ["windows-services-json"],
        "active_exploitation_available": False,
        "required_evidence": "Private owner observations or selected saved file-capability/service declarations; effective permissions and exploitability remain unverified"}
        for key, fields in PROFILES.items()]


def _failure():
    raise ValueError("Unsupported privilege evidence shape, selected field or bounds; contents withheld") from None


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
        data = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Invalid privilege evidence JSON; contents withheld") from None
    stack, count = [(data, 0)], 0
    while stack:
        value, depth = stack.pop()
        count += 1
        if count > 20000 or depth > 40 or (isinstance(value, float) and not math.isfinite(value)):
            _failure()
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
    return data


def _report():
    return {"engine": "privilege-evidence-review", "schema_version": 1, "category": "Privilege Escalation",
        "reviewed_at": datetime.now(timezone.utc).isoformat(), "records": [], "findings": [],
        "network_requests": 0, "external_tools_executed": 0, "referenced_files_opened": 0,
        "effective_permissions_verified": False, "privilege_escalation_verified": False,
        "all_skills_automated": False, "real_world_effectiveness": "unverified", "truncated": False, "candidates_not_retained": 0,
        "references": REFERENCES, "limitations": [
            "Selected saved Linux getcap text and Windows Win32_Service JSON only; no host enumeration, process execution, network traffic or system mutation",
            "No file/service ACL resolution, user/group/token membership, namespace/bounding-set calculation, path expansion or executable resolution",
            "No sudoers/SUID/cron/systemd/registry/task/DLL parsing, patch/CVE matching or active privilege escalation",
            "Unsupported getcap lines are counted as unreviewed; no finding does not establish absence of privileges",
            "Service path ambiguity does not establish attacker write access, restart ability or a usable privilege boundary",
            "Source paths, accounts, commands and private values are withheld; receipts do not establish provenance or consent"]}



def _record(report, case, skill, context, **fields):
    if len(report["records"]) >= 2000:
        _failure()
    row = {"case": case, "skill": skill, "context": context, "status": "selected-declaration-only", **fields}
    report["records"].append(row)
    return row


def _add(report, case, skill, key, title, fix):
    if len(report["findings"]) >= MAX_FINDINGS:
        report["truncated"] = True
        report["candidates_not_retained"] += 1
        return
    report["findings"].append({"rule_id": "privilege-review." + key.replace("_", "-"), "skill": skill,
        "test_case": case, "title": title, "severity": "INFO", "cwe": "CWE-693",
        "message": title + ". " + fix, "remediation": fix, "code": "", "file_path": "external-evidence",
        "line_start": 1, "line_end": 1, "engine": "privilege-evidence-review", "verification_status": "unverified"})


def _finish(report):
    rows = report["records"]
    report["status"] = "insufficient-evidence" if not rows or all(r["status"] == "insufficient-evidence" for r in rows) else "partial-offline-review"
    return report


def review_evidence(data):
    if not isinstance(data, dict) or set(data) != {"schema_version", "records"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        _failure()
    if not isinstance(data["records"], list) or not 1 <= len(data["records"]) <= 20:
        _failure()
    report, ids, counts = _report(), set(), {}
    for row in data["records"]:
        if not isinstance(row, dict) or set(row) != {"id", "skill", "observations"}:
            _failure()
        if not isinstance(row["id"], str) or not ID.fullmatch(row["id"]) or row["id"] in ids:
            _failure()
        ids.add(row["id"])
        skill, obs = row["skill"], row["observations"]
        if not isinstance(skill, str) or not skill.startswith("offensive-") or skill[10:] not in PROFILES:
            _failure()
        key = skill[10:]
        counts[key] = counts.get(key, 0) + 1
        if counts[key] > 10 or not isinstance(obs, dict) or set(obs) != set(PROFILES[key]) or not all(v is None or type(v) is bool for v in obs.values()):
            _failure()
        for field, value in obs.items():
            if value is False:
                _add(report, row["id"], skill, key + "." + field, "Owner evidence declares incomplete privilege assurance: " + field.replace("_", " "),
                    "Review applicable privilege boundaries, actual permission checks and independent evidence; this declaration does not demonstrate a vulnerability.")
        unknown = [f for f, v in obs.items() if v is None]
        _record(report, row["id"], skill, "owner-evidence", unknown_fields=unknown,
            status="insufficient-evidence" if len(unknown) == len(obs) else "partial-declared-evidence")
    return _finish(report)





CAPS = {"cap_setuid", "cap_setgid", "cap_dac_override", "cap_dac_read_search", "cap_sys_admin", "cap_sys_ptrace", "cap_sys_module", "cap_setpcap", "cap_setfcap"}
CAP_LIST = r"cap_[a-z0-9_]{1,64}(?:,cap_[a-z0-9_]{1,64})*"
CAP_CLAUSE = CAP_LIST + r"=[eip]{1,3}"
CAP_START = re.compile(r"\s+(?=" + CAP_CLAUSE + r"(?:\s|$))")
CAP_TEXT = re.compile(CAP_CLAUSE + r"(?:\s+" + CAP_CLAUSE + r")*\Z")
ROOT_ID = re.compile(r" \[rootid=([0-9]{1,10})\]\Z")
EXE = re.compile(r"\.exe(?=\s|$)", re.I)


def _getcap(raw, receipt):
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError:
        raise ValueError("Invalid saved capability text; contents withheld") from None
    lines = text.splitlines()
    if len(lines) > 1000 or any(len(line) > 4096 or any(ord(c) < 32 and c != "\t" for c in line) for line in lines):
        _failure()
    report, unreviewed, nonblank = _report(), 0, 0
    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        nonblank += 1
        root = ROOT_ID.search(line)
        root_declared = root is not None
        if root:
            line = line[:root.start()]
        empty = line.endswith(" =") and len(line) > 2
        start = CAP_START.search(line)
        if not empty and (not start or not CAP_TEXT.fullmatch(line[start.end():])):
            unreviewed += 1
            continue
        selected, seen, valid = set(), set(), True
        if not empty:
            for clause in line[start.end():].split():
                names, flags = clause.split("=")
                if len(set(flags)) != len(flags):
                    valid = False
                for name in names.split(","):
                    if name in seen:
                        valid = False
                    seen.add(name)
                    if name in CAPS:
                        selected.add(name)
            if len(seen) > 64:
                valid = False
        if not valid:
            unreviewed += 1
            continue
        case = "priv-" + receipt[:12] + "-cap-" + str(i)
        _record(report, case, "offensive-linux-privesc", "getcap-text", selected_capability_count=len(selected),
            empty_capability_declaration=empty, namespace_root_id_declared=root_declared, namespace_mapping_verified=False)
        if selected:
            _add(report, case, "offensive-linux-privesc", "selected-file-capabilities", "Saved file declaration contains selected sensitive capabilities",
                "Review intended duties, executable contents, file ownership/mount policy, user namespaces, bounding sets and actual invocation. Capability text alone does not prove effective privilege or exploitability.")
    report["source_review"] = {"nonblank_lines": nonblank, "unsupported_lines_not_reviewed": unreviewed,
        "complete_capability_format_support": False, "referenced_files_inspected": False}
    return _finish(report)


def _text(value, maximum=4096):
    if value is not None and (not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 for c in value)):
        _failure()
    return value


def _windows(data, receipt):
    rows = data if isinstance(data, list) else [data]
    if len(rows) > 1000:
        _failure()
    report = _report()
    for i, service in enumerate(rows, 1):
        if not isinstance(service, dict) or "PathName" not in service:
            _failure()
        path = _text(service["PathName"])
        account = _text(service.get("StartName"), 512)
        mode = _text(service.get("StartMode"), 64)
        kind = _text(service.get("ServiceType"), 128)
        if mode is not None and mode not in ("Boot", "System", "Auto", "Manual", "Disabled", "Automatic", "Unknown"):
            _failure()
        case = "priv-" + receipt[:12] + "-svc-" + str(i)
        own_process = kind in ("Own Process", "Share Process", "Interactive Process", "Win32 Own Process", "Win32 Share Process")
        classification = "unknown"
        if own_process and path and not any(v in path for v in ("%", "${")):
            command = path.strip()
            if command.startswith('"'):
                classification = "quoted-prefix-not-resolved" if '"' in command[1:] else "unknown"
            elif (re.match(r"[A-Za-z]:[\\/]", command) or command.startswith("\\\\")):
                match = EXE.search(command)
                if match:
                    prefix = command[:match.end()]
                    classification = "unquoted-spaced-exe" if any(c.isspace() for c in prefix) else "unquoted-simple-exe"
        _record(report, case, "offensive-windows-privesc", "windows-services-json",
            status="insufficient-evidence" if all(v is None for v in (path, account, mode, kind)) else "selected-declaration-only",
            path_classification=classification,
            local_system_name_declared=account.casefold() in ("localsystem", "nt authority\\system") if account else None,
            startup_declaration="disabled" if mode == "Disabled" else ("other-declared" if mode else "unknown"),
            process_service_type_recognized=own_process, effective_access_verified=False)
        if classification == "unquoted-spaced-exe":
            _add(report, case, "offensive-windows-privesc", "unquoted-service-path", "Saved process-service executable prefix is unquoted and contains whitespace",
                "Quote the intended executable path and independently review prefix-directory/file ACLs, actual service identity, restart rights and execution context. No writable path, successful start or privilege escalation is demonstrated.")
    report["source_review"] = {"services_reviewed": len(rows), "complete_service_validation": False,
        "path_expansion_performed": False, "service_or_file_acls_resolved": False}
    return _finish(report)


def review_file(path, *, authorized=False, mode="normalized"):
    if not authorized:
        raise PermissionError("Privilege evidence review requires explicit authorization")
    if mode not in ("normalized", "getcap-text", "windows-services-json"):
        _failure()
    raw = read_bounded(_approved_file(path), MAX_BYTES)
    receipt = hashlib.sha256(raw).hexdigest()
    report = _getcap(raw, receipt) if mode == "getcap-text" else (review_evidence(_decode(raw)) if mode == "normalized" else _windows(_decode(raw), receipt))
    report.update(input_sha256=receipt, input_mode=mode)
    return report
