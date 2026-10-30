"""Offline evidence-integrity/C2 assurance and selected saved Windows/DNS log review."""
from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from .bounty import _approved_file
from .source_files import read_bounded

MAX_BYTES = 1_048_576
MAX_FINDINGS = 500
ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
PROFILES = {
    "anti-forensics": ("log_retention_reviewed", "central_collection_reviewed", "tamper_alerting_reviewed", "time_integrity_reviewed", "immutable_evidence_reviewed", "chain_of_custody_reviewed", "incident_preservation_reviewed"),
    "c2-frameworks": ("framework_inventory_reviewed", "operator_access_reviewed", "network_isolation_reviewed", "transport_visibility_reviewed", "domain_and_egress_policy_reviewed", "session_audit_reviewed", "revocation_and_cleanup_reviewed"),
}
REFERENCES = ["https://github.com/SnailSploit/Claude-Red/tree/main/Skills/forensics",
    "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102",
    "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4719",
    "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616",
    "https://docs.zeek.org/en/current/reference/logs/dns.html"]


def catalog():
    return [{"id": "offensive-" + key, "implementation": "offline-forensics-assurance-review", "fields": list(fields),
        "native_input_modes": ["windows-events-xml"] if key == "anti-forensics" else ["zeek-dns-jsonl"],
        "active_exploitation_available": False,
        "required_evidence": "Private owner observations or selected saved Windows/DNS logs; provenance, evidence integrity, malicious intent and C2 attribution remain unverified"}
        for key, fields in PROFILES.items()]


def _failure():
    raise ValueError("Unsupported forensics evidence shape, selected field or bounds; contents withheld") from None


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
        raise ValueError("Invalid forensics evidence JSON; contents withheld") from None
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
    return {"engine": "forensics-evidence-review", "schema_version": 1, "category": "Forensics & C2",
        "reviewed_at": datetime.now(timezone.utc).isoformat(), "records": [], "findings": [],
        "network_requests": 0, "external_tools_executed": 0, "referenced_files_opened": 0,
        "evidence_integrity_verified": False, "malicious_activity_verified": False, "c2_attribution_verified": False,
        "all_skills_automated": False, "real_world_effectiveness": "unverified", "truncated": False, "candidates_not_retained": 0,
        "references": REFERENCES, "limitations": [
            "Selected saved Windows event XML and Zeek DNS JSONL only; no host collection, execution, endpoint contact or DNS queries",
            "No evidence/log alteration, timestamp mutation, secure deletion, payload/agent generation, C2 deployment or remote tasking",
            "No EVTX/PCAP parsing, full event/DNS schema validation, timeline correlation, signature verification, chain-of-custody proof or C2 framework attribution",
            "Administrative audit/time changes, TXT queries and long query strings can be legitimate; indicators require independent baseline/context review",
            "Missing context stays unknown; unsupported records are counted and no findings is not proof of no tampering or C2",
            "Names, accounts, addresses, domains, commands, timestamps and raw source values are withheld; hashes do not establish provenance or owner consent"]}



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
    report["findings"].append({"rule_id": "forensics-review." + key.replace("_", "-"), "skill": skill,
        "test_case": case, "title": title, "severity": "INFO", "cwe": "CWE-693",
        "message": title + ". " + fix, "remediation": fix, "code": "", "file_path": "external-evidence",
        "line_start": 1, "line_end": 1, "engine": "forensics-evidence-review", "verification_status": "unverified"})


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
                _add(report, row["id"], skill, key + "." + field, "Owner evidence declares incomplete forensics assurance: " + field.replace("_", " "),
                    "Review applicable evidence preservation, authorized framework governance and independent evidence; this declaration does not demonstrate a vulnerability.")
        unknown = [f for f, v in obs.items() if v is None]
        _record(report, row["id"], skill, "owner-evidence", unknown_fields=unknown,
            status="insufficient-evidence" if len(unknown) == len(obs) else "partial-declared-evidence")
    return _finish(report)

EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
DEFAULT_LONG_QUERY_CHARS = 80
EVENTS = {
    1102: ("Microsoft-Windows-Eventlog", "log-clear", "Saved event declares Security audit-log clearing"),
    4719: ("Microsoft-Windows-Security-Auditing", "audit-policy-change", "Saved event declares system audit-policy change"),
    4616: ("Microsoft-Windows-Security-Auditing", "system-time-change", "Saved event declares system time change"),
}


def _one(node, name):
    matches = node.findall(EVENT_NS + name) if node is not None else []
    if len(matches) > 1:
        _failure()
    return matches[0] if matches else None


def _scalar(node, name):
    child = _one(node, name)
    if child is None:
        return None
    if len(child):
        _failure()
    value = (child.text or "").strip()
    if len(value) > 256:
        _failure()
    return value


def _events(raw, receipt):
    try:
        root = ElementTree.fromstring(raw, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except (ElementTree.ParseError, DefusedXmlException, ValueError, UnicodeError, LookupError, RecursionError):
        raise ValueError("Invalid or forbidden event XML; contents withheld") from None
    count, stack = 0, [(root, 0)]
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > 20000 or depth > 40:
            _failure()
        stack.extend((child, depth + 1) for child in node)
    if root.tag == EVENT_NS + "Event":
        rows = [root]
    elif root.tag in ("Events", EVENT_NS + "Events"):
        rows = list(root)
    else:
        _failure()
    if len(rows) > 1000:
        _failure()
    report, unsupported, unmatched = _report(), 0, 0
    for index, event in enumerate(rows, 1):
        if event.tag != EVENT_NS + "Event":
            unsupported += 1
            continue
        system = _one(event, "System")
        value, channel = _scalar(system, "EventID"), _scalar(system, "Channel")
        if value is not None and (not value.isascii() or not value.isdigit() or len(value) > 5 or int(value) > 65535):
            _failure()
        number = int(value) if value is not None else None
        provider = _one(system, "Provider")
        name = provider.get("Name") if provider is not None else None
        selected = EVENTS.get(number)
        context = bool(selected and name == selected[0] and channel == "Security")
        if selected and not context:
            unmatched += 1
        case = "forensic-" + receipt[:12] + "-event-" + str(index)
        _record(report, case, "offensive-anti-forensics", "windows-events-xml",
            event_class=selected[1] if context else ("context-unverified" if selected else "other-or-unknown"),
            selected_provider_and_channel_matched=context,
            status="insufficient-evidence" if not context else "selected-declaration-only")
        if context:
            _add(report, case, "offensive-anti-forensics", selected[1], selected[2],
                "Preserve the original evidence and compare authorized maintenance, collection provenance, central copies and the audit/time baseline. This saved declaration does not establish unauthorized tampering or source authenticity.")
    report["source_review"] = {"xml_nodes": count, "unsupported_elements_not_reviewed": unsupported,
        "selected_events_without_matching_context": unmatched, "complete_event_schema_validation": False,
        "timeline_or_signature_verification_performed": False}
    return _finish(report)


def _text(value, maximum):
    if value is not None and (not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 for c in value)):
        _failure()
    return value


def _dns(raw, receipt, threshold):
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError:
        raise ValueError("Invalid saved DNS text; contents withheld") from None
    lines = text.splitlines()
    if len(lines) > 1000 or any(len(line) > 16384 for line in lines):
        _failure()
    report, unsupported = _report(), 0
    for index, line in enumerate(lines, 1):
        if not line.strip():
            continue
        row = _decode(line)
        if not isinstance(row, dict) or not any(key in row for key in ("query", "qtype_name", "rcode_name")):
            unsupported += 1
            continue
        query = _text(row.get("query"), 4096)
        qtype = _text(row.get("qtype_name"), 32)
        rcode = _text(row.get("rcode_name"), 32)
        rejected = row.get("rejected")
        if rejected is not None and type(rejected) is not bool:
            _failure()
        long_query = query not in (None, "", "-") and len(query.rstrip(".")) >= threshold
        txt = qtype is not None and qtype.upper() == "TXT"
        case = "forensic-" + receipt[:12] + "-dns-" + str(index)
        _record(report, case, "offensive-c2-frameworks", "zeek-dns-jsonl",
            txt_query_declared=txt if qtype else None, long_query_declared=bool(long_query) if query not in (None, "", "-") else None,
            response_class="unknown" if not rcode else ("nxdomain" if rcode.upper() == "NXDOMAIN" else "other-declared"),
            rejected_declaration=rejected,
            status="insufficient-evidence" if all(v in (None, "", "-") for v in (query, qtype, rcode)) else "selected-declaration-only")
        cues = [(txt, "txt-query", "Saved DNS record declares a TXT query"),
            (long_query, "long-query", "Saved DNS query string reaches the selected character threshold")]
        for condition, key, title in cues:
            if condition:
                _add(report, case, "offensive-c2-frameworks", key, title,
                    "Compare the approved DNS/application baseline, endpoint telemetry, resolver visibility and authorized test inventory. TXT and long names are often legitimate; query metadata alone does not establish a tunnel, beacon, successful response or C2 framework.")
    report["source_review"] = {"unsupported_rows_not_reviewed": unsupported, "long_query_threshold_chars": threshold,
        "complete_dns_schema_validation": False, "query_syntax_validated": False, "aggregation_or_timing_analysis_performed": False,
        "answers_or_payloads_inspected": False}
    return _finish(report)


def review_file(path, *, authorized=False, mode="normalized", long_query_chars=DEFAULT_LONG_QUERY_CHARS):
    if not authorized:
        raise PermissionError("Forensics evidence review requires explicit authorization")
    if mode not in ("normalized", "windows-events-xml", "zeek-dns-jsonl") or type(long_query_chars) is not int or not 1 <= long_query_chars <= 4096:
        _failure()
    raw = read_bounded(_approved_file(path), MAX_BYTES)
    receipt = hashlib.sha256(raw).hexdigest()
    if mode == "normalized":
        report = review_evidence(_decode(raw))
    elif mode == "windows-events-xml":
        report = _events(raw, receipt)
    else:
        report = _dns(raw, receipt, long_query_chars)
    report.update(input_sha256=receipt, input_mode=mode)
    return report
