"""Offline network assurance and selected saved sysctl/resolved declarations."""
from __future__ import annotations

import configparser
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
    "network-attacks": ("arp_inspection_reviewed", "name_resolution_policy_reviewed", "vlan_segmentation_reviewed", "dhcp_snooping_reviewed", "nac_policy_reviewed", "ipv6_ra_guard_reviewed", "management_plane_reviewed", "traffic_monitoring_reviewed"),
}
REFERENCES = ["https://github.com/SnailSploit/Claude-Red/tree/main/Skills/network",
    "https://docs.kernel.org/networking/ip-sysctl.html",
    "https://www.freedesktop.org/software/systemd/man/latest/resolved.conf.html"]


def catalog():
    return [{"id": "offensive-" + key, "implementation": "offline-network-assurance-review", "fields": list(fields),
        "native_input_modes": ["sysctl-text", "resolved-conf"],
        "active_exploitation_available": False,
        "required_evidence": "Private owner observations or selected saved Linux network/resolver settings; effective interface policy, network topology and exploitability remain unverified"}
        for key, fields in PROFILES.items()]


def _failure():
    raise ValueError("Unsupported network evidence shape, selected field or bounds; contents withheld") from None


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
        raise ValueError("Invalid network evidence JSON; contents withheld") from None
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
    return {"engine": "network-evidence-review", "schema_version": 1, "category": "Network",
        "reviewed_at": datetime.now(timezone.utc).isoformat(), "records": [], "findings": [],
        "network_requests": 0, "external_tools_executed": 0, "referenced_files_opened": 0,
        "effective_interface_policy_verified": False, "network_topology_verified": False, "exploitability_verified": False,
        "all_skills_automated": False, "real_world_effectiveness": "unverified", "truncated": False, "candidates_not_retained": 0,
        "references": REFERENCES, "limitations": [
            "Selected saved Linux sysctl and systemd-resolved declarations only; no host collection, DNS resolution, packet transmission or configuration changes",
            "No ARP/DNS/LLMNR poisoning, interception, VLAN hopping, DHCP/RA injection, NAC bypass or credential access",
            "No all/default/interface combination, forwarding-role calculation, drop-in/config precedence, per-link resolution or runtime verification",
            "Forwarding and multicast resolution can be intentional; IPv4/IPv6 settings have distinct semantics and no security verdict follows from a declaration alone",
            "Switch/ARP/DHCP/NAC/RA controls use owner observations only; missing settings remain unknown and unsupported assignments are counted",
            "Interface names, addresses, domains, private config values and paths are withheld; receipts do not prove current state, provenance or owner consent"]}



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
    report["findings"].append({"rule_id": "network-review." + key.replace("_", "-"), "skill": skill,
        "test_case": case, "title": title, "severity": "INFO", "cwe": "CWE-693",
        "message": title + ". " + fix, "remediation": fix, "code": "", "file_path": "external-evidence",
        "line_start": 1, "line_end": 1, "engine": "network-evidence-review", "verification_status": "unverified"})


def _finish(report):
    rows = report["records"]
    report["status"] = "insufficient-evidence" if not rows or all(r["status"] == "insufficient-evidence" for r in rows) else "partial-offline-review"
    return report


def review_evidence(data):
    if not isinstance(data, dict) or set(data) != {"schema_version", "records"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        _failure()
    if not isinstance(data["records"], list) or not 1 <= len(data["records"]) <= 10:
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
                _add(report, row["id"], skill, key + "." + field, "Owner evidence declares incomplete network assurance: " + field.replace("_", " "),
                    "Review applicable network roles, topology, effective interface/switch policy and independent evidence; this declaration does not demonstrate a vulnerability.")
        unknown = [f for f, v in obs.items() if v is None]
        _record(report, row["id"], skill, "owner-evidence", unknown_fields=unknown,
            status="insufficient-evidence" if len(unknown) == len(obs) else "partial-declared-evidence")
    return _finish(report)

MODES = ("normalized", "sysctl-text", "resolved-conf")
# Only these integer declarations are supported. No effective-policy combination.
SYSCTL_RULES = {
    ("ipv4", "accept_redirects"): ({0, 1}, {1}),
    ("ipv4", "accept_source_route"): ({0, 1}, {1}),
    ("ipv4", "send_redirects"): ({0, 1}, {1}),
    ("ipv4", "secure_redirects"): ({0, 1}, {0}),
    ("ipv4", "rp_filter"): ({0, 1, 2}, {0}),
    ("ipv6", "accept_redirects"): ({0, 1}, {1}),
    ("ipv6", "accept_ra"): ({0, 1, 2}, {2}),
    ("ipv6", "forwarding"): ({0, 1}, {1}),
}
SYSCTL_KEY = re.compile(r"net\.(ipv4|ipv6)\.conf\.([A-Za-z0-9_-]{1,32})\.([a-z_]+)\Z")
BOOLS = {"yes":"yes", "true":"yes", "on":"yes", "1":"yes", "no":"no", "false":"no", "off":"no", "0":"no"}
RESOLVED_SPECIAL = {"LLMNR":"resolve", "MulticastDNS":"resolve", "DNSSEC":"allow-downgrade", "DNSOverTLS":"opportunistic"}


def _lines(raw):
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError:
        raise ValueError("Invalid saved network configuration text; contents withheld") from None
    lines = text.splitlines()
    if len(lines) > 1000 or any(len(line) > 4096 or any(ord(c) < 32 and c != "\t" for c in line) for line in lines):
        _failure()
    return text, lines


def _sysctl(raw, receipt):
    _, lines = _lines(raw)
    report, unsupported, seen = _report(), 0, set()
    for index, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        key, separator, value = line.partition("=")
        key, value = key.strip(), value.strip()
        match = SYSCTL_KEY.fullmatch(key)
        if key == "net.ipv4.ip_forward":
            family, scope, setting, rule = "ipv4", "global", "ip_forward", ({0, 1}, {1})
        elif match and (match[1], match[3]) in SYSCTL_RULES:
            family, scope, setting = match.groups()
            rule = SYSCTL_RULES[(family, setting)]
        else:
            unsupported += 1
            continue
        if not separator or key in seen or not re.fullmatch(r"[0-9]{1,3}", value) or int(value) not in rule[0]:
            _failure()
        seen.add(key)
        number = int(value)
        case = "net-" + receipt[:12] + "-sysctl-" + str(index)
        _record(report, case, "offensive-network-attacks", "sysctl-text", family=family, setting=setting,
            scope_class="global" if key == "net.ipv4.ip_forward" else (scope if scope in ("all", "default") else "interface"), integer_declaration=number,
            effective_combination_computed=False)
        if number in rule[1]:
            _add(report, case, "offensive-network-attacks", family + "-" + setting, "Saved " + family + " declaration has " + setting + "=" + str(number),
                "Review intended host/router and asymmetric-routing roles, all/default/interface interactions, mount/network namespace and actual runtime policy. This declaration alone does not establish a spoofing, redirect or interception vulnerability; do not apply a blanket setting without context.")
    report["source_review"] = {"unsupported_assignments_not_reviewed": unsupported, "complete_sysctl_parsing": False,
        "interface_names_exported": False, "role_or_effective_policy_computed": False}
    return _finish(report)


def _resolved(raw, receipt):
    text, _ = _lines(raw)
    parser = configparser.ConfigParser(interpolation=None, strict=True, empty_lines_in_values=False)
    parser.optionxform = str
    try:
        parser.read_string(text)
    except configparser.Error:
        raise ValueError("Invalid saved resolver configuration; contents withheld") from None
    if parser.defaults():
        _failure()
    report, unsupported, index = _report(), 0, 0
    for section in parser.sections():
        for key, value in parser.items(section, raw=True):
            if section != "Resolve" or key not in RESOLVED_SPECIAL:
                unsupported += 1
                continue
            normalized = value.strip().lower()
            if not normalized:
                declared = "unknown"
            elif normalized in BOOLS:
                declared = BOOLS[normalized]
            elif normalized == RESOLVED_SPECIAL[key]:
                declared = normalized
            else:
                _failure()
            index += 1
            case = "net-" + receipt[:12] + "-resolved-" + str(index)
            _record(report, case, "offensive-network-attacks", "resolved-conf", setting=key, mode_declaration=declared,
                status="insufficient-evidence" if declared == "unknown" else "selected-declaration-only",
                per_link_or_dropin_policy_resolved=False)
            cue = (key in ("LLMNR", "MulticastDNS") and declared in ("yes", "resolve")) or (key in ("DNSSEC", "DNSOverTLS") and declared not in ("yes", "unknown"))
            if cue:
                _add(report, case, "offensive-network-attacks", "resolved-" + key, "Saved resolver declaration has " + key + "=" + declared,
                    "Compare approved name-resolution requirements, per-link settings, drop-ins, upstream support and the actual application/resolver path. Multicast lookup and downgrade/opportunistic modes may be intentional; this is not proof of poisoning, interception or absent runtime protection.")
    report["source_review"] = {"unsupported_settings_not_reviewed": unsupported, "complete_systemd_config_parsing": False,
        "config_precedence_or_per_link_settings_resolved": False, "resolver_or_dnssec_tls_probed": False}
    return _finish(report)


def review_file(path, *, authorized=False, mode="normalized"):
    if not authorized:
        raise PermissionError("Network evidence review requires explicit authorization")
    if mode not in MODES:
        _failure()
    raw = read_bounded(_approved_file(path), MAX_BYTES)
    receipt = hashlib.sha256(raw).hexdigest()
    if mode == "normalized":
        report = review_evidence(_decode(raw))
    elif mode == "sysctl-text":
        report = _sysctl(raw, receipt)
    else:
        report = _resolved(raw, receipt)
    report.update(input_sha256=receipt, input_mode=mode)
    return report
