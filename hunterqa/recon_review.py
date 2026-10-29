"""Offline OSINT assurance and explicitly scoped DNS-name inventory imports."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone

from .bounty import _approved_file
from .source_files import read_bounded

MAX_BYTES = 1_048_576
ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
PROFILES = {
    "osint": ("authorized_scope_reviewed", "source_provenance_reviewed", "asset_attribution_reviewed", "data_minimization_reviewed"),
    "osint-methodology": ("collection_plan_reviewed", "source_corroboration_reviewed", "evidence_timestamps_reviewed", "retention_policy_reviewed"),
}
REFERENCES = ["https://github.com/SnailSploit/Claude-Red/tree/main/Skills/recon",
    "https://www.rfc-editor.org/rfc/rfc5280.html", "https://www.rfc-editor.org/rfc/rfc9162.html"]


def catalog():
    return [{"id": "offensive-" + key, "implementation": "offline-osint-assurance-review", "fields": list(fields),
        "scoped_name_import_available": key == "osint", "live_collection_available": False,
        "required_evidence": "Owner-normalized nullable observations or previously collected DNS names plus an explicit private domain scope; ownership and current DNS remain unverified"}
        for key, fields in PROFILES.items()]


def _failure():
    raise ValueError("Unsupported reconnaissance evidence shape, name scope or bounds; contents withheld") from None


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
        raise ValueError("Invalid reconnaissance JSON; contents withheld") from None


def _report():
    return {"engine": "reconnaissance-evidence-review", "schema_version": 1, "category": "Reconnaissance",
        "reviewed_at": datetime.now(timezone.utc).isoformat(), "records": [], "findings": [],
        "network_requests": 0, "dns_queries": 0, "external_tools_executed": 0, "referenced_files_opened": 0,
        "asset_ownership_verified": False, "current_dns_verified": False, "certificate_or_ct_proof_verified": False,
        "all_skills_automated": False, "real_world_effectiveness": "unverified", "references": REFERENCES,
        "limitations": ["Selected offline owner declarations and DNS-name imports only; no live OSINT, DNS, CT query or endpoint request",
            "Name-scope matching is not independently verified owner consent, asset attribution, active-test permission or a vulnerability finding",
            "CT-style name exports can be stale, fabricated or unrelated to current service ownership; no certificate/log proof is verified",
            "Wildcard patterns are retained without expansion or DNS/TLS wildcard-semantics evaluation",
            "No personal profiling, email/credential collection, breach lookup, source-code search or third-party tool execution",
            "Default native output withholds names; explicit include-names exports admitted names only into the private report; hashes are correlatable, not anonymity guarantees"]}


def _add(report, case, skill, key, title, fix):
    report["findings"].append({"rule_id": "recon-review." + key.replace("_", "-"), "skill": skill,
        "test_case": case, "title": title, "severity": "INFO", "cwe": "CWE-693",
        "message": title + ". " + fix, "remediation": fix, "code": "", "file_path": "external-evidence",
        "line_start": 1, "line_end": 1, "engine": "reconnaissance-evidence-review", "verification_status": "unverified"})


def _finish(report):
    rows = report["records"]
    report["status"] = "insufficient-evidence" if not rows or all(r["status"] == "insufficient-evidence" for r in rows) else "partial-offline-review"
    return report


def review_evidence(data):
    if not isinstance(data, dict) or set(data) != {"schema_version", "records"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        _failure()
    if not isinstance(data["records"], list) or not 1 <= len(data["records"]) <= 20:
        _failure()
    ids, counts, report = set(), {}, _report()
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
                _add(report, row["id"], skill, key + "." + field,
                    "Owner evidence declares incomplete reconnaissance assurance: " + field.replace("_", " "),
                    "Independently review permitted collection, source reliability and attribution; this declaration does not demonstrate exposure or impact.")
        unknown = [f for f, v in obs.items() if v is None]
        report["records"].append({"case": row["id"], "skill": skill, "unknown_fields": unknown,
            "status": "insufficient-evidence" if len(unknown) == len(obs) else "partial-declared-evidence"})
    return _finish(report)


def _name(value, *, allow_wildcard=False):
    if not isinstance(value, str) or not value.isascii() or not value or value != value.strip():
        return None
    value = value.lower()
    if value.endswith("."):
        value = value[:-1]
    wildcard = value.startswith("*.")
    if wildcard:
        if not allow_wildcard:
            return None
        value = value[2:]
    labels = value.split(".")
    if len(value) + (2 if wildcard else 0) > 253 or len(labels) < 2 or all(label.isdigit() for label in labels) or not all(LABEL.fullmatch(label) for label in labels):
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return ("*." if wildcard else "") + value
    return None


def validate_scope(data):
    if not isinstance(data, dict) or set(data) != {"schema_version", "domains"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        _failure()
    if not isinstance(data["domains"], list) or not 1 <= len(data["domains"]) <= 20:
        _failure()
    result, seen = [], set()
    for row in data["domains"]:
        if not isinstance(row, dict) or set(row) != {"name", "include_subdomains"} or type(row["include_subdomains"]) is not bool:
            _failure()
        name = _name(row["name"])
        if name is None or name in seen:
            _failure()
        seen.add(name)
        result.append((name, row["include_subdomains"]))
    return result


def _admitted(name, scope):
    wildcard = name.startswith("*.")
    base = name[2:] if wildcard else name
    return any((base == root and (subdomains or not wildcard)) or (subdomains and base.endswith("." + root)) for root, subdomains in scope)


def _candidates(raw, mode):
    if mode == "names":
        try:
            text = raw.decode("utf-8")
        except UnicodeError:
            _failure()
        if any(ord(c) < 32 and c not in "\r\n\t" for c in text) or "\x7f" in text:
            _failure()
        lines = text.splitlines()
        if len(lines) > 2000 or any(len(line) > 1024 for line in lines):
            _failure()
        return [(line.strip(), i, 1) for i, line in enumerate(lines, 1) if line.strip()]
    data = _decode(raw)
    if not isinstance(data, list) or len(data) > 500:
        _failure()
    result = []
    for i, row in enumerate(data, 1):
        if not isinstance(row, dict) or not isinstance(row.get("name_value"), str) or len(row["name_value"]) > 8192:
            _failure()
        names = row["name_value"].splitlines()
        if len(names) > 100:
            _failure()
        for j, name in enumerate(names, 1):
            if name.strip():
                result.append((name.strip(), i, j))
                if len(result) > 2000:
                    _failure()
    return result


def inventory_file(path, scope_path, *, authorized=False, mode="names", include_names=False):
    if not authorized:
        raise PermissionError("Reconnaissance inventory requires explicit authorization")
    if mode not in ("names", "ct-names-json") or type(include_names) is not bool:
        _failure()
    source, scope_file = _approved_file(path), _approved_file(scope_path)
    scope_raw = read_bounded(scope_file, MAX_BYTES)
    scope = validate_scope(_decode(scope_raw))
    raw = read_bounded(source, MAX_BYTES)
    candidates = _candidates(raw, mode)
    report, inventory, invalid, outside, duplicates = _report(), {}, 0, 0, 0
    for value, row, item in candidates:
        name = _name(value, allow_wildcard=True)
        if name is None:
            invalid += 1
            continue
        if not _admitted(name, scope):
            outside += 1
            continue
        observation = {"source_row": row, "name_index": item}
        if name in inventory:
            duplicates += 1
            if len(inventory[name]["source_observations"]) < 10:
                inventory[name]["source_observations"].append(observation)
            else:
                inventory[name]["source_observations_not_retained"] += 1
            continue
        if len(inventory) >= 1000:
            _failure()
        digest = hashlib.sha256(name.encode("ascii")).hexdigest()
        entry = {"case": "recon-" + digest[:32], "skill": "offensive-osint", "context": "scoped-name-inventory",
            "canonical_name_sha256": digest, "kind": "wildcard-pattern" if name.startswith("*.") else "hostname",
            "source_observations": [observation], "source_observations_not_retained": 0,
            "status": "declared-domain-match-only"}
        if include_names:
            entry["name"] = name
        inventory[name] = entry
    report["records"] = list(inventory.values())
    receipt = hashlib.sha256(raw).hexdigest()
    scope_receipt = hashlib.sha256(scope_raw).hexdigest()
    context = "recon-" + hashlib.sha256((receipt + scope_receipt).encode("ascii")).hexdigest()[:24]
    wildcards = sum(r["kind"] == "wildcard-pattern" for r in report["records"])
    if wildcards:
        _add(report, context, "offensive-osint", "inventory.wildcard-patterns", "Inventory retains unexpanded wildcard-name patterns",
            "Obtain independently approved exact hostnames before any active workflow; no pattern expansion or wildcard matching against DNS/TLS services occurs here.")
    if mode == "ct-names-json" and inventory:
        _add(report, context, "offensive-osint-methodology", "inventory.ct-attribution", "Saved certificate-name text needs independent attribution",
            "Verify source provenance, timing and current ownership; names in an export do not prove present DNS, service exposure or target permission.")
    report.update(input_sha256=receipt, scope_sha256=scope_receipt, input_mode=mode, names_included=include_names,
        inventory_counts={"candidates_seen": len(candidates), "invalid_names": invalid, "outside_scope": outside,
            "duplicate_admitted_names": duplicates, "unique_admitted_names": len(inventory), "wildcard_patterns": wildcards},
        source_review={"scope_domains_reviewed": len(scope), "wildcards_expanded": False, "active_targets_enrolled": False,
            "scope_semantics": "union-of-explicit-domain-rules", "ct_fields_other_than_name_value_interpreted": False})
    return _finish(report)


def review_file(path, *, authorized=False):
    if not authorized:
        raise PermissionError("Reconnaissance evidence review requires explicit authorization")
    raw = read_bounded(_approved_file(path), MAX_BYTES)
    report = review_evidence(_decode(raw))
    report.update(input_sha256=hashlib.sha256(raw).hexdigest(), input_mode="normalized")
    return report
