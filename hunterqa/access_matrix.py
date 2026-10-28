"""Explicit dedicated-account GET contracts; no account/resource enumeration."""
from __future__ import annotations

import hashlib
import re
import time

from .bounty import BountyPolicy, _approved_file, _read_json
from .engagement import digest, pinned_request
from .source_files import read_bounded
from .web_discovery import origin
from .workflow_network import NetworkJournal
from .workflow_protocol import ID, _fields, _integer


def validate_matrix(data, policy):
    _fields(data, ("schema_version", "roles", "cases"), "access matrix")
    _integer(data["schema_version"], 1, 1, "schema_version")
    roles, cases = data["roles"], data["cases"]
    if not isinstance(roles, dict) or not 1 <= len(roles) <= 8:
        raise ValueError("Define 1..8 explicit test roles")
    for name, role in roles.items():
        if not ID.fullmatch(name):
            raise ValueError("Invalid role identifier")
        _fields(role, ("origin", "authenticated"), "role")
        policy.authorize_url(role["origin"], "GET")
        if type(role["authenticated"]) is not bool:
            raise ValueError("Role authentication must be explicit")
        if role["authenticated"] and not role["origin"].startswith("https://") and not policy.lab_mode:
            raise ValueError("Remote credentials require HTTPS")
    if not isinstance(cases, list) or not 1 <= len(cases) <= 40:
        raise ValueError("Define 1..40 exact access cases")
    ids = set()
    for case in cases:
        _fields(case, ("id", "role", "url", "expect", "statuses", "body_sha256"), "access case")
        if not isinstance(case["id"], str) or not ID.fullmatch(case["id"]) or case["id"] in ids:
            raise ValueError("Access case IDs must be unique")
        ids.add(case["id"])
        if not isinstance(case["role"], str) or case["role"] not in roles:
            raise ValueError("Access case references an unknown role")
        policy.authorize_url(case["url"], "GET")
        if origin(case["url"]) != origin(roles[case["role"]]["origin"]):
            raise ValueError("Role credentials cannot cross their declared origin")
        if case["expect"] not in ("allow", "deny"):
            raise ValueError("Access expectation must be allow or deny")
        statuses = case["statuses"]
        permitted = range(200, 300) if case["expect"] == "allow" else (401, 403, 404)
        if (not isinstance(statuses, list) or not 1 <= len(statuses) <= 5
                or any(type(s) is not int or s not in permitted for s in statuses)
                or len(set(statuses)) != len(statuses)):
            raise ValueError("Invalid expected access statuses")
        value = case["body_sha256"]
        if value is not None and (not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value)):
            raise ValueError("Expected body digest must be SHA-256 or null")
    return data


def credentials(binding, roles):
    path = _approved_file(binding["secret_file"])
    if hashlib.sha256(read_bounded(path, 32_768)).hexdigest() != binding["secret_file_sha256"]:
        raise PermissionError("Test credential file changed after review")
    data = _read_json(path, 32_768)
    required = {name for name, role in roles.items() if role["authenticated"]}
    if not isinstance(data, dict) or set(data) != required:
        raise ValueError("Provide exactly the declared authenticated role credentials")
    for value in data.values():
        if (not isinstance(value, str) or not 8 <= len(value) <= 4096
                or not value.startswith(("Bearer ", "Basic "))
                or any(not 32 <= ord(c) < 127 for c in value)):
            raise ValueError("Use bounded dedicated-account Bearer or Basic authorization values")
    return data


def execute_matrix(request, *, transport=pinned_request, sleeper=time.sleep):
    policy = BountyPolicy.from_dict(request["policy"])
    binding, step = request["binding"], request["step"]
    matrix = validate_matrix(_read_json(binding["file"], 65_536), policy)
    if len(matrix["cases"]) > step["requests"] or not {c["url"] for c in matrix["cases"]} <= set(step["targets"]):
        raise ValueError("Access matrix exceeds reviewed reservation or targets")
    observations, findings = [], []
    stopped = False
    journal = NetworkJournal(request["network_log"])
    try:
        for index, case in enumerate(matrix["cases"]):
            if index:
                sleeper(request["interval_seconds"])
            tokens = credentials(binding, matrix["roles"])
            headers = {"Authorization": tokens[case["role"]]} if case["role"] in tokens else {}
            target = case["url"]
            journal.append("intent", target, "GET")
            try:
                response = transport(policy, target, "GET", headers=headers)
            except Exception as exc:
                journal.append("error", target, "GET", error_type=type(exc).__name__)
                raise
            status = response["status"]
            journal.append("response", target, "GET", status=status)
            body_hash = hashlib.sha256(response["body"]).hexdigest()
            matched = status in case["statuses"] and case["body_sha256"] in (None, body_hash)
            observations.append({"case": case["id"], "role": case["role"], "expected": case["expect"],
                "status": status, "contract_matched": matched, "body_sha256": body_hash,
                "target_sha256": digest(target), "verification_status": "unverified"})
            if case["expect"] == "deny" and 200 <= status < 300:
                findings.append({"rule_id": "access.unexpected-success", "title": "Denied-role case returned a successful status; inspect authorization and response content",
                    "severity": "WARNING", "cwe": "CWE-284", "file_path": "external-evidence", "line_start": 1,
                    "target_ref_hash": hashlib.sha256(target.encode()).hexdigest(),
                    "verification_status": "unverified", "case": case["id"], "role": case["role"]})
            # Expected access denials are part of the contract, not a reason to
            # bypass the matrix. Unexpected denials may indicate expired tokens.
            if (status == 429 or 300 <= status < 400 or status >= 500
                    or (case["expect"] == "allow" and status in (401, 403))):
                stopped = True
                break
        return {"adapter": "authorization-matrix", "adapter_version": 1, "requests": len(observations),
            "findings": findings, "observations": observations, "safety_stop": stopped,
            "verification_status": "unverified", "access_summary": {"cases_executed": len(observations),
                "cases_selected": len(matrix["cases"]), "contracts_matched": sum(o["contract_matched"] for o in observations)},
            "limitations": ["Dedicated credentials and exact GET cases only; no SSO/session negotiation or business-flow execution",
                "Status/body-digest contracts do not prove correct authorization; successful denial cases require analyst review"]}
    finally:
        journal.close()
