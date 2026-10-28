"""Offline OpenAPI security review for an explicitly authorized bug-bounty workspace.

No URLs are fetched. Inputs are bounded local JSON specs inside operator-approved
roots. The output is a *review queue*, not a claim of exploitability or CVEs.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .bounty import BountyPolicy, _approved_file, _read_json

MAX_SPEC_BYTES = 1_000_000
MAX_PATHS = 250
MAX_OPERATIONS = 500
METHODS = ("get", "head", "options", "post", "put", "patch", "delete")
OBJECT_REF = re.compile(r"\{[A-Za-z0-9_.-]*(?:id|key|account|owner|user|org|tenant)[A-Za-z0-9_.-]*\}", re.I)
SENSITIVE_NAMES = ("admin", "payment", "billing", "transfer", "role", "permission", "token", "secret")
SAFE_TEXT = re.compile(r"[\x00-\x1f\x7f]")


def _short(value, limit=160):
    if not isinstance(value, str):
        return ""
    return SAFE_TEXT.sub(" ", value)[:limit]


def _auth_declaration(operation, global_security):
    """Parse security inheritance without treating omitted declarations as proof."""
    if "security" in operation:
        security = operation["security"]
        inherited = False
    else:
        security = global_security
        inherited = True
    if security is None:
        return "not_declared"
    if not isinstance(security, list):
        return "invalid"
    if len(security) == 0:
        return "explicitly_public"
    if len(security) > 20 or any(not isinstance(entry, dict) for entry in security):
        return "invalid"
    if any(not isinstance(scopes, list) or len(scopes) > 100 or any(not isinstance(scope, str) for scope in scopes)
           for entry in security for scopes in entry.values()):
        return "invalid"
    # OpenAPI defines {} as an anonymous alternative, not a malformed declaration.
    if any(not entry for entry in security):
        return "optional_authentication" if any(entry for entry in security) else "explicitly_public"
    return "declared_inherited" if inherited else "declared"


def inspect_openapi(spec_path, profile_path, *, authorized=False):
    """Generate deterministic API coverage and review suggestions (no HTTP)."""
    if not authorized:
        raise PermissionError("Explicit --authorized is required for API research")
    policy = BountyPolicy.load(profile_path)
    doc = _read_json(spec_path, MAX_SPEC_BYTES)
    if not isinstance(doc, dict):
        raise ValueError("OpenAPI root must be a JSON object")
    version = doc.get("openapi")
    if not isinstance(version, str) or not (version.startswith("3.0.") or version.startswith("3.1.")):
        raise ValueError("Only bounded OpenAPI 3.0/3.1 JSON specifications supported")
    paths = doc.get("paths")
    if not isinstance(paths, dict) or len(paths) > MAX_PATHS:
        raise ValueError("OpenAPI paths missing or exceed 250 entries")
    raw_servers = doc.get("servers", [])
    if not isinstance(raw_servers, list) or len(raw_servers) > 30:
        raise ValueError("OpenAPI servers must be a bounded list")
    # Never execute requests or trust server values as authorization.
    server_notes = []
    for server in raw_servers:
        if not isinstance(server, dict):
            continue
        url = server.get("url")
        if isinstance(url, str):
            try:
                parts = urlsplit(url)
                host = parts.hostname.lower().rstrip(".") if parts.hostname else ""
                matched = bool(host and host in policy.allowed_hosts and
                               host not in policy.excluded_hosts and
                               parts.scheme in ("http", "https") and
                               parts.username is None and parts.password is None)
            except ValueError:
                matched = False
            # No server URLs, queries, credentials or tokens are persisted.
            server_notes.append({
                "contract_server_hash": hashlib.sha256(url.encode()).hexdigest()[:20],
                "scope_status": "hostname_declared_in_scope" if matched
                                else "unverified_or_out_of_scope",
                "testing_authorized": False,
            })
    global_security = doc.get("security")
    operations, candidates = [], []
    allowed_parameters = {"path", "query", "header", "cookie"}
    total = 0
    for route, path_item in sorted(paths.items(), key=lambda x: str(x[0])):
        if not isinstance(route, str) or not route.startswith("/") or len(route) > 240:
            continue
        if not isinstance(path_item, dict):
            continue
        for method, operation in sorted(path_item.items(), key=lambda x: str(x[0])):
            if method not in METHODS or not isinstance(operation, dict):
                continue
            total += 1
            if total > MAX_OPERATIONS:
                raise ValueError("OpenAPI has more than 500 operations")
            auth = _auth_declaration(operation, global_security)
            params = (path_item.get("parameters", []) if isinstance(path_item.get("parameters", []), list) else [])
            op_params = operation.get("parameters", [])
            if isinstance(op_params, list):
                params = (params + op_params)[:50]
            parsed_params = []
            for item in params:
                if not isinstance(item, dict):
                    continue
                name, location = _short(item.get("name"), 80), item.get("in")
                if name and location in allowed_parameters:
                    parsed_params.append({"name": name, "in": location,
                                          "required": bool(item.get("required", False))})
            write_method = method in ("post", "put", "patch", "delete")
            object_ref = bool(OBJECT_REF.search(route))
            entry = {
                "operation_id": hashlib.sha256(f"{method.upper()} {route}".encode()).hexdigest()[:16],
                "method": method.upper(), "path_template": _short(route, 240),
                "auth_declaration": auth, "parameters": parsed_params[:30],
                "has_request_body": isinstance(operation.get("requestBody"), dict),
                "object_reference": object_ref, "state_changing": write_method,
                "tags": [_short(v, 50) for v in operation.get("tags", [])[:5]
                         if isinstance(v, str)] if isinstance(operation.get("tags"), list) else [],
                "deprecated": operation.get("deprecated") is True,
            }
            operations.append(entry)
            def suggest(rule, title, reason, priority):
                candidates.append({
                    "id": hashlib.sha256(f"{rule}:{entry['operation_id']}".encode()).hexdigest()[:20],
                    "rule_id": rule, "title": title, "operation_id": entry["operation_id"],
                    "method": entry["method"], "path_template": entry["path_template"],
                    "reason": reason, "priority": priority,
                    "verification": "manual_review_required",
                    "confirmed": False, "cve_id": None, "zero_day_confirmed": False,
                })
            if auth in ("not_declared", "invalid") and write_method:
                suggest("api.auth-declaration-review",
                        "Check authorization policy on state-changing API",
                        "Schema lacks a valid declared auth requirement; this is not proof of unauthorized access.",
                        "review")
            if auth in ("explicitly_public", "optional_authentication") and write_method:
                suggest("api.public-write-review",
                        "Check intended public write operation",
                        "Schema permits an anonymous alternative on a modifying operation; public behavior may be intentional.",
                        "review")
            if object_ref:
                suggest("api.object-access-review",
                        "Review object-level authorization for resource identifier",
                        "An object identifier occurs in the route; check tenant and owner boundary using authorized test accounts.",
                        "manual")
            if write_method and any(term in route.lower() for term in SENSITIVE_NAMES):
                suggest("api.business-logic-review",
                        "Review sensitive state-changing business workflow",
                        "Potentially sensitive operation; requires human business-impact analysis.",
                        "manual")
            if entry["deprecated"]:
                suggest("api.deprecated-operation-review",
                        "Review deprecated API operation exposure",
                        "Deprecated route remains in the contract; actual deployment is unverified.",
                        "informational")
    # Only the bounded, de-duplicated review queue is exported.
    candidates = candidates[:250]
    return {
        "schema_version": 1, "engine": "hunterqa_v12_offline_api_surface",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "program": policy.program, "platform": policy.platform,
        "policy_sha256": hashlib.sha256(_approved_file(profile_path).read_bytes()).hexdigest(),
        "spec_sha256": hashlib.sha256(_approved_file(spec_path).read_bytes()).hexdigest(),
        "openapi_version": version, "servers": server_notes,
        "summary": {"operations": len(operations), "review_candidates": len(candidates),
                    "verified_vulnerabilities": 0, "confirmed_zero_days": 0},
        "operations": operations, "review_candidates": candidates,
        "claims": {"confirmed_vulnerabilities": 0, "assigned_cves": 0,
                   "false_positive_free": False},
        "limitations": "This is offline, non-executing contract analysis. Schema security "
                       "declarations and route names cannot prove runtime authorization. "
                       "No API request is sent, no account is accessed and no CVE is issued.",
    }
