"""Offline API assurance and selected non-resolving OpenAPI JSON review."""
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
METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
PROFILES = {
    "api-security": ("object_authorization_reviewed", "function_authorization_reviewed", "authentication_reviewed", "response_minimization_reviewed", "resource_limits_reviewed", "transport_policy_reviewed"),
    "api-abuse": ("business_invariants_reviewed", "workflow_order_reviewed", "idempotency_reviewed", "batch_limits_reviewed", "webhook_destination_policy_reviewed", "webhook_authenticity_reviewed"),
}
REFERENCES = ["https://github.com/SnailSploit/Claude-Red/tree/main/Skills/api",
    "https://spec.openapis.org/oas/v3.0.4.html", "https://spec.openapis.org/oas/v3.1.1.html"]


def catalog():
    return [{"id": "offensive-" + key, "implementation": "offline-api-assurance-review", "fields": list(fields),
        "openapi_json_review_available": key == "api-security", "active_api_testing_available": False,
        "required_evidence": "Owner-normalized nullable observations or selected OpenAPI 3.0/3.1 JSON; server enforcement, authorization and business invariants remain unverified"}
        for key, fields in PROFILES.items()]


def _failure():
    raise ValueError("Unsupported API evidence shape, selected OpenAPI field or bounds; contents withheld") from None


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
        raise ValueError("Invalid API evidence JSON; contents withheld") from None
    stack, nodes, refs = [(data, 0)], 0, 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > 20000 or depth > 40 or (isinstance(value, float) and not math.isfinite(value)):
            _failure()
        if isinstance(value, dict):
            for key in ("$ref", "$dynamicRef", "$recursiveRef"):
                if key in value:
                    if not isinstance(value[key], str):
                        _failure()
                    refs += 1
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
    return data, refs


def _report():
    return {"engine": "api-evidence-review", "schema_version": 1, "category": "API Security",
        "reviewed_at": datetime.now(timezone.utc).isoformat(), "records": [], "findings": [],
        "network_requests": 0, "external_tools_executed": 0, "referenced_files_opened": 0,
        "runtime_enforcement_verified": False, "authorization_verified": False, "business_logic_verified": False,
        "all_skills_automated": False, "real_world_effectiveness": "unverified", "truncated": False, "candidates_not_retained": 0,
        "references": REFERENCES, "limitations": ["Offline owner declarations and selected OpenAPI JSON syntax only; no endpoint request, account action or payload execution",
            "No BOLA/BFLA, tenant isolation, workflow, webhook, rate-limit, gRPC or WebSocket runtime validation",
            "OpenAPI declarations can be incomplete or stale; public operations and flexible schemas can be intentional",
            "No local/external reference resolution, composed-schema evaluation, YAML parsing or complete OpenAPI/JSON Schema validation",
            "API paths, operation IDs, scheme names, scope names, server URLs, parameters and examples are withheld; hashes remain correlatable",
            "Missing/unresolved declarations remain unknown; source syntax is not independently verified owner consent or demonstrated impact"]}


def _add(report, case, skill, key, title, fix):
    if len(report["findings"]) >= MAX_FINDINGS:
        report["truncated"] = True
        report["candidates_not_retained"] += 1
        return
    report["findings"].append({"rule_id": "api-review." + key.replace("_", "-"), "skill": skill, "test_case": case,
        "title": title, "severity": "INFO", "cwe": "CWE-693", "message": title + ". " + fix, "remediation": fix,
        "code": "", "file_path": "external-evidence", "line_start": 1, "line_end": 1,
        "engine": "api-evidence-review", "verification_status": "unverified"})


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
                _add(report, row["id"], skill, key + "." + field, "Owner evidence declares incomplete API assurance: " + field.replace("_", " "),
                    "Independently review applicable source evidence and server behavior; this declaration does not demonstrate a vulnerability.")
        unknown = [f for f, v in obs.items() if v is None]
        report["records"].append({"case": row["id"], "skill": skill, "unknown_fields": unknown,
            "status": "insufficient-evidence" if len(unknown) == len(obs) else "partial-declared-evidence"})
    return _finish(report)


def _security(value, schemes):
    if value is None:
        return {"declaration": "not-declared", "alternatives": [], "unresolved_schemes": 0}
    if not isinstance(value, list) or len(value) > 20:
        _failure()
    unresolved, alternatives = set(), []
    for option in value:
        if not isinstance(option, dict) or len(option) > 20:
            _failure()
        alternatives.append(len(option))
        for name, scopes in option.items():
            if not isinstance(scopes, list) or len(scopes) > 50 or not all(isinstance(s, str) and len(s) <= 256 for s in scopes):
                _failure()
            definition = schemes.get(name)
            if not isinstance(definition, dict) or "$ref" in definition or definition.get("type") not in ("http", "apiKey", "oauth2", "openIdConnect", "mutualTLS"):
                unresolved.add(name)
    state = "no-requirement-declared" if not value else ("anonymous-alternative-declared" if 0 in alternatives else (
        "unresolved-mechanism-declaration" if unresolved else "named-mechanisms-declared"))
    return {"declaration": state, "alternatives": alternatives, "unresolved_schemes": len(unresolved)}


def _servers(value):
    if not isinstance(value, list) or len(value) > 20:
        _failure()
    cleartext = False
    for server in value:
        if not isinstance(server, dict) or not isinstance(server.get("url"), str) or not 1 <= len(server["url"]) <= 2048:
            _failure()
        cleartext = cleartext or server["url"].lower().startswith("http://")
    return "http-url-declared" if cleartext else "no-http-url-observed-not-verified"


def _parameters(value):
    if not isinstance(value, list) or len(value) > 100:
        _failure()
    result, unresolved = {}, False
    for item in value:
        if not isinstance(item, dict):
            _failure()
        if "$ref" in item:
            unresolved = True
            continue
        if not isinstance(item.get("name"), str) or item.get("in") not in ("query", "header", "path", "cookie"):
            _failure()
        key = item["name"], item["in"]
        if key in result:
            _failure()
        result[key] = item
    return result, unresolved


def _schema_state(schema):
    if not isinstance(schema, (dict, bool)):
        _failure()
    if isinstance(schema, bool):
        return "boolean-schema-not-evaluated"
    if any(k in schema for k in ("$ref", "$dynamicRef", "$recursiveRef", "allOf", "anyOf", "oneOf", "if", "then", "else", "not")):
        return "referenced-or-composed-not-evaluated"
    if "maxItems" in schema and (type(schema["maxItems"]) is not int or not 0 <= schema["maxItems"] <= 1_000_000_000):
        _failure()
    return "selected-inline-schema-only"


def _openapi(data, receipt, refs):
    if not isinstance(data, dict) or not isinstance(data.get("openapi"), str) or not re.fullmatch(r"3\.(?:0|1)\.[0-9]{1,3}", data["openapi"]):
        _failure()
    paths, components = data.get("paths", {}), data.get("components", {})
    if not isinstance(paths, dict) or len(paths) > 200 or not isinstance(components, dict):
        _failure()
    schemes = components.get("securitySchemes", {})
    if not isinstance(schemes, dict) or len(schemes) > 50:
        _failure()
    report, operations, skipped, skipped_inline = _report(), 0, 0, 0
    for i, definition in enumerate(schemes.values(), 1):
        if not isinstance(definition, dict):
            _failure()
        if "$ref" in definition:
            continue
        case = "api-" + receipt[:12] + "-scheme-" + str(i)
        if definition.get("type") == "apiKey":
            if definition.get("in") not in ("query", "header", "cookie") or not isinstance(definition.get("name"), str) or not 1 <= len(definition["name"]) <= 256:
                _failure()
            if definition["in"] == "query":
                _add(report, case, "offensive-api-security", "openapi.query-api-key", "Security scheme declares an API key in query parameters",
                    "Review intended credential transport, URL logging and alternatives; definition presence does not prove an operation uses it.")
        if definition.get("type") == "http":
            if not isinstance(definition.get("scheme"), str) or not 1 <= len(definition["scheme"]) <= 64:
                _failure()
            if definition["scheme"].lower() == "basic":
                _add(report, case, "offensive-api-security", "openapi.basic-auth", "Security scheme declares HTTP Basic authentication",
                    "Review actual TLS, credential lifecycle and intended compatibility; this declaration alone is not a vulnerability.")
    if "security" in data and data["security"] is None:
        _failure()
    global_security = _security(data.get("security"), schemes)
    global_servers = data.get("servers", [])
    _servers(global_servers)
    for path, item in paths.items():
        if path.startswith("x-"):
            continue
        if not path.startswith("/") or not isinstance(item, dict):
            _failure()
        if "$ref" in item:
            skipped += 1
            skipped_inline += sum(m in item for m in METHODS)
            continue
        inherited_parameters, path_unresolved = _parameters(item.get("parameters", []))
        inherited_servers = item.get("servers", global_servers)
        _servers(inherited_servers)
        for method in METHODS:
            if method not in item:
                continue
            operation = item[method]
            if not isinstance(operation, dict) or "$ref" in operation:
                _failure()
            operations += 1
            if operations > 500:
                _failure()
            case = "api-" + receipt[:12] + "-operation-" + str(operations)
            if "security" in operation and operation["security"] is None:
                _failure()
            security = _security(operation["security"], schemes) if "security" in operation else dict(global_security)
            transport = _servers(operation.get("servers", inherited_servers))
            row = {"case": case, "skill": "offensive-api-security", "context": "openapi-operation", "method": method,
                "path_sha256": hashlib.sha256(path.encode("utf-8", errors="surrogatepass")).hexdigest(),
                "security_source": "operation" if "security" in operation else ("root" if "security" in data else "not-declared"),
                "security": security, "transport_declaration": transport, "status": "selected-native-syntax-only"}
            report["records"].append(row)
            if security["declaration"] in ("no-requirement-declared", "anonymous-alternative-declared"):
                _add(report, case, "offensive-api-security", "openapi.optional-security", "Operation contract declares no required security or an anonymous alternative",
                    "Review whether public access is intentional and independently verify server authentication and authorization; no access test occurs.")
            if transport == "http-url-declared":
                _add(report, case, "offensive-api-security", "openapi.http-server", "Effective selected server declaration includes an HTTP URL",
                    "Review intended deployment/TLS termination and actual transport; no server URL is requested.")
            params, op_unresolved = _parameters(operation.get("parameters", []))
            merged = {**inherited_parameters, **params}
            row["parameters_status"] = "partial-unresolved-references" if path_unresolved or op_unresolved else "selected-inline-parameters-only"
            if not (path_unresolved or op_unresolved):
                for (name, location), parameter in merged.items():
                    if location != "query" or name not in ("limit", "page_size", "per_page", "first", "last") or "schema" not in parameter:
                        continue
                    schema = parameter["schema"]
                    if _schema_state(schema) != "selected-inline-schema-only":
                        continue
                    if schema.get("type") in ("integer", "number"):
                        bound = False
                        if "maximum" in schema:
                            if type(schema["maximum"]) not in (int, float):
                                _failure()
                            bound = True
                        if "exclusiveMaximum" in schema:
                            exclusive = schema["exclusiveMaximum"]
                            if data["openapi"].startswith("3.0."):
                                if type(exclusive) is not bool:
                                    _failure()
                            else:
                                if type(exclusive) not in (int, float):
                                    _failure()
                                bound = True
                        if not bound:
                            _add(report, case, "offensive-api-security", "openapi.pagination-bound", "Selected numeric pagination parameter lacks an explicit upper-bound declaration",
                                "Review runtime quotas and intended pagination; a documentation gap does not prove resource exhaustion.")
            body = operation.get("requestBody")
            row["request_body_status"] = "not-declared"
            if "requestBody" in operation and body is None:
                _failure()
            if body is not None:
                if not isinstance(body, dict):
                    _failure()
                row["request_body_status"] = "unresolved-reference" if "$ref" in body else "non-json-or-missing-schema-not-reviewed"
                if "$ref" not in body:
                    content = body.get("content", {})
                    if not isinstance(content, dict) or len(content) > 20:
                        _failure()
                    media = content.get("application/json", {})
                    if not isinstance(media, dict):
                        _failure()
                    if "schema" in media:
                        schema = media["schema"]
                        state = _schema_state(schema)
                        row["request_body_status"] = state
                        if state == "selected-inline-schema-only":
                            if schema.get("type") == "array" and "maxItems" not in schema:
                                _add(report, case, "offensive-api-abuse", "openapi.array-bound", "JSON array request has no explicit maxItems declaration",
                                    "Review intended batching and runtime size/rate controls; no batching or denial-of-service test is performed.")
                            if schema.get("type") == "object" and schema.get("additionalProperties") is True:
                                _add(report, case, "offensive-api-security", "openapi.open-object", "JSON object request explicitly permits additional properties",
                                    "Review field authorization and intended extensibility; flexible input does not demonstrate mass assignment.")
    report["source_review"] = {"openapi_version": data["openapi"], "inline_operations_reviewed": operations,
        "referenced_paths_not_reviewed": skipped, "inline_operations_skipped_with_referenced_paths": skipped_inline,
        "references_not_resolved": refs, "complete_openapi_validation": False, "schema_definitions_fully_validated": False,
        "callbacks_webhooks_and_components_operations_reviewed": False, "native_source_line_locations_available": False}
    return _finish(report)


def review_file(path, *, authorized=False, mode="normalized"):
    if not authorized:
        raise PermissionError("API evidence review requires explicit authorization")
    if mode not in ("normalized", "openapi-json"):
        _failure()
    raw = read_bounded(_approved_file(path), MAX_BYTES)
    data, refs = _decode(raw)
    receipt = hashlib.sha256(raw).hexdigest()
    report = review_evidence(data) if mode == "normalized" else _openapi(data, receipt, refs)
    report.update(input_sha256=receipt, input_mode=mode)
    return report
