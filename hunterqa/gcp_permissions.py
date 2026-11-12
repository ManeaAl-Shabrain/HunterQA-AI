"""Exact-project caller permission query; never exercises the tested permissions."""
from __future__ import annotations

import hashlib
import http.client
import json
import math
import time

from . import shared_quota
from . import cloud_transport
from .bounty import BountyPolicy, _approved_file, _decode_json, resolve_pinned
from .cloud_inventory_common import bounded_json, live_window, temporary_credentials, read_credentials
from .engagement import digest, utcnow
from .gcp_inventory import CONTEXT_HOST, NUMBER, PARENT, PROJECT_ID, _GCPConnection, _gcp_get
from .source_files import read_bounded

PERMISSIONS = frozenset("resourcemanager.projects." + suffix for suffix in
    ("get", "getIamPolicy", "setIamPolicy", "update", "delete"))
FIELDS = {"schema_version", "provider", "project_id", "project_number", "expected_parent",
          "authorization_reference", "acknowledged_authorization", "expires_at", "permissions", "interval_seconds"}


def validate_contract(data):
    try:
        if not isinstance(data, dict) or set(data) != FIELDS:
            raise ValueError
        if type(data["schema_version"]) is not int or data["schema_version"] != 1 or data["provider"] != "gcp":
            raise ValueError
        if not isinstance(data["project_id"], str) or not PROJECT_ID.fullmatch(data["project_id"]):
            raise ValueError
        if not isinstance(data["project_number"], str) or not NUMBER.fullmatch(data["project_number"]):
            raise ValueError
        if data["expected_parent"] is not None and (not isinstance(data["expected_parent"], str) or not PARENT.fullmatch(data["expected_parent"])):
            raise ValueError
        ref = data["authorization_reference"]
        if data["acknowledged_authorization"] is not True or not isinstance(ref, str) or not 1 <= len(ref) <= 200 or not ref.strip() or any(ord(c) < 32 for c in ref):
            raise ValueError
        permissions = data["permissions"]
        if (not isinstance(permissions, list) or not 1 <= len(permissions) <= 5
                or any(not isinstance(p, str) or p not in PERMISSIONS for p in permissions)
                or len(set(permissions)) != len(permissions)):
            raise ValueError
        delay = data["interval_seconds"]
        if type(delay) not in (int, float) or not math.isfinite(delay) or not 0.5 <= delay <= 5:
            raise ValueError
        live_window(data["expires_at"])
    except (ValueError, TypeError):
        raise ValueError("Invalid GCP permission contract; private values withheld") from None
    return data


def _permission_post(number, permissions, token, *, before_send):
    # Validate again at the credential-bearing boundary. No arbitrary URL,
    # method, permission wildcard, IAM write or caller-supplied body is accepted.
    if (not isinstance(number, str) or not NUMBER.fullmatch(number) or not isinstance(permissions, list)
            or not 1 <= len(permissions) <= 5 or any(not isinstance(p, str) or p not in PERMISSIONS for p in permissions)
            or len(set(permissions)) != len(permissions)):
        raise ValueError("GCP permission request rejected")
    path = "/v3/projects/" + number + ":testIamPermissions"
    body = json.dumps({"permissions": permissions}, separators=(",", ":")).encode("ascii")
    # Reuse only the public-address DNS admission. Generic bounty HTTP policy
    # stays HEAD/GET-only; this module independently fixes the query-only POST.
    policy = BountyPolicy.from_dict({"program": "Explicit GCP caller permission query", "platform": "private",
        "authorization_reference": "Exact invocation contract", "acknowledged_authorization": True,
        "allowed_hosts": [CONTEXT_HOST], "allowed_ports": [443], "allowed_paths": [path],
        "methods": ["GET"], "max_requests": 1, "interval_seconds": 0.5})
    ip = resolve_pinned(policy, CONTEXT_HOST, 443)
    before_send()
    connection = _GCPConnection(CONTEXT_HOST, ip)
    try:
        before_send()  # Recheck after local trust setup, immediately before TCP.
        connection.connect()
        before_send()
        connection.request("POST", path, body=body, headers={
            "Authorization": "Bearer " + token, "Accept": "application/json", "Accept-Encoding": "identity",
            "Content-Type": "application/json", "Connection": "close", "User-Agent": "HunterQA-AI scoped-gcp-permissions"})
        return cloud_transport.read_response(connection.getresponse(), 16384)
    finally:
        connection.close()


def check_permissions(input_file, credential_file, *, authorized=False, context_transport=None,
                      permission_transport=None, sleeper=time.sleep, credential_provider=None):
    if authorized is not True:
        raise PermissionError("GCP permission query requires --authorized and written exact-project permission")
    raw = read_bounded(_approved_file(input_file), 16384)
    secret, credential_binding = read_credentials(credential_file, credential_provider)
    try:
        contract = validate_contract(_decode_json(raw))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ValueError("Invalid GCP permission contract; private values withheld") from None
    keys = temporary_credentials(secret)
    synthetic = context_transport is not None or permission_transport is not None
    context_transport = context_transport or _gcp_get
    permission_transport = permission_transport or _permission_post

    def gate():
        admission.ensure_active()
        try:
            if read_bounded(_approved_file(input_file), 16384) != raw or read_credentials(credential_file, credential_provider) != (secret, credential_binding):
                raise ValueError
            validate_contract(contract)
            live_window(keys["expires_at"])
        except (OSError, ValueError):
            raise PermissionError("GCP permission authorization changed or expired") from None

    report = {"engine": "scoped-gcp-permission-check", "schema_version": 1, "observed_at": utcnow().isoformat(),
        "execution_source": "DEMO" if synthetic else "LIVE", "synthetic": synthetic,
        "real_provider_verified": False, "credential_binding_sha256": credential_binding,
        "input_sha256": hashlib.sha256(raw).hexdigest(), "project_ref": digest(contract["project_id"]),
        "project_number_ref": digest(contract["project_number"]),
        "parent_ref": digest(contract["expected_parent"]) if contract["expected_parent"] is not None else None,
        "request_budget": 2, "requests_attempted": 0, "requests_completed": 0,
        "project_context_matched": False, "permission_query_completed": False,
        "principal_identity_verified": False, "effective_permissions_verified": False, "owner_grant_verified": False,
        "permissions": [{"permission": p, "provider_reported_granted": None} for p in contract["permissions"]],
        "receipts": [], "findings": [], "outcome": "inconclusive", "limitations": [
            "One fixed project-context GET then one Resource Manager v3 testIamPermissions POST for 1-5 allowlisted project permissions",
            "Tests the supplied caller token only; no IAM policy changes, project update/deletion, impersonation, refresh, login, SDK or CLI discovery",
            "Boolean results describe only the accepted provider response for requested permissions at observation time, not proof an operation would succeed",
            "No complete effective-access calculation, deny/condition/org-policy analysis, identity introspection, data-plane access or other-principal evaluation",
            "Failure, rejected response or unmatched project context leaves all permission values unknown; no redirects, retries, API enablement or fallback",
            "Context and permission query are sequential, not an atomic authorization snapshot; in-flight results can complete after stop",
            "Native HTTPS: five-second shared post-DNS TCP/TLS/send/header/body I/O deadline per request, one-MiB context and 16-KiB permission body caps; no DNS or process-wide deadline",
            "Optional trusted host-local quota and local operator attestation; no verified owner grant, tenant/OS isolation or cross-host enforcement",
            "Hashes do not authenticate provenance or anonymize guessable project values; representative live GCP field effectiveness is unverified"]}
    context_target = "https://" + CONTEXT_HOST + "/v3/projects/" + contract["project_number"] + "?fields=name%2CprojectId%2Cparent%2Cstate"
    permission_target = "https://" + CONTEXT_HOST + "/v3/projects/" + contract["project_number"] + ":testIamPermissions"
    with shared_quota.invocation(2) as admission:
        report["shared_quota"] = admission.receipt
        for index, target in enumerate((context_target, permission_target)):
            if index:
                sleeper(contract["interval_seconds"])
            receipt = {"action": "project-context" if index == 0 else "test-permissions", "target_sha256": digest(target),
                       "status": None, "body_bytes": None, "body_sha256": None}
            try:
                gate()
                report["requests_attempted"] += 1
                report["receipts"].append(receipt)
                response = (context_transport(target, keys["access_token"], before_send=gate) if index == 0 else
                    permission_transport(contract["project_number"], contract["permissions"], keys["access_token"], before_send=gate))
            except shared_quota.QuotaStopped:
                report["outcome"] = "quota-stopped"
                break
            except PermissionError:
                report["outcome"] = "authorization-stopped"
                break
            except (OSError, http.client.HTTPException, ValueError):
                report["outcome"] = "transport-rejected"
                break
            try:
                status, body = response["status"], response["body"]
                if (type(status) is not int or not 100 <= status <= 599 or not isinstance(body, bytes)
                        or len(body) > (1048576 if index == 0 else 16384)):
                    raise ValueError
                report["requests_completed"] += 1
                receipt.update(status=status, body_bytes=len(body), body_sha256=hashlib.sha256(body).hexdigest())
                if status != 200:
                    report["outcome"] = "http-error"
                    break
                data = bounded_json(body)
                if index == 0:
                    if (data.get("name") != "projects/" + contract["project_number"] or data.get("projectId") != contract["project_id"]
                            or data.get("parent") != contract["expected_parent"] or data.get("state") != "ACTIVE"):
                        report["outcome"] = "project-context-mismatch"
                        break
                    report["project_context_matched"] = True
                    continue
                values = data.get("permissions", [])
                if (set(data) - {"permissions"} or not isinstance(values, list) or len(values) > 5
                        or any(not isinstance(p, str) or p not in contract["permissions"] for p in values)
                        or len(set(values)) != len(values)):
                    raise ValueError
                report["permissions"] = [{"permission": p, "provider_reported_granted": p in values} for p in contract["permissions"]]
                report.update(permission_query_completed=True, outcome="permission-response-observed")
            except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
                report["outcome"] = "invalid-response"
                break
    return report
