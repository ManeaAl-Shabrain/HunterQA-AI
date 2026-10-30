"""Bounded commercial Azure ARM inventory using explicit short-lived bearer credentials."""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import math
import re
import socket
import ssl
import time
from urllib.parse import parse_qsl, urlencode, urlsplit

from .bounty import BountyPolicy, _approved_file, _decode_json, resolve_pinned
from .engagement import digest, utcnow
from .cloud_inventory_common import live_window as _live, temporary_credentials as _credentials, bounded_json as _json
from .source_files import read_bounded

HOST = "management.azure.com"
ORIGIN = "https://" + HOST
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
FIELDS = {"schema_version", "provider", "subscription_id", "tenant_id", "authorization_reference",
          "acknowledged_authorization", "expires_at", "max_pages", "page_size", "max_resources", "interval_seconds"}
KINDS = {"microsoft.compute/virtualmachines": "virtual-machine", "microsoft.storage/storageaccounts": "storage-account",
    "microsoft.network/virtualnetworks": "virtual-network", "microsoft.network/networkinterfaces": "network-interface",
    "microsoft.network/publicipaddresses": "public-ip", "microsoft.network/networksecuritygroups": "network-security-group",
    "microsoft.sql/servers": "sql-server", "microsoft.sql/servers/databases": "sql-database",
    "microsoft.keyvault/vaults": "key-vault", "microsoft.web/sites": "app-service",
    "microsoft.containerservice/managedclusters": "kubernetes-cluster", "microsoft.containerregistry/registries": "container-registry"}


def validate_contract(data):
    try:
        if not isinstance(data, dict) or set(data) != FIELDS:
            raise ValueError
        if type(data["schema_version"]) is not int or data["schema_version"] != 1 or data["provider"] != "azure":
            raise ValueError
        for field in ("subscription_id", "tenant_id"):
            if not isinstance(data[field], str) or not UUID.fullmatch(data[field]):
                raise ValueError
        ref = data["authorization_reference"]
        if data["acknowledged_authorization"] is not True or not isinstance(ref, str) or not 1 <= len(ref) <= 200 or not ref.strip() or any(ord(c) < 32 for c in ref):
            raise ValueError
        for field, limit in (("max_pages", 5), ("page_size", 100), ("max_resources", 500)):
            if type(data[field]) is not int or not 1 <= data[field] <= limit:
                raise ValueError
        delay = data["interval_seconds"]
        if type(delay) not in (int, float) or not math.isfinite(delay) or not 0.5 <= delay <= 5:
            raise ValueError
        _live(data["expires_at"])
    except (ValueError, TypeError):
        raise ValueError("Invalid Azure inventory contract; private values withheld") from None
    return data


def _resource_path(contract):
    return "/subscriptions/" + contract["subscription_id"] + "/resources"


def _next_target(value, contract):
    if not isinstance(value, str) or not 1 <= len(value) <= 4096 or any(not 33 <= ord(c) < 127 for c in value) or "\\" in value:
        raise ValueError("Unsupported Azure continuation link")
    parts = urlsplit(value)
    if (parts.scheme != "https" or parts.netloc != HOST or parts.fragment
            or parts.path.lower() != _resource_path(contract) or "%" in parts.path):
        raise ValueError("Azure continuation exceeds exact subscription scope")
    pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True, max_num_fields=3)
    params = dict(pairs)
    if len(params) != len(pairs) or not {"api-version", "$skiptoken"} <= set(params) <= {"api-version", "$skiptoken", "$top"}:
        raise ValueError("Unsupported Azure continuation parameters")
    token = params["$skiptoken"]
    if (params["api-version"] != "2021-04-01" or not 1 <= len(token) <= 2048
            or any(not 33 <= ord(c) < 127 for c in token)
            or ("$top" in params and params["$top"] != str(contract["page_size"]))):
        raise ValueError("Azure continuation policy mismatch")
    return ORIGIN + _resource_path(contract) + "?" + urlencode(sorted(pairs))


def _dial(ip):
    channel = socket.socket(socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET, socket.SOCK_STREAM)
    try:
        channel.settimeout(5)
        channel.connect((ip, 443))
        return channel
    except BaseException:
        channel.close()
        raise


class _ARMConnection(http.client.HTTPSConnection):
    def __init__(self, ip):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_flags |= ssl.VERIFY_X509_STRICT | ssl.VERIFY_X509_PARTIAL_CHAIN
        context.load_default_certs()
        super().__init__(HOST, 443, timeout=5, context=context)
        self.ip = ip
        self.debuglevel = 0  # Never inherit HTTP debug printing of bearer headers.

    def connect(self):
        channel = _dial(self.ip)
        try:
            self.sock = self._context.wrap_socket(channel, server_hostname=HOST)
        except BaseException:
            channel.close()
            raise


def _arm_get(target, token, *, before_send):
    parts = urlsplit(target)
    if parts.scheme != "https" or parts.netloc != HOST or parts.fragment or not re.fullmatch(r"/subscriptions/[0-9a-f-]{36}(?:/resources)?", parts.path):
        raise ValueError("Azure request target rejected")
    policy = BountyPolicy.from_dict({"program": "Explicit Azure inventory", "platform": "private",
        "authorization_reference": "Exact invocation contract", "acknowledged_authorization": True,
        "allowed_hosts": [HOST], "allowed_ports": [443], "allowed_paths": ["/subscriptions"],
        "methods": ["GET"], "max_requests": 1, "interval_seconds": 0.5})
    ip = resolve_pinned(policy, HOST, 443)
    before_send()  # DNS delays cannot extend authorization for a new connection.
    connection = _ARMConnection(ip)
    try:
        connection.connect()
        before_send()  # Check again after TLS, before sending the bearer token.
        connection.request("GET", parts.path + "?" + parts.query,
            headers={"Authorization": "Bearer " + token, "Accept": "application/json",
                     "Accept-Encoding": "identity", "Connection": "close", "User-Agent": "HunterQA-AI scoped-azure-inventory"})
        response = connection.getresponse()
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise ValueError("Unsupported Azure response encoding")
        body = response.read(1048577)
        if len(body) > 1048576:
            raise ValueError("Azure response size rejected")
        return {"status": response.status, "body": body}
    finally:
        connection.close()


def _resource(row, contract):
    if not isinstance(row, dict):
        raise ValueError("Invalid resource")
    rid, kind = row.get("id"), row.get("type")
    if (not isinstance(rid, str) or not 1 <= len(rid) <= 2048 or not rid.startswith("/")
            or any(not 32 <= ord(c) < 127 for c in rid) or any(c in rid for c in "?#%\\")
            or not isinstance(kind, str) or not 1 <= len(kind) <= 256
            or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+", kind)):
        raise ValueError("Unsupported resource identifier")
    segments = rid[1:].split("/")
    if any(part in ("", ".", "..") for part in segments) or [p.lower() for p in segments[:2]] != ["subscriptions", contract["subscription_id"]]:
        raise ValueError("Resource outside subscription")
    offset, group = 2, None
    if len(segments) > 3 and segments[2].lower() == "resourcegroups":
        group, offset = segments[3].lower(), 4
    tail = segments[offset:]
    if len(tail) < 4 or len(tail) % 2 or tail[0].lower() != "providers" or "/".join(tail[1:2] + tail[2::2]).lower() != kind.lower():
        raise ValueError("Unsupported resource type path")
    return {"resource_ref": digest(rid.lower()), "resource_group_ref": digest(group) if group is not None else None,
            "type_ref": digest(kind.lower()), "kind": KINDS.get(kind.lower(), "other")}


def inventory(input_file, credential_file, *, authorized=False, transport=None, sleeper=time.sleep):
    if authorized is not True:
        raise PermissionError("Azure inventory requires --authorized and written subscription permission")
    raw = read_bounded(_approved_file(input_file), 16384)
    secret = read_bounded(_approved_file(credential_file), 32768)
    try:
        contract = validate_contract(_decode_json(raw))
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise ValueError("Invalid Azure inventory contract; private values withheld") from None
    keys = _credentials(secret)
    transport = transport or _arm_get
    def gate():
        try:
            if read_bounded(_approved_file(input_file), 16384) != raw or read_bounded(_approved_file(credential_file), 32768) != secret:
                raise ValueError
            validate_contract(contract)
            _live(keys["expires_at"])
        except (ValueError, OSError):
            raise PermissionError("Azure authorization changed or expired") from None
    report = {"engine": "scoped-azure-inventory", "schema_version": 1, "observed_at": utcnow().isoformat(),
        "input_sha256": hashlib.sha256(raw).hexdigest(), "subscription_ref": digest(contract["subscription_id"]),
        "tenant_ref": digest(contract["tenant_id"]), "request_budget": 1 + contract["max_pages"],
        "requests_attempted": 0, "requests_completed": 0, "subscription_context_matched": False,
        "pages_observed": 0, "visible_pagination_exhausted": False, "inventory_complete": False,
        "resources": [], "duplicates_not_retained": 0, "outcome": "inconclusive", "receipts": [],
        "effective_permissions_verified": False, "owner_grant_verified": False, "findings": [],
        "limitations": ["Commercial Azure ARM only; subscription context then bounded generic resource-list pages visible to the supplied token",
            "No SDK/CLI credential discovery, login, refresh, managed identity, role assumption, redirects, retries or resource modification",
            "Strict continuation host/path/API/query checks; unknown formats stop collection rather than expanding scope",
            "No RBAC, deny/condition/PIM evaluation, data-plane access, configuration review or general tenant isolation assessment",
            "Pagination exhaustion is not inventory completeness: permissions, API omissions, service behavior and concurrent changes can hide resources",
            "Five-second socket inactivity timeout, one-MiB response cap; no independent process-wide wall-clock deadline",
            "Invocation-local quotas and operator attestation only; hashes do not authenticate provenance or anonymize guessable data",
            "Runtime adapter has owned/synthetic transport controls; representative Azure field effectiveness remains unverified"]}
    target = ORIGIN + "/subscriptions/" + contract["subscription_id"] + "?api-version=2022-12-01"
    seen_targets, seen_resources = set(), set()
    for index in range(1 + contract["max_pages"]):
        if index:
            sleeper(contract["interval_seconds"])
        receipt = {"action": "subscription-context" if index == 0 else "list-resources",
                   "target_sha256": digest(target), "status": None, "body_sha256": None, "body_bytes": None}
        try:
            gate()
            report["requests_attempted"] += 1
            seen_targets.add(target)
            report["receipts"].append(receipt)
            response = transport(target, keys["access_token"], before_send=gate)
        except PermissionError:
            report["outcome"] = "authorization-stopped"
            break
        except (OSError, http.client.HTTPException, ValueError):
            report["outcome"] = "transport-rejected"
            break
        try:
            status, body = response["status"], response["body"]
            if type(status) is not int or not 100 <= status <= 599 or not isinstance(body, bytes) or len(body) > 1048576:
                raise ValueError
            receipt.update(status=status, body_sha256=hashlib.sha256(body).hexdigest(), body_bytes=len(body))
            report["requests_completed"] += 1
            if status != 200:
                report["outcome"] = "http-error"
                break
            data = _json(body)
            if index == 0:
                if (data.get("subscriptionId") != contract["subscription_id"] or data.get("tenantId") != contract["tenant_id"]
                        or data.get("id", "").lower() != "/subscriptions/" + contract["subscription_id"]):
                    report["outcome"] = "subscription-context-mismatch"
                    break
                report["subscription_context_matched"] = True
                target = ORIGIN + _resource_path(contract) + "?" + urlencode({"api-version": "2021-04-01", "$top": contract["page_size"]})
                continue
            values = data.get("value")
            if not isinstance(values, list) or len(values) > 500:
                raise ValueError
            rows = [_resource(row, contract) for row in values]
            report["pages_observed"] += 1
            limited = False
            for row in rows:
                if row["resource_ref"] in seen_resources:
                    report["duplicates_not_retained"] += 1
                elif len(report["resources"]) < contract["max_resources"]:
                    seen_resources.add(row["resource_ref"])
                    report["resources"].append(row)
                else:
                    limited = True
            continuation = data.get("nextLink")
            if continuation is None or continuation == "":
                report.update(visible_pagination_exhausted=not limited,
                              outcome="resource-limit" if limited else "visible-pages-exhausted")
                break
            if limited or len(report["resources"]) >= contract["max_resources"]:
                report["outcome"] = "resource-limit"
                break
            try:
                target = _next_target(continuation, contract)
            except ValueError:
                report["outcome"] = "next-link-rejected"
                break
            if target in seen_targets:
                report["outcome"] = "pagination-loop"
                break
            report["outcome"] = "page-limit"
        except (ValueError, UnicodeError, RecursionError, TypeError, KeyError, AttributeError):
            report["outcome"] = "invalid-response"
            break
    report["resources_retained"] = len(report["resources"])
    return report
