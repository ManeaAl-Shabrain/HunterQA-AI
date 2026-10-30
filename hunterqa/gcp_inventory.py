"""One project context and bounded Cloud Asset Inventory pages; explicit temporary token."""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import math
import re
import socket
import ssl
import time
from urllib.parse import urlencode, urlsplit

from .bounty import BountyPolicy, _approved_file, _decode_json, resolve_pinned
from .cloud_inventory_common import live_window, temporary_credentials, bounded_json
from .engagement import _expiry, digest, utcnow
from .source_files import read_bounded

CONTEXT_HOST = "cloudresourcemanager.googleapis.com"
ASSET_HOST = "cloudasset.googleapis.com"
PROJECT_ID = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]\Z")
NUMBER = re.compile(r"[1-9][0-9]{0,19}\Z")
PARENT = re.compile(r"(?:organizations|folders)/[1-9][0-9]{0,19}\Z")
FIELDS = {"schema_version", "provider", "project_id", "project_number", "expected_parent", "read_time",
          "authorization_reference", "acknowledged_authorization", "expires_at",
          "max_pages", "page_size", "max_resources", "interval_seconds"}
PROJECTION = "readTime,nextPageToken,assets(name,assetType,ancestors)"
KINDS = {"compute.googleapis.com/Instance": "virtual-machine", "compute.googleapis.com/Disk": "disk",
    "compute.googleapis.com/Network": "virtual-network", "compute.googleapis.com/Firewall": "firewall",
    "storage.googleapis.com/Bucket": "storage-bucket", "container.googleapis.com/Cluster": "kubernetes-cluster",
    "sqladmin.googleapis.com/Instance": "sql-instance", "iam.googleapis.com/ServiceAccount": "service-account",
    "cloudresourcemanager.googleapis.com/Project": "project"}


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
        for field, maximum in (("max_pages", 5), ("page_size", 100), ("max_resources", 500)):
            if type(data[field]) is not int or not 1 <= data[field] <= maximum:
                raise ValueError
        delay = data["interval_seconds"]
        if type(delay) not in (int, float) or not math.isfinite(delay) or not 0.5 <= delay <= 5:
            raise ValueError
        live_window(data["expires_at"])
        _read_time(data["read_time"])
        if _expiry(data["read_time"]) > utcnow():
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError("Invalid GCP inventory contract; private values withheld") from None
    return data


def _read_time(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3}(?:[0-9]{3})?(?:[0-9]{3})?)?Z", value):
        raise ValueError("Unsupported GCP snapshot timestamp")
    age = (utcnow() - _expiry(value)).total_seconds()
    if not -60 <= age <= 3600:
        raise ValueError("GCP snapshot outside bounded freshness window")
    # Canonicalize equivalent 3/6/9-digit protobuf representations without
    # rounding nanoseconds through datetime's microsecond precision.
    fraction = value[20:-1] if len(value) > 20 else ""
    nanos = fraction.ljust(9, "0")
    if int(nanos) == 0:
        return value[:19] + "Z"
    width = 3 if nanos[3:] == "000000" else (6 if nanos[6:] == "000" else 9)
    return value[:19] + "." + nanos[:width] + "Z"


def _target(contract, page_token=None, read_time=None):
    params = {"contentType": "RESOURCE", "pageSize": str(contract["page_size"]), "fields": PROJECTION}
    if page_token is not None:
        if not isinstance(page_token, str) or not 1 <= len(page_token) <= 2048 or any(not 33 <= ord(c) < 127 for c in page_token):
            raise ValueError("Unsupported GCP continuation token")
        params["pageToken"] = page_token
    if read_time is not None:
        params["readTime"] = _read_time(read_time)
    return "https://" + ASSET_HOST + "/v1/projects/" + contract["project_number"] + "/assets?" + urlencode(params)


def _asset(row, contract):
    if not isinstance(row, dict):
        raise ValueError("Invalid GCP asset")
    name, kind, ancestors = row.get("name"), row.get("assetType"), row.get("ancestors")
    if (not isinstance(name, str) or not 1 <= len(name) <= 2048 or any(not 33 <= ord(c) < 127 for c in name)
            or any(c in name for c in "?#%\\") or not re.fullmatch(r"//[a-z][a-z0-9.-]{0,100}\.googleapis\.com/.+", name)
            or not isinstance(kind, str) or not 1 <= len(kind) <= 256
            or not re.fullmatch(r"[a-z][a-z0-9.-]{0,100}\.googleapis\.com/[A-Za-z][A-Za-z0-9_.]{0,127}", kind)):
        raise ValueError("Unsupported GCP asset identifier")
    path = name.split("/", 3)[3].split("/")
    if any(segment in ("", ".", "..") for segment in path):
        raise ValueError("Ambiguous GCP asset path")
    if path[0] == "projects" and (len(path) < 2 or path[1] not in (contract["project_id"], contract["project_number"])):
        raise ValueError("GCP asset name exceeds project scope")
    if not isinstance(ancestors, list) or not 1 <= len(ancestors) <= 12 or any(not isinstance(a, str) for a in ancestors):
        raise ValueError("Missing bounded GCP asset ancestry")
    if ancestors[0] != "projects/" + contract["project_number"] or len(set(ancestors)) != len(ancestors):
        raise ValueError("GCP asset outside project ancestry")
    tail = ancestors[1:]
    if any(not PARENT.fullmatch(a) for a in tail) or any(a.startswith("organizations/") for a in tail[:-1]):
        raise ValueError("Unsupported GCP hierarchy")
    expected = contract["expected_parent"]
    if (expected is None and tail) or (expected is not None and (not tail or tail[0] != expected)):
        raise ValueError("GCP asset parent context mismatch")
    return {"asset_ref": digest(name), "type_ref": digest(kind), "kind": KINDS.get(kind, "other")}


def _dial(ip):
    channel = socket.socket(socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET, socket.SOCK_STREAM)
    try:
        channel.settimeout(5)
        channel.connect((ip, 443))
        return channel
    except BaseException:
        channel.close()
        raise


class _GCPConnection(http.client.HTTPSConnection):
    def __init__(self, host, ip):
        if host not in (CONTEXT_HOST, ASSET_HOST):
            raise ValueError("Unsupported GCP credential destination")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_flags |= ssl.VERIFY_X509_STRICT | ssl.VERIFY_X509_PARTIAL_CHAIN
        context.load_default_certs()
        super().__init__(host, 443, timeout=5, context=context)
        self.ip, self.debuglevel = ip, 0

    def connect(self):
        channel = _dial(self.ip)
        try:
            self.sock = self._context.wrap_socket(channel, server_hostname=self.host)
        except BaseException:
            channel.close()
            raise


def _gcp_get(target, token, *, before_send):
    parts = urlsplit(target)
    paths = {CONTEXT_HOST: r"/v3/projects/[1-9][0-9]{0,19}", ASSET_HOST: r"/v1/projects/[1-9][0-9]{0,19}/assets"}
    if parts.scheme != "https" or parts.netloc not in paths or parts.fragment or not re.fullmatch(paths[parts.netloc], parts.path):
        raise ValueError("GCP request target rejected")
    host = parts.netloc
    policy = BountyPolicy.from_dict({"program": "Explicit GCP inventory", "platform": "private",
        "authorization_reference": "Exact invocation contract", "acknowledged_authorization": True,
        "allowed_hosts": [host], "allowed_ports": [443], "allowed_paths": [parts.path],
        "methods": ["GET"], "max_requests": 1, "interval_seconds": 0.5})
    ip = resolve_pinned(policy, host, 443)
    before_send()
    connection = _GCPConnection(host, ip)
    try:
        connection.connect()
        before_send()
        connection.request("GET", parts.path + ("?" + parts.query if parts.query else ""), headers={
            "Authorization": "Bearer " + token, "Accept": "application/json", "Accept-Encoding": "identity",
            "Connection": "close", "User-Agent": "HunterQA-AI scoped-gcp-inventory"})
        response = connection.getresponse()
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise ValueError("Unsupported GCP response encoding")
        body = response.read(1048577)
        if len(body) > 1048576:
            raise ValueError("GCP response size rejected")
        return {"status": response.status, "body": body}
    finally:
        connection.close()


def inventory(input_file, credential_file, *, authorized=False, transport=None, sleeper=time.sleep):
    if authorized is not True:
        raise PermissionError("GCP inventory requires --authorized and written project permission")
    raw = read_bounded(_approved_file(input_file), 16384)
    secret = read_bounded(_approved_file(credential_file), 32768)
    try:
        contract = validate_contract(_decode_json(raw))
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise ValueError("Invalid GCP inventory contract; private values withheld") from None
    keys = temporary_credentials(secret)
    transport = transport or _gcp_get
    def gate():
        try:
            if read_bounded(_approved_file(input_file), 16384) != raw or read_bounded(_approved_file(credential_file), 32768) != secret:
                raise ValueError
            validate_contract(contract)
            live_window(keys["expires_at"])
        except (ValueError, OSError):
            raise PermissionError("GCP authorization changed or expired") from None
    report = {"engine": "scoped-gcp-inventory", "schema_version": 1, "observed_at": utcnow().isoformat(),
        "input_sha256": hashlib.sha256(raw).hexdigest(), "project_ref": digest(contract["project_id"]),
        "project_number_ref": digest(contract["project_number"]), "parent_ref": digest(contract["expected_parent"]) if contract["expected_parent"] is not None else None,
        "request_budget": 1 + contract["max_pages"], "requests_attempted": 0, "requests_completed": 0,
        "project_context_matched": False, "pages_observed": 0, "visible_pagination_exhausted": False,
        "requested_read_time": _read_time(contract["read_time"]), "snapshot_read_time": None,
        "read_time_consistent": None, "inventory_complete": False,
        "effective_permissions_verified": False, "owner_grant_verified": False, "assets": [],
        "duplicates_not_retained": 0, "receipts": [], "findings": [], "outcome": "inconclusive",
        "limitations": ["One Resource Manager v3 project context then bounded Cloud Asset Inventory v1 RESOURCE pages with a fixed metadata projection",
            "No ADC/SDK/CLI discovery, login, metadata credentials, refresh, impersonation, API enablement, quota-project header or resource mutation",
            "Opaque continuation tokens are encoded into a fixed project URL, never followed as links; no redirects or retries",
            "Exact project number/ID/direct parent and per-asset ancestry are required; unsupported or cross-project shapes stop the entire page",
            "Reported snapshot time is pinned across pages but does not prove atomicity, freshness, CAI completeness or consistency during indexing delays",
            "No IAM/deny/condition evaluation, organization/folder enumeration, data-plane requests or general tenant isolation testing",
            "Five-second socket inactivity timeout and one-MiB response cap; no independent process-wide deadline, OS isolation or shared quota",
            "Local operator attestation and hashes do not verify owner grants, provenance or anonymity; representative GCP field effectiveness is unverified"]}
    target = "https://" + CONTEXT_HOST + "/v3/projects/" + contract["project_number"] + "?" + urlencode({"fields": "name,projectId,parent,state"})
    seen_assets, seen_tokens = set(), set()
    for index in range(1 + contract["max_pages"]):
        if index:
            sleeper(contract["interval_seconds"])
        receipt = {"action": "project-context" if index == 0 else "list-assets", "target_sha256": digest(target),
                   "status": None, "body_bytes": None, "body_sha256": None}
        try:
            gate()
            report["requests_attempted"] += 1
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
            receipt.update(status=status, body_bytes=len(body), body_sha256=hashlib.sha256(body).hexdigest())
            report["requests_completed"] += 1
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
                target = _target(contract, read_time=contract["read_time"])
                continue
            stamp = _read_time(data.get("readTime"))
            if stamp != report["requested_read_time"]:
                report.update(outcome="snapshot-mismatch", read_time_consistent=False)
                break
            values = data.get("assets", [])
            if not isinstance(values, list) or len(values) > 500:
                raise ValueError
            rows = [_asset(row, contract) for row in values]
            report.update(snapshot_read_time=stamp, read_time_consistent=True)
            report["pages_observed"] += 1
            limited = False
            for row in rows:
                if row["asset_ref"] in seen_assets:
                    report["duplicates_not_retained"] += 1
                elif len(report["assets"]) < contract["max_resources"]:
                    seen_assets.add(row["asset_ref"])
                    report["assets"].append(row)
                else:
                    limited = True
            continuation = data.get("nextPageToken", "")
            if continuation == "":
                report.update(visible_pagination_exhausted=not limited, outcome="resource-limit" if limited else "visible-pages-exhausted")
                break
            if limited or len(report["assets"]) >= contract["max_resources"]:
                report["outcome"] = "resource-limit"
                break
            try:
                if not isinstance(continuation, str):
                    raise ValueError("Unsupported GCP page token shape")
                target = _target(contract, continuation, stamp)
            except ValueError:
                report["outcome"] = "page-token-rejected"
                break
            if continuation in seen_tokens:
                report["outcome"] = "pagination-loop"
                break
            seen_tokens.add(continuation)
            report["outcome"] = "page-limit"
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
            report["outcome"] = "invalid-response"
            break
    report["assets_retained"] = len(report["assets"])
    return report
