"""Bounded commercial AWS STS/EC2/S3 reads with explicit encrypted credentials.

The SDK signs only. No ambient credential discovery, endpoints, role assumption,
metadata access, mutations, redirects or retries are configurable.
"""
import hashlib
import hmac
import ipaddress
import math
import os
import re
import time
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from . import assessment_sessions, cloud_review, cloud_transport, shared_quota
from .bounty import BountyPolicy, _approved_file, _decode_json, resolve_pinned
from .cloud_inventory_common import live_window
from .engagement import digest, utcnow
from .scenario_assessment import _TLS, runtime_identity
from .source_files import read_bounded

FIELDS = {"schema_version", "provider", "account_id", "region", "authorization_reference", "acknowledged_authorization",
    "expires_at", "max_pages", "page_size", "max_resources", "interval_seconds", "timeout_seconds"}
HEADERS = {"X-AWS-Access-Key-ID", "X-AWS-Secret-Access-Key", "X-AWS-Session-Token"}
ACTIONS = ("DescribeInstances", "DescribeSecurityGroups", "ListBuckets")


def targets(data):
    return {"aws-sts": "https://sts.amazonaws.com", "aws-ec2": "https://ec2." + data["region"] + ".amazonaws.com",
        "aws-s3": "https://s3." + data["region"] + ".amazonaws.com"}


def load(path, session_file, session_key):
    raw = read_bounded(_approved_file(path), 16384)
    data = _decode_json(raw)
    if (not isinstance(data, dict) or set(data) != FIELDS or type(data["schema_version"]) is not int or data["schema_version"] != 1
            or data["provider"] != "aws" or not isinstance(data["account_id"], str) or not re.fullmatch(r"[0-9]{12}", data["account_id"])
            or not isinstance(data["region"], str) or not re.fullmatch(r"(?:us|eu|ap|ca|sa|me|af|il|mx)-[a-z]{3,16}-[1-9]", data["region"])
            or data["acknowledged_authorization"] is not True or not isinstance(data["authorization_reference"], str)
            or not 1 <= len(data["authorization_reference"].strip()) <= 200 or any(ord(c) < 32 for c in data["authorization_reference"])):
        raise ValueError("Invalid exact AWS account/region read contract")
    live_window(data["expires_at"])
    for key, low, high in (("max_pages", 1, 5), ("page_size", 5, 100), ("max_resources", 1, 100), ("timeout_seconds", 1, 300)):
        if type(data[key]) is not int or not low <= data[key] <= high:
            raise ValueError("Invalid AWS inventory limit")
    if type(data["interval_seconds"]) not in (int, float) or not math.isfinite(data["interval_seconds"]) or not 0.5 <= data["interval_seconds"] <= 5:
        raise ValueError("Use a bounded AWS request interval")
    actors, session_hash = assessment_sessions.load(session_file, session_key, purpose="aws-signing")
    if set(actors) != set(targets(data)):
        raise ValueError("Dedicated origin-bound STS/EC2/S3 credentials required")
    credentials = None
    for actor_id, origin in targets(data).items():
        actor = actors[actor_id]
        if actor["origin"] != origin or set(actor["headers"]) != HEADERS or actor["cookies"] or actor["local_storage"]:
            raise ValueError("AWS signing credential origin differs from the fixed API")
        values = actor["headers"]
        if (not re.fullmatch(r"ASIA[A-Z0-9]{16}", values["X-AWS-Access-Key-ID"])
                or not re.fullmatch(r"[A-Za-z0-9/+=]{40}", values["X-AWS-Secret-Access-Key"])
                or not 16 <= len(values["X-AWS-Session-Token"]) <= 8192 or any(not 33 <= ord(c) < 127 for c in values["X-AWS-Session-Token"])):
            raise ValueError("Only explicit short-lived AWS STS credentials are accepted")
        if credentials is not None and credentials != values:
            raise ValueError("All three signing origins must use the same reviewed identity")
        credentials = values
    from .cloud_account import require_cloud
    require_cloud()
    from importlib.metadata import version
    fingerprint = digest({"contract_sha256": hashlib.sha256(raw).hexdigest(), "session_binding": session_hash,
        "quota": shared_quota.configured_review(), "runtime": runtime_identity(), "botocore_version": version("botocore")})
    return data, actors, fingerprint


def preflight(path, session_file, session_key):
    data, _, fingerprint = load(path, session_file, session_key)
    return {"approval_sha256": fingerprint, "network_requests": 0, "maximum_requests": 1 + 3 * data["max_pages"],
        "actions": ["GetCallerIdentity", *ACTIONS], "sdk_credential_discovery": False, "resource_mutations": False}


def _policy(host):
    return BountyPolicy.from_dict({"program": "Explicit AWS inventory", "platform": "private", "authorization_reference": "Reviewed AWS API scope",
        "acknowledged_authorization": True, "allowed_hosts": [host], "allowed_paths": ["/"], "methods": ["GET"],
        "allowed_ports": [443], "max_requests": 1, "interval_seconds": 0.5})


def _transport(url, method, body, headers, *, before_send, end):
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.path != "/" or parts.username is not None or parts.password is not None or parts.fragment:
        raise ValueError("AWS API target rejected")
    policy = _policy(parts.hostname)
    policy.authorize_url(url, "GET")
    ip = resolve_pinned(policy, parts.hostname, 443)
    before_send()
    connection = _TLS(parts.hostname, ip, 443, end)
    connection.debuglevel = 0
    try:
        connection.connect()
        before_send()  # No signing credentials leave after context/expiry changes.
        connection.request(method, "/" + ("?" + parts.query if parts.query else ""), body=body,
            headers={**headers, "Connection": "close", "Accept-Encoding": "identity", "User-Agent": "HunterQA-AWS-read-inventory"})
        return cloud_transport.read_response(connection.getresponse(), 1048576)
    finally:
        connection.close()


def _signed(data, actors, action, token=None):
    from botocore.auth import SigV4Auth, S3SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials
    actor_id = "aws-sts" if action == "GetCallerIdentity" else "aws-s3" if action == "ListBuckets" else "aws-ec2"
    keys = actors[actor_id]["headers"]
    credentials = Credentials(keys["X-AWS-Access-Key-ID"], keys["X-AWS-Secret-Access-Key"], keys["X-AWS-Session-Token"])
    url, headers = targets(data)[actor_id] + "/", {}
    if action == "ListBuckets":
        params = {"max-buckets": str(data["page_size"]), "bucket-region": data["region"]}
        if token:
            params["continuation-token"] = token
        url += "?" + urlencode(params)
        method, body, service = "GET", None, "s3"
    else:
        if action not in {"GetCallerIdentity", "DescribeInstances", "DescribeSecurityGroups"}:
            raise ValueError("Only fixed read actions are supported")
        params = {"Action": action, "Version": "2011-06-15" if actor_id == "aws-sts" else "2016-11-15"}
        if actor_id == "aws-ec2":
            params["MaxResults"] = str(data["page_size"])
        if token:
            params["NextToken"] = token
        method, body, service = "POST", urlencode(params).encode(), "sts" if actor_id == "aws-sts" else "ec2"
        headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
    request = AWSRequest(method=method, url=url, data=body, headers=headers)
    signer = S3SigV4Auth if service == "s3" else SigV4Auth
    signer(credentials, service, "us-east-1" if service == "sts" else data["region"]).add_auth(request)
    return url, method, body, dict(request.headers.items())


def _text(element, path, default=None):
    return element.findtext(path, default)


def _xml(raw):
    from defusedxml import ElementTree
    root = ElementTree.fromstring(raw)
    count = 0
    for _ in root.iter():
        count += 1
        if count > 20000:
            raise ValueError("AWS XML node bound reached")
    return root


def _resources(root, action, data):
    resources, declarations = [], []
    if action == "DescribeInstances":
        if root.tag.split("}")[-1] != "DescribeInstancesResponse" or root.find("{*}reservationSet") is None:
            raise ValueError("Unexpected EC2 instance response")
        for reservation in root.findall("{*}reservationSet/{*}item"):
            if _text(reservation, "{*}ownerId") != data["account_id"]:
                raise PermissionError("EC2 reservation belongs to another account")
            for row in reservation.findall("{*}instancesSet/{*}item"):
                identity = _text(row, "{*}instanceId", "")
                if not re.fullmatch(r"i-(?:[a-f0-9]{8}|[a-f0-9]{17})", identity):
                    raise ValueError("Invalid instance identity")
                ref = digest(identity)
                address = _text(row, "{*}ipAddress")
                if address:
                    ipaddress.ip_address(address)
                tokens = _text(row, "{*}metadataOptions/{*}httpTokens")
                enabled = _text(row, "{*}metadataOptions/{*}httpEndpoint")
                state = _text(row, "{*}instanceState/{*}name", "unknown")
                resources.append({"kind": "virtual-machine", "resource_ref": ref, "public_address_present": bool(address), "state": state if state in {"pending", "running", "shutting-down", "terminated", "stopping", "stopped"} else "unknown"})
                if state == "running":
                    declarations.append({"id": "instance-" + ref[:32], "provider": "aws", "area": "compute", "observations": {
                        "imds_v2_required": tokens == "required" if enabled == "enabled" and tokens in {"required", "optional"} else None,
                        "metadata_hop_limit_reviewed": None, "instance_role_scope_reviewed": None}})
    elif action == "DescribeSecurityGroups":
        if root.tag.split("}")[-1] != "DescribeSecurityGroupsResponse" or root.find("{*}securityGroupInfo") is None:
            raise ValueError("Unexpected EC2 security group response")
        for row in root.findall("{*}securityGroupInfo/{*}item"):
            if _text(row, "{*}ownerId") != data["account_id"]:
                raise PermissionError("Security group belongs to another account")
            identity = _text(row, "{*}groupId", "")
            if not re.fullmatch(r"sg-(?:[a-f0-9]{8}|[a-f0-9]{17})", identity):
                raise ValueError("Invalid security group identity")
            ref, broad = digest(identity), False
            for permission in row.findall("{*}ipPermissions/{*}item"):
                protocol = _text(permission, "{*}ipProtocol", "")
                if protocol not in {"tcp", "6", "-1"}:
                    continue
                selected = protocol == "-1"
                if not selected:
                    low, high = _text(permission, "{*}fromPort", ""), _text(permission, "{*}toPort", "")
                    if not re.fullmatch(r"[0-9]{1,5}", low) or not re.fullmatch(r"[0-9]{1,5}", high) or not 0 <= int(low) <= int(high) <= 65535:
                        raise ValueError("Invalid TCP port declaration")
                    selected = any(int(low) <= port <= int(high) for port in (22, 3389, 1433, 3306, 5432, 6379, 27017))
                if selected:
                    cidrs = [_text(item, "{*}cidrIp", "") for item in permission.findall("{*}ipRanges/{*}item")]
                    cidrs += [_text(item, "{*}cidrIpv6", "") for item in permission.findall("{*}ipv6Ranges/{*}item")]
                    broad |= any(ipaddress.ip_network(value, strict=False).prefixlen == 0 for value in cidrs)
            resources.append({"kind": "security-group", "resource_ref": ref, "broad_admin_ingress_declared": broad})
            declarations.append({"id": "group-" + ref[:32], "provider": "aws", "area": "network", "observations": {
                "internet_admin_ports": broad, "public_database_endpoint": None, "flow_logs_enabled": None}})
    else:
        if root.tag.split("}")[-1] != "ListAllMyBucketsResult" or root.find("{*}Buckets") is None:
            raise ValueError("Unexpected S3 bucket list response")
        for row in root.findall("{*}Buckets/{*}Bucket"):
            name = _text(row, "{*}Name", "")
            if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", name) or _text(row, "{*}BucketRegion") != data["region"]:
                raise PermissionError("Bucket name or returned region differs from inventory scope")
            resources.append({"kind": "storage-bucket", "resource_ref": digest(name), "configuration_assessed": False})
    if len(resources) > data["page_size"]:
        raise ValueError("AWS response exceeded approved page size")
    return resources, declarations


def inventory(path, session_file, session_key, approval, *, authorized=False, transport=None, sleeper=time.sleep, evidence_dir=None):
    if authorized is not True:
        raise PermissionError("AWS collection requires --authorized")
    data, actors, fingerprint = load(path, session_file, session_key)
    if not isinstance(approval, str) or not hmac.compare_digest(approval, fingerprint):
        raise PermissionError("Approve the exact AWS account/region/credential/runtime fingerprint")
    destination = None
    if evidence_dir is not None:
        from .cli import _approved_root
        destination = Path(evidence_dir).expanduser()
        if not destination.is_absolute() or ".." in destination.parts or destination.exists():
            raise ValueError("Use a new approved private evidence directory")
        _approved_root(str(destination.parent))
        if any((parent / ".git").exists() for parent in (destination.parent, *destination.parents)):
            raise ValueError("Private raw AWS evidence must remain outside Git")
        destination.mkdir(mode=0o700)
    send = transport or _transport
    report = {"engine": "scoped-aws-resource-inventory", "schema_version": 1, "execution_source": "DEMO" if transport is not None else "LIVE",
        "synthetic": transport is not None, "collector": "custom-test-transport" if transport is not None else "aws-pinned-read-apis",
        "approval_sha256": fingerprint, "started_at": utcnow().isoformat(), "account_context_matched": False,
        "resources": [], "findings": [], "receipts": [], "services": {}, "stopped": False, "error_type": None,
        "private_raw_evidence_retained": destination is not None, "real_provider_verified": False,
        "limitations": ["One commercial account and region; EC2 instances/security groups and regional general-purpose S3 bucket names only",
            "No complete inventory, effective IAM, bucket policies/encryption, logging, key management, role assumption, data-plane access or metadata requests",
            "Broad ingress and IMDS declarations are review cues, not verified reachability or compromise; received values are provider assertions",
            "Shared per-request post-DNS IO deadline and total request budget; OS resolver delays are not forcibly cancelled",
            "Raw evidence is retained only when explicitly requested; hashes alone are not independent provenance; actual provider validation remains unverified"]}
    end = time.monotonic() + data["timeout_seconds"]
    records, seen = [], set()
    stop = _approved_file(path).parent / "stop"
    with shared_quota.invocation(1 + 3 * data["max_pages"]) as admission:
        report["shared_quota"] = admission.receipt
        def gate():
            admission.ensure_active()
            if stop.exists() or time.monotonic() >= end or load(path, session_file, session_key)[2] != fingerprint:
                raise PermissionError("AWS inventory stopped, changed or expired")

        def request(action, token=None):
            gate()
            url, method, body, headers = _signed(data, actors, action, token)
            receipt = {"action": action, "target_sha256": digest(url), "status": None}
            report["receipts"].append(receipt)
            response = send(url, method, body, headers, before_send=gate, end=min(end, time.monotonic() + 5))
            if not isinstance(response, dict) or type(response.get("status")) is not int or not isinstance(response.get("body"), bytes) or len(response["body"]) > 1048576:
                raise ValueError("Invalid bounded AWS response")
            receipt.update(status=response["status"], body_sha256=hashlib.sha256(response["body"]).hexdigest(), body_bytes=len(response["body"]))
            if destination is not None:
                filename = "response-" + str(len(report["receipts"])).zfill(4) + ".xml"
                fd = os.open(destination / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(response["body"])
                receipt["evidence_file"] = filename
            gate()
            if response["status"] != 200:
                raise PermissionError("AWS API unavailable or caller lacks the required read permission")
            return _xml(response["body"])
        try:
            context = request("GetCallerIdentity")
            if _text(context, ".//{*}GetCallerIdentityResult/{*}Account") != data["account_id"]:
                raise PermissionError("AWS account context mismatch")
            report["account_context_matched"] = True
            limited = False
            for action in ACTIONS:
                token, tokens = None, set()
                state = {"pages": 0, "visible_pages_exhausted": False, "outcome": "page-limit"}
                report["services"][action] = state
                for _ in range(data["max_pages"]):
                    sleeper(data["interval_seconds"])
                    root = request(action, token)
                    resources, declarations = _resources(root, action, data)
                    state["pages"] += 1
                    allowed = set()
                    for row in resources:
                        if row["resource_ref"] in seen:
                            continue
                        if len(report["resources"]) >= data["max_resources"]:
                            limited = True
                            break
                        seen.add(row["resource_ref"])
                        allowed.add(row["resource_ref"][:32])
                        report["resources"].append(row)
                    records.extend(row for row in declarations if row["id"].split("-", 1)[1] in allowed)
                    token = _text(root, "{*}ContinuationToken" if action == "ListBuckets" else "{*}nextToken", "")
                    if limited:
                        state["outcome"] = "resource-limit"
                        break
                    if not token:
                        state.update(visible_pages_exhausted=True, outcome="visible-pages-exhausted")
                        break
                    if not isinstance(token, str) or not 1 <= len(token) <= 1024 or any(not 33 <= ord(c) < 127 for c in token) or token in tokens:
                        raise ValueError("AWS continuation token rejected")
                    tokens.add(token)
                if limited:
                    break
        except Exception as error:
            report["stopped"], report["error_type"] = True, type(error).__name__
        if records:
            # The existing analyzer deliberately bounds records per area. Reuse
            # it per collected record without relaxing its input contract.
            report["findings"] = [finding for row in records
                for finding in cloud_review.review_evidence({"schema_version": 1, "records": [row]})["findings"]]
    report["resources_retained"] = len(report["resources"])
    report["visible_pagination_exhausted"] = len(report["services"]) == 3 and all(row["visible_pages_exhausted"] for row in report["services"].values()) and not report["stopped"]
    report["finished_at"] = utcnow().isoformat()
    if destination is not None:
        from .assessment_demo import save
        save(destination / "manifest.json", {"execution_source": report["execution_source"], "approval_sha256": fingerprint, "receipts": report["receipts"]})
    return report
