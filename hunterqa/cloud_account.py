"""Two fixed read-only AWS APIs, pinned HTTPS, explicit temporary credentials.

No SDK credential discovery, metadata access, resource mutation or role assumption.
"""
from __future__ import annotations

import hashlib
import importlib.util
import re
import time
from urllib.parse import urlencode

from .bounty import BountyPolicy, _approved_file, _decode_json
from .engagement import _expiry, digest, pinned_request, utcnow
from .source_files import read_bounded
from .workflow_network import NetworkJournal, read_manifest
from .workflow_protocol import _fields, _integer

TARGETS = ["https://sts.amazonaws.com/", "https://iam.amazonaws.com/"]
COUNTERS = {"AccountMFAEnabled", "AccountAccessKeysPresent", "AccountPasswordPresent",
            "AccountSigningCertificatesPresent", "Users", "Groups", "Roles", "Policies",
            "Providers", "MFADevices", "MFADevicesInUse"}


def validate_account(data):
    _fields(data, ("schema_version", "account_id"), "AWS account scope")
    _integer(data["schema_version"], 1, 1, "schema_version")
    if not isinstance(data["account_id"], str) or not re.fullmatch(r"[0-9]{12}", data["account_id"]):
        raise ValueError("An exact 12-digit AWS account ID is required")
    return data


def require_cloud():
    if any(importlib.util.find_spec(name) is None for name in ("botocore", "defusedxml")):
        raise ValueError("Install HunterQA's cloud extra before planning AWS checks")


def credentials(binding):
    path = _approved_file(binding["secret_file"])
    raw = read_bounded(path, 32_768)
    if hashlib.sha256(raw).hexdigest() != binding["secret_file_sha256"]:
        raise PermissionError("AWS credential file changed after review")
    data = _decode_json(raw)
    _fields(data, ("access_key_id", "secret_access_key", "session_token", "expires_at"), "temporary AWS credentials")
    if not isinstance(data["access_key_id"], str) or not re.fullmatch(r"ASIA[A-Z0-9]{16}", data["access_key_id"]):
        raise ValueError("Use dedicated temporary AWS credentials, not long-lived keys")
    if not isinstance(data["secret_access_key"], str) or not re.fullmatch(r"[A-Za-z0-9/+=]{40}", data["secret_access_key"]):
        raise ValueError("Invalid temporary AWS secret")
    token = data["session_token"]
    if not isinstance(token, str) or not 16 <= len(token) <= 8192 or any(not 33 <= ord(c) < 127 for c in token):
        raise ValueError("A bounded temporary AWS session token is required")
    if not 0 < (_expiry(data["expires_at"]) - utcnow()).total_seconds() <= 86_400:
        raise PermissionError("Temporary AWS credentials must expire within 24 hours")
    return data


def _signed(credentials, service, action, version):
    # The SDK signs only; network transport and credentials remain explicit.
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials
    body = urlencode({"Action": action, "Version": version}).encode("ascii")
    request = AWSRequest(method="POST", url=TARGETS[0 if service == "sts" else 1], data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"})
    signer = Credentials(credentials["access_key_id"], credentials["secret_access_key"], credentials["session_token"])
    SigV4Auth(signer, service, "us-east-1").add_auth(request)
    return body, dict(request.headers.items())


def execute_account(request, *, transport=pinned_request, sleeper=time.sleep):
    from defusedxml import ElementTree
    policy = BountyPolicy.from_dict(request["policy"])
    binding, step = request["binding"], request["step"]
    account = validate_account(read_manifest(binding, 1024))
    if step["targets"] != TARGETS or step["requests"] != 2:
        raise ValueError("AWS account checks require exactly the two fixed endpoints and two requests")
    journal = NetworkJournal(request["network_log"])
    observations, findings, counters = [], [], {}
    summary = {"account_ref": digest(account["account_id"]), "identity_matched": False, "summary_observed": False}
    stopped = False
    try:
        for index, (service, action, version) in enumerate((
                ("sts", "GetCallerIdentity", "2011-06-15"), ("iam", "GetAccountSummary", "2010-05-08"))):
            if index:
                sleeper(request["interval_seconds"])
            keys = credentials(binding)
            target = TARGETS[index]
            body, headers = _signed(keys, service, action, version)
            journal.append("intent", target, "POST")
            try:
                response = transport(policy, target, "POST", body=body, headers=headers)
            except Exception as exc:
                journal.append("error", target, "POST", error_type=type(exc).__name__)
                raise
            status = response["status"]
            journal.append("response", target, "POST", status=status)
            observations.append({"target_sha256": digest(target), "method": "POST", "action": action,
                "status": status, "body_sha256": hashlib.sha256(response["body"]).hexdigest(),
                "verification_status": "unverified"})
            if status != 200:
                stopped = True
                break
            xml = ElementTree.fromstring(response["body"])
            if index == 0:
                observed_account = xml.findtext(".//{*}GetCallerIdentityResult/{*}Account")
                if observed_account != account["account_id"]:
                    stopped = True
                    break  # Never query IAM in an unexpected account.
                summary["identity_matched"] = True
                arn = xml.findtext(".//{*}GetCallerIdentityResult/{*}Arn", "")
                summary["principal_ref"] = digest(arn)
            else:
                for entry in xml.findall(".//{*}GetAccountSummaryResult/{*}SummaryMap/{*}entry"):
                    key, value = entry.findtext("{*}key"), entry.findtext("{*}value", "")
                    if key in COUNTERS and re.fullmatch(r"[0-9]{1,12}", value):
                        if key in counters:
                            raise ValueError("Duplicate AWS summary counter")
                        counters[key] = int(value)
                if not counters:
                    raise ValueError("AWS response did not contain selected account summary counters")
                summary["summary_observed"] = True
        cues = []
        if counters.get("AccountMFAEnabled") == 0 and counters.get("AccountPasswordPresent") == 1:
            cues.append(("cloud.aws.root-mfa-review", "Root password is present and account MFA is not enabled; review root access policy"))
        if counters.get("AccountAccessKeysPresent") == 1:
            cues.append(("cloud.aws.root-keys-review", "Account access keys are present; independently review root credential use"))
        for rule, title in cues:
            findings.append({"rule_id": rule, "title": title, "severity": "WARNING", "cwe": "CWE-284",
                "file_path": "external-evidence", "line_start": 1,
                "target_ref_hash": hashlib.sha256(TARGETS[1].encode()).hexdigest(),
                "verification_status": "unverified"})
        return {"adapter": "aws-account-audit", "adapter_version": 1, "requests": len(observations),
            "observations": observations, "findings": findings, "safety_stop": stopped,
            "cloud_summary": {**summary, "selected_counters": counters}, "verification_status": "unverified",
            "limitations": ["Two fixed read-only APIs in the commercial AWS partition; no other providers, resource inventory or policy simulation",
                "Account matching verifies credential context, not customer ownership or authorization",
                "Selected counters are review cues, not proof of exploitability or complete cloud posture coverage"]}
    finally:
        journal.close()
