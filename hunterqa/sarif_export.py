"""Conservative SARIF 2.1.0 export; does not upload or read source code."""
from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath, PureWindowsPath
from urllib.parse import quote

from .bounty import _read_json
from .source_files import positive_line

RULE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}\Z")


def _relative_uri(value):
    if not isinstance(value, str) or not value or len(value) > 1000:
        return None
    if PureWindowsPath(value).drive or any(ord(c) < 32 or ord(c) == 127 or c in ":?#" for c in value):
        return None
    value = value.replace("\\", "/")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value or value in (".", "external-evidence"):
        return None
    return quote(value, safe="/-._~")


def export_sarif(file_path):
    data = _read_json(file_path, 2_000_000)
    rows = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(rows, list) or len(rows) > 1000:
        raise ValueError("Expected a bounded normalized HunterQA findings array")
    rules, results = {}, []
    omitted = 0
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("rule_id"), str) or not RULE.fullmatch(row["rule_id"]):
            raise ValueError("Invalid normalized finding rule ID")
        rule_id = row["rule_id"]
        if rule_id not in rules:
            rules[rule_id] = {"id": rule_id, "shortDescription": {"text": "Unverified security review candidate"}}
        # Do not export source excerpts, arbitrary scanner messages, AI prose or fixes.
        severity = row.get("severity") if isinstance(row.get("severity"), str) else "INFO"
        result = {"ruleId": rule_id, "level": {"ERROR": "error", "WARNING": "warning", "INFO": "note"}.get(severity, "note"),
                  "message": {"text": "Unverified review candidate. Inspect the private HunterQA evidence and independently validate impact."},
                  "properties": {"verificationStatus": "unverified", "humanReviewRequired": True}}
        uri = _relative_uri(row.get("file_path"))
        if uri:
            line = positive_line(row.get("line_start"))
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": uri},
                "region": {"startLine": line, "endLine": max(line, positive_line(row.get("line_end"), line))}}}]
        else:
            omitted += 1
        identity = f"{rule_id}\0{uri or ''}\0{row.get('target_ref_hash', '')}\0{positive_line(row.get('line_start'))}"
        result["partialFingerprints"] = {"hunterqaCandidate/v1": hashlib.sha256(identity.encode()).hexdigest()}
        results.append(result)
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "HunterQA AI", "informationUri": "https://github.com/ManeaAl-Shabrain/HunterQA-AI",
                                          "rules": list(rules.values())}}, "results": results,
                      "properties": {"humanReviewRequired": True, "omittedUnsafeOrExternalLocations": omitted,
                                     "claims": "Scanner levels are triage labels; impact and exploitability are unverified."}}]}
