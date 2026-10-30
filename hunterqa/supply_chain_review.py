"""Offline supply-chain assurance and selected npm lock/config and pip config review."""
from __future__ import annotations

import base64
import binascii
import configparser
import hashlib
import json
import math
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .bounty import _approved_file
from .source_files import read_bounded

MAX_BYTES = 1_048_576
MAX_FINDINGS = 500
ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
PROFILES = {
    "supply-chain": ("dependency_inventory_reviewed", "artifact_provenance_reviewed", "integrity_policy_reviewed", "install_scripts_reviewed", "maintainer_access_reviewed", "build_isolation_reviewed", "release_verification_reviewed"),
    "dependency-confusion": ("private_namespace_inventory_reviewed", "registry_routing_reviewed", "source_mapping_reviewed", "index_policy_reviewed", "credential_scoping_reviewed", "resolution_precedence_reviewed", "namespace_monitoring_reviewed"),
}
REFERENCES = ["https://github.com/SnailSploit/Claude-Red/tree/main/Skills/supply-chain",
    "https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/",
    "https://docs.npmjs.com/cli/v11/configuring-npm/npmrc/",
    "https://pip.pypa.io/en/stable/cli/pip_install/", "https://pip.pypa.io/en/stable/topics/configuration/"]


def catalog():
    return [{"id": "offensive-" + key, "implementation": "offline-supply-chain-assurance-review", "fields": list(fields),
        "native_input_modes": ["npm-lock-json", "npmrc-text", "pip-conf"],
        "active_exploitation_available": False,
        "required_evidence": "Private owner observations or selected saved npm/pip declarations; artifact authenticity, effective source resolution and namespace ownership remain unverified"}
        for key, fields in PROFILES.items()]


def _failure():
    raise ValueError("Unsupported supply-chain evidence shape, selected field or bounds; contents withheld") from None


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
        raise ValueError("Invalid supply-chain evidence JSON; contents withheld") from None
    stack, count = [(data, 0)], 0
    while stack:
        value, depth = stack.pop()
        count += 1
        if count > 20000 or depth > 40 or (isinstance(value, float) and not math.isfinite(value)):
            _failure()
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
    return data


def _report():
    return {"engine": "supply-chain-evidence-review", "schema_version": 1, "category": "Supply Chain",
        "reviewed_at": datetime.now(timezone.utc).isoformat(), "records": [], "findings": [],
        "network_requests": 0, "external_tools_executed": 0, "referenced_files_opened": 0,
        "artifact_authenticity_verified": False, "effective_resolution_verified": False, "namespace_ownership_verified": False,
        "all_skills_automated": False, "real_world_effectiveness": "unverified", "truncated": False, "candidates_not_retained": 0,
        "references": REFERENCES, "limitations": [
            "Selected npm lock v2/v3 JSON, literal npmrc assignments and pip INI declarations only; no complete package-manager emulation",
            "No package installation, script execution, registry/DNS access, namespace registration, package publishing or callbacks",
            "No artifact download/digest comparison, signature/provenance verification, dependency resolution or CVE/malware verdict",
            "CLI/environment/user/global config precedence, npm aliases/workspaces and registry ownership remain unresolved; missing settings stay unknown",
            "Hash syntax, script flags and multiple sources are review context, not proof of trust, exploitability or dependency confusion",
            "Package names, scopes, paths, URLs, hosts, tokens, credentials, scripts and digest values are withheld; receipts do not prove provenance or owner consent"]}



def _record(report, case, skill, context, **fields):
    if len(report["records"]) >= 2000:
        _failure()
    row = {"case": case, "skill": skill, "context": context, "status": "selected-declaration-only", **fields}
    report["records"].append(row)
    return row


def _add(report, case, skill, key, title, fix):
    if len(report["findings"]) >= MAX_FINDINGS:
        report["truncated"] = True
        report["candidates_not_retained"] += 1
        return
    report["findings"].append({"rule_id": "supply-chain-review." + key.replace("_", "-"), "skill": skill,
        "test_case": case, "title": title, "severity": "INFO", "cwe": "CWE-693",
        "message": title + ". " + fix, "remediation": fix, "code": "", "file_path": "external-evidence",
        "line_start": 1, "line_end": 1, "engine": "supply-chain-evidence-review", "verification_status": "unverified"})


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
                _add(report, row["id"], skill, key + "." + field, "Owner evidence declares incomplete supply-chain assurance: " + field.replace("_", " "),
                    "Review applicable artifact provenance, package-source trust and independent evidence; this declaration does not demonstrate a vulnerability.")
        unknown = [f for f, v in obs.items() if v is None]
        _record(report, row["id"], skill, "owner-evidence", unknown_fields=unknown,
            status="insufficient-evidence" if len(unknown) == len(obs) else "partial-declared-evidence")
    return _finish(report)

MODES = ("normalized", "npm-lock-json", "npmrc-text", "pip-conf")


def _text(value, maximum=4096):
    if value is not None and (not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 for c in value)):
        _failure()
    return value


def _url(value):
    if not value:
        return "unknown", False
    if any(v in value for v in ("${", "%(")):
        return "unresolved", False
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() in ("http", "https") and not parsed.hostname:
            _failure()
        return parsed.scheme.lower() if parsed.scheme.lower() in ("http", "https") else "other", parsed.username is not None or parsed.password is not None
    except ValueError:
        raise ValueError("Unsupported package-source declaration; contents withheld") from None


def _url_cues(report, case, value):
    scheme, userinfo = _url(value)
    if scheme == "http":
        _add(report, case, "offensive-supply-chain", "plain-http-source", "Selected package source declares plain HTTP transport",
            "Review the intended trusted source and migrate to authenticated HTTPS with appropriate trust roots; source authenticity is not verified.")
    if userinfo:
        _add(report, case, "offensive-dependency-confusion", "url-user-information", "Selected source URL embeds user information",
            "Review credential handling and source scoping through approved secret management; no credential value is exported or validated.")
    return scheme


def _integrity(value):
    if not value:
        return "missing"
    tokens = value.split()
    if len(tokens) > 8:
        return "unrecognized-shape"
    strong, legacy = False, False
    for token in tokens:
        algorithm, separator, digest = token.partition("-")
        sizes = {"sha1":20, "sha256":32, "sha384":48, "sha512":64}
        if not separator or algorithm not in sizes or len(digest) > 128:
            return "unrecognized-shape"
        try:
            decoded = base64.b64decode(digest, validate=True)
        except (binascii.Error, ValueError):
            return "unrecognized-shape"
        if len(decoded) != sizes[algorithm]:
            return "unrecognized-shape"
        strong = strong or algorithm != "sha1"
        legacy = legacy or algorithm == "sha1"
    return "recognized-strong-shape" if strong else ("recognized-legacy-shape" if legacy else "unrecognized-shape")


def _npm_lock(data, receipt):
    if not isinstance(data, dict) or type(data.get("lockfileVersion")) is not int or data["lockfileVersion"] not in (2, 3) or not isinstance(data.get("packages"), dict) or len(data["packages"]) > 1500:
        _failure()
    report, root_rows, links = _report(), 0, 0
    for index, (location, package) in enumerate(data["packages"].items(), 1):
        if not isinstance(package, dict):
            _failure()
        if not location:
            root_rows += 1
            continue
        if len(location) > 4096:
            _failure()
        flags = {name:package.get(name) for name in ("link", "hasInstallScript")}
        if any(v is not None and type(v) is not bool for v in flags.values()):
            _failure()
        resolved = _text(package.get("resolved"))
        integrity = _text(package.get("integrity"), 1024)
        case = "sc-" + receipt[:12] + "-npm-" + str(index)
        source = _url_cues(report, case, resolved)
        state = _integrity(integrity)
        link = flags["link"] is True
        links += link
        _record(report, case, "offensive-supply-chain", "npm-lock-json", source_class=source,
            integrity_declaration=state, link_declaration=flags["link"], install_script_declaration=flags["hasInstallScript"],
            artifact_digest_compared=False)
        if source in ("http", "https") and not link and state != "recognized-strong-shape":
            _add(report, case, "offensive-supply-chain", "archive-integrity-review", "HTTP(S) artifact lacks a recognized selected strong digest declaration",
                "Review the saved metadata and approved package-manager integrity policy. Digest syntax alone does not verify downloaded bytes, signatures, publisher identity or authenticity.")
        if flags["hasInstallScript"] is True:
            _add(report, case, "offensive-supply-chain", "install-script-declaration", "Package metadata declares an install script",
                "Review the actual dependency and approved install-script/build-isolation policy independently; scripts are not read or executed and can be legitimate.")
    report["source_review"] = {"root_metadata_entries_not_reviewed": root_rows, "link_entries": links,
        "complete_lock_schema_validation": False, "dependency_graph_resolved": False}
    return _finish(report)


def _lines(raw):
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError:
        raise ValueError("Invalid saved package configuration text; contents withheld") from None
    lines = text.splitlines()
    if len(lines) > 1000 or any(len(line) > 4096 or any(ord(c) < 32 and c != "\t" for c in line) for line in lines):
        _failure()
    return text, lines


def _boolean(value):
    if value.lower() not in ("true", "false"):
        _failure()
    return value.lower() == "true"


def _npmrc(raw, receipt):
    _, lines = _lines(raw)
    report, seen, unsupported = _report(), set(), 0
    for index, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        key, separator, value = line.partition("=")
        key, value = key.strip().lower(), value.strip()
        registry = key == "registry" or re.fullmatch(r"@[a-z0-9_.-]+:registry", key) is not None
        if not separator or not registry and key not in ("strict-ssl", "ignore-scripts", "package-lock"):
            unsupported += 1
            continue
        if key in seen:
            _failure()
        seen.add(key)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        case = "sc-" + receipt[:12] + "-npmrc-" + str(index)
        label = "scoped-registry" if key.startswith("@") else key
        if registry:
            source = _url_cues(report, case, _text(value))
            _record(report, case, "offensive-dependency-confusion", "npmrc-text", setting=label, source_class=source,
                effective_routing_verified=False)
        else:
            flag = _boolean(value) if "${" not in value else None
            _record(report, case, "offensive-supply-chain", "npmrc-text", setting=label, enabled_declaration=flag)
            if flag is False:
                _add(report, case, "offensive-supply-chain", "npmrc-" + key, "Selected npm configuration explicitly disables " + key,
                    "Review intended behavior and higher-priority configuration. These declarations do not establish installation behavior, package trust or malicious scripts.")
    report["source_review"] = {"unsupported_assignments_not_reviewed": unsupported, "complete_npmrc_parsing": False,
        "config_precedence_or_environment_resolved": False}
    return _finish(report)


def _pip(raw, receipt):
    text, _ = _lines(raw)
    parser = configparser.ConfigParser(interpolation=None, strict=True, empty_lines_in_values=False)
    try:
        parser.read_string(text)
    except configparser.Error:
        raise ValueError("Invalid saved pip configuration; contents withheld") from None
    if parser.defaults():
        _failure()
    report, unsupported, index = _report(), 0, 0
    selected = {"index-url", "extra-index-url", "trusted-host", "require-hashes", "no-index"}
    for section in parser.sections():
        for key, value in parser.items(section, raw=True):
            if section not in ("global", "install", "download", "wheel") or key not in selected:
                unsupported += 1
                continue
            index += 1
            case = "sc-" + receipt[:12] + "-pip-" + str(index)
            count = 0
            declared = None
            if key in ("no-index", "require-hashes"):
                if value.lower() not in configparser.ConfigParser.BOOLEAN_STATES:
                    _failure()
                declared = configparser.ConfigParser.BOOLEAN_STATES[value.lower()]
            elif key in ("index-url", "extra-index-url"):
                urls = value.split()
                if len(urls) > 20 or key == "index-url" and len(urls) > 1:
                    _failure()
                for n, url in enumerate(urls, 1):
                    _url_cues(report, case + "-url-" + str(n), _text(url))
                count = len(urls)
            _record(report, case, "offensive-dependency-confusion", "pip-conf", setting=key, section=section,
                enabled_declaration=declared, source_count=count, effective_resolution_verified=False)
            cues = [(key == "extra-index-url" and count > 0, "pip-extra-index", "Selected pip configuration declares an additional package index"),
                (key == "trusted-host" and bool(value.strip()), "pip-trusted-host", "Selected pip configuration declares trusted-host exceptions"),
                (key == "require-hashes" and declared is False, "pip-hashes-disabled", "Selected pip configuration explicitly disables require-hashes")]
            for condition, rule, title in cues:
                if condition:
                    _add(report, case, "offensive-dependency-confusion", rule, title,
                        "Review private-package source isolation, secure transport and integrity policy with actual CLI/environment/config precedence. Additional indexes do not create a private-first trust boundary; exposure and selected artifacts remain unverified.")
    report["source_review"] = {"unsupported_settings_not_reviewed": unsupported, "complete_pip_configuration_validation": False,
        "config_precedence_or_environment_resolved": False}
    return _finish(report)


def review_file(path, *, authorized=False, mode="normalized"):
    if not authorized:
        raise PermissionError("Supply-chain evidence review requires explicit authorization")
    if mode not in MODES:
        _failure()
    raw = read_bounded(_approved_file(path), MAX_BYTES)
    receipt = hashlib.sha256(raw).hexdigest()
    readers = {"normalized":lambda: review_evidence(_decode(raw)), "npm-lock-json":lambda: _npm_lock(_decode(raw), receipt),
        "npmrc-text":lambda: _npmrc(raw, receipt), "pip-conf":lambda: _pip(raw, receipt)}
    report = readers[mode]()
    report.update(input_sha256=receipt, input_mode=mode)
    return report
