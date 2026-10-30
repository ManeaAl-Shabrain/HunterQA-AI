"""Offline cryptography assurance and selected non-executing Python AST checks."""
from __future__ import annotations

import ast
import hashlib
import json
import math
import re
import warnings
from datetime import datetime, timezone

from .bounty import _approved_file
from .source_files import read_bounded

MAX_BYTES = 1_048_576
MAX_FINDINGS = 500
ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
PROFILES = {
    "crypto-attacks": ("algorithm_usage_reviewed", "authenticated_encryption_reviewed", "key_lifecycle_reviewed", "nonce_uniqueness_reviewed", "secure_randomness_reviewed", "password_kdf_reviewed", "side_channels_reviewed"),
    "tls-attacks": ("protocol_policy_reviewed", "cipher_policy_reviewed", "certificate_chain_reviewed", "hostname_validation_reviewed", "patch_status_reviewed", "replay_policy_reviewed", "mtls_identity_reviewed"),
}
REFERENCES = ["https://github.com/SnailSploit/Claude-Red/tree/main/Skills/crypto",
    "https://docs.python.org/3/library/hashlib.html", "https://docs.python.org/3/library/ssl.html",
    "https://docs.python.org/3/library/random.html", "https://www.rfc-editor.org/rfc/rfc8996.html"]


def catalog():
    return [{"id": "offensive-" + key, "implementation": "offline-crypto-assurance-review", "fields": list(fields),
        "native_source_modes": ["python-source"],
        "active_exploitation_available": False,
        "required_evidence": "Private owner observations or selected Python source; actual cryptographic use, runtime TLS and exploitability remain unverified"}
        for key, fields in PROFILES.items()]


def _failure():
    raise ValueError("Unsupported crypto evidence shape, selected field or bounds; contents withheld") from None


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
        raise ValueError("Invalid crypto evidence JSON; contents withheld") from None
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
    return {"engine": "crypto-evidence-review", "schema_version": 1, "category": "Cryptography",
        "reviewed_at": datetime.now(timezone.utc).isoformat(), "records": [], "findings": [],
        "network_requests": 0, "external_tools_executed": 0, "referenced_files_opened": 0,
        "cryptographic_correctness_verified": False, "runtime_tls_verified": False,
        "all_skills_automated": False, "real_world_effectiveness": "unverified", "truncated": False, "candidates_not_retained": 0,
        "references": REFERENCES, "limitations": [
            "Selected local Python AST patterns and owner observations only; no code execution, imports, decryption, cracking or network traffic",
            "No dataflow, reachability, constant propagation, local dependency resolution or complete alias/type analysis",
            "Only unambiguously imported top-level names are considered; shadowed or dynamically imported names are skipped",
            "No certificate parsing, TLS handshake/cipher enumeration, key-strength measurement or protocol/CVE exploitation",
            "Weak hashes and general-purpose random calls can be intentional non-security uses; every cue requires independent context review",
            "Source paths, names, literals, keys, ciphertext and private values are withheld; receipts do not establish provenance or consent"]}



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
    report["findings"].append({"rule_id": "crypto-review." + key.replace("_", "-"), "skill": skill,
        "test_case": case, "title": title, "severity": "INFO", "cwe": "CWE-693",
        "message": title + ". " + fix, "remediation": fix, "code": "", "file_path": "external-evidence",
        "line_start": 1, "line_end": 1, "engine": "crypto-evidence-review", "verification_status": "unverified"})


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
                _add(report, row["id"], skill, key + "." + field, "Owner evidence declares incomplete crypto assurance: " + field.replace("_", " "),
                    "Review applicable cryptographic design, runtime configuration and independent evidence; this declaration does not demonstrate a vulnerability.")
        unknown = [f for f, v in obs.items() if v is None]
        _record(report, row["id"], skill, "owner-evidence", unknown_fields=unknown,
            status="insufficient-evidence" if len(unknown) == len(obs) else "partial-declared-evidence")
    return _finish(report)




LEGACY_PROTOCOLS = {"ssl.PROTOCOL_SSLv2", "ssl.PROTOCOL_SSLv3", "ssl.PROTOCOL_TLSv1", "ssl.PROTOCOL_TLSv1_1"}
REQUESTS = {"requests." + k for k in ("request", "get", "post", "put", "patch", "delete", "head", "options")}
HTTPX = {"httpx." + k for k in ("Client", "AsyncClient", "request", "get", "post", "put", "patch", "delete", "head", "options", "stream")}
RANDOM = {"random." + k for k in ("random", "randint", "randrange", "getrandbits", "randbytes", "choice", "choices", "sample", "uniform")}


def _source(raw, receipt):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(raw)
    except (SyntaxError, ValueError, UnicodeError, RecursionError, MemoryError):
        raise ValueError("Invalid or excessive Python source; contents withheld") from None
    count, stack = 0, [(tree, 0)]
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > 50000 or depth > 100:
            _failure()
        stack.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    bindings, invalid = {}, set()
    top_imports = {id(n) for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                local = alias.asname or (alias.name.split(".")[0] if isinstance(node, ast.Import) else alias.name)
                if alias.name == "*":
                    # Star imports can replace any otherwise recognized name.
                    invalid.add("*")
                    continue
                target = (alias.name if alias.asname else alias.name.split(".")[0]) if isinstance(node, ast.Import) else (node.module or "") + "." + alias.name
                if id(node) not in top_imports or getattr(node, "level", 0) or local in bindings:
                    invalid.add(local)
                else:
                    bindings[local] = target
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            invalid.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            invalid.add(node.name)
        elif isinstance(node, ast.arg):
            invalid.add(node.arg)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            invalid.add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            invalid.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            invalid.add(node.rest)
    if "*" in invalid:
        bindings.clear()
    else:
        bindings = {k:v for k,v in bindings.items() if k not in invalid}

    def resolve(node):
        if isinstance(node, ast.Name):
            return bindings.get(node.id, "")
        if isinstance(node, ast.Attribute):
            parent = resolve(node.value)
            return parent + "." + node.attr if parent else ""
        return ""

    report, calls = _report(), 0
    case = "crypto-" + receipt[:12]
    _record(report, case, "offensive-crypto-attacks", "python-source", status="partial-static-review",
        ast_nodes=count, imported_names_not_resolved=len(invalid), runtime_usage_verified=False)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        calls += 1
        target = resolve(node.func)
        cues = []
        if target in ("hashlib.md5", "hashlib.sha1") or target == "hashlib.new" and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str) and node.args[0].value.lower().replace("-", "") in ("md5", "sha1"):
            cues.append(("crypto-attacks", "weak-hash", "Selected weak hash construction appears in source",
                "Determine whether collision resistance or authentication is required; use a reviewed modern construction for security use. Non-security hashing may be intentional."))
        if target in RANDOM:
            cues.append(("crypto-attacks", "general-random", "General-purpose random generator call appears in source",
                "Check whether output protects tokens, keys or other secrets; use a cryptographic random source for security-sensitive output. Simulation and sampling can be legitimate."))
        if target in ("Crypto.Cipher.AES.new", "Cryptodome.Cipher.AES.new"):
            mode = node.args[1] if len(node.args) > 1 else next((k.value for k in node.keywords if k.arg == "mode"), None)
            if resolve(mode) in ("Crypto.Cipher.AES.MODE_ECB", "Cryptodome.Cipher.AES.MODE_ECB"):
                cues.append(("crypto-attacks", "ecb-mode", "Selected AES ECB mode declaration appears in source",
                    "Review the threat model and prefer a vetted authenticated-encryption design with correct nonce and key management; no plaintext recovery is attempted."))
        if target == "ssl._create_unverified_context":
            cues.append(("tls-attacks", "unverified-context", "Unverified TLS context construction appears in source",
                "Use a reviewed client context with certificate-chain and hostname validation; independently verify runtime use and intended endpoint identity."))
        if target in REQUESTS | HTTPX and any(k.arg == "verify" and isinstance(k.value, ast.Constant) and k.value.value is False for k in node.keywords):
            cues.append(("tls-attacks", "verify-disabled", "Selected HTTP client explicitly disables TLS verification",
                "Restore certificate validation with the intended trust roots and review endpoint identity; request reachability and actual runtime behavior remain unknown."))
        if target == "ssl.SSLContext":
            protocol = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg == "protocol"), None)
            if resolve(protocol) in LEGACY_PROTOCOLS:
                cues.append(("tls-attacks", "legacy-protocol", "Selected legacy-only SSL/TLS context declaration appears in source",
                    "Review protocol compatibility and migrate to a maintained modern TLS policy; source presence does not demonstrate successful negotiation."))
        for skill, key, title, fix in cues:
            c = case + "-line-" + str(node.lineno) + "-call-" + str(calls)
            _add(report, c, "offensive-" + skill, key, title, fix)
    report["source_review"] = {"calls_inspected": calls, "complete_source_analysis": False,
        "dataflow_analyzed": False, "source_line_locations_exported": False}
    return _finish(report)


def review_file(path, *, authorized=False, mode="normalized"):
    if not authorized:
        raise PermissionError("Cryptography evidence review requires explicit authorization")
    if mode not in ("normalized", "python-source"):
        _failure()
    raw = read_bounded(_approved_file(path), MAX_BYTES)
    receipt = hashlib.sha256(raw).hexdigest()
    report = review_evidence(_decode(raw)) if mode == "normalized" else _source(raw, receipt)
    report.update(input_sha256=receipt, input_mode=mode)
    return report
