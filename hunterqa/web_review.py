"""Original offline Python source review pack; never executes inspected code.

The category vocabulary references Claude-Red. These are deliberately narrow
review cues, not transplanted agent instructions or exploitation capabilities.
"""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

from .source_files import project_files, read_bounded

SOURCE = "https://github.com/SnailSploit/Claude-Red#web-application"
MAX_FILES = 500
MAX_BYTES = 128 * 1024
MAX_FINDINGS = 500

# ID, CWE, remediation, independently required review evidence.
SKILLS = (
    ("sqli", "CWE-89", "Use parameterized queries and separate SQL structure from values.", "Review database callsites and approved baseline/probe evidence."),
    ("xss", "CWE-79", "Keep contextual output escaping and sanitize approved rich HTML.", "Review output context, encoding and browser execution evidence."),
    ("ssrf", "CWE-918", "Validate destinations, resolved addresses and every redirect hop.", "Review URL provenance, egress policy and destination validation."),
    ("ssti", "CWE-1336", "Use fixed templates and pass user data as template variables.", "Review template provenance and rendering context."),
    ("xxe", "CWE-611", "Disable external entity resolution and external resource loading.", "Review parser configuration and document trust boundaries."),
    ("idor", "CWE-639", "Enforce server-side ownership and tenant checks on every object operation.", "Use dedicated-role authorization-matrix cases with known object ownership."),
    ("file-upload", "CWE-434", "Generate storage names, restrict content and isolate non-executable storage.", "Review upload authorization, size/type policy, filename and storage handling."),
    ("rce", "CWE-78", "Avoid shell interpretation; use fixed executables and validated arguments.", "Review command construction, input provenance and process privileges."),
    ("deserialization", "CWE-502", "Use data-only formats and safe loaders for untrusted data.", "Review serializer types, trust boundaries and object construction."),
    ("race-condition", "CWE-362", "Enforce atomic transitions, transactions and idempotency.", "Review shared state, transaction boundaries and sequential state-transition tests."),
    ("request-smuggling", "CWE-444", "Align proxy/backend HTTP parsing and reject ambiguous framing.", "Review edge/backend protocol configuration and isolated conformance results."),
    ("open-redirect", "CWE-601", "Allow only approved local routes or exact approved destinations.", "Review redirect provenance, normalization and destination validation."),
    ("parameter-pollution", "CWE-235", "Define and enforce one duplicate-parameter policy across components.", "Review duplicate-value handling at the proxy, framework and application."),
    ("graphql", "CWE-200", "Restrict schema exposure where appropriate and enforce resolver authorization and query budgets.", "Review schema exposure, resolver access, query depth and cost controls."),
    ("waf-bypass", "CWE-693", "Keep application validation independent of edge filtering and normalize inputs consistently.", "Review edge/application normalization and approved defensive test evidence; no evasion execution."),
    ("business-logic", "CWE-840", "Enforce workflow state, ownership, price and approval rules on the server.", "Document invariants and approved sequential tests using synthetic business records."),
)
AUTOMATED = frozenset({"sqli", "xss", "ssrf", "ssti", "xxe", "file-upload", "rce", "deserialization", "open-redirect", "graphql"})


def catalog():
    return [{"id": "offensive-" + key, "cwe": cwe,
        "implementation": "python-source-review" if key in AUTOMATED else "guided-review-only",
        "active_exploitation_available": False, "remediation": fix,
        "required_evidence": evidence} for key, cwe, fix, evidence in SKILLS]


def _name(node, aliases):
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        return _name(node.value, aliases) + "." + node.attr
    return ""


def _dynamic(node):
    # No alias/constant propagation or taint analysis is claimed.
    return node is not None and not isinstance(node, ast.Constant)


def _interpolated(node):
    return isinstance(node, (ast.JoinedStr, ast.BinOp)) or (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format")


def _cues(node, aliases):
    name = _name(node.func, aliases)
    first = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg in {"source", "url", "location", "template_name_or_list"}), None)
    keywords = {k.arg: k.value for k in node.keywords if k.arg}
    enabled = lambda key: isinstance(keywords.get(key), ast.Constant) and keywords[key].value is True
    result = []
    if name.endswith((".execute", ".executemany", ".executescript")) and _interpolated(first):
        result.append(("sqli", "Interpolated expression reaches a database-like execution call"))
    if name in {"markupsafe.Markup", "flask.Markup"} and _dynamic(first):
        result.append(("xss", "Dynamic expression is marked as trusted HTML"))
    if name in {"requests.get", "requests.post", "requests.request", "httpx.get", "httpx.post", "urllib.request.urlopen"}:
        destination = (node.args[1] if len(node.args) > 1 else keywords.get("url")) if name == "requests.request" else first
        if _dynamic(destination):
            result.append(("ssrf", "Dynamic destination reaches an outbound HTTP call"))
    if name in {"flask.render_template_string", "jinja2.Template"} and _dynamic(first):
        result.append(("ssti", "Dynamic expression is used as template source"))
    if name == "lxml.etree.XMLParser" and enabled("resolve_entities"):
        result.append(("xxe", "XML parser explicitly enables entity resolution"))
    if name.endswith(".save") and isinstance(first, ast.Attribute) and first.attr == "filename":
        result.append(("file-upload", "File-like save uses an object's original filename directly"))
    if (name in {"os.system", "os.popen"} and _dynamic(first)) or (
        name in {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call"} and enabled("shell")):
        result.append(("rce", "Review shell interpretation and command input provenance"))
    if name in {"pickle.load", "pickle.loads", "dill.load", "dill.loads", "yaml.unsafe_load"} and _dynamic(first):
        result.append(("deserialization", "Object-capable deserializer receives a dynamic expression"))
    if name == "flask.redirect" and _dynamic(first):
        result.append(("open-redirect", "Dynamic expression is used as redirect destination"))
    if name in {"strawberry.flask.views.GraphQLView", "ariadne.asgi.GraphQL", "ariadne.wsgi.GraphQL"} and enabled("introspection"):
        result.append(("graphql", "GraphQL setup explicitly enables schema introspection"))
    return result


def review_project(root: Path):
    root = Path(root).resolve(strict=True)
    findings, receipts, skipped = [], [], []
    examined = 0
    truncated = False
    for path in project_files(root):
        if path.suffix.lower() != ".py":
            continue
        if examined >= MAX_FILES:
            truncated = True
            break
        examined += 1
        relative = path.relative_to(root).as_posix()
        try:
            raw = read_bounded(path, MAX_BYTES)
        except (OSError, ValueError):
            skipped.append({"file_path": relative, "reason": "unreadable-or-size-limit"})
            continue
        receipt = {"file_path": relative, "sha256": hashlib.sha256(raw).hexdigest()}
        try:
            tree = ast.parse(raw, filename=relative)
        except (SyntaxError, ValueError, RecursionError):
            skipped.append({**receipt, "reason": "python-parse-failed"})
            continue
        receipts.append(receipt)
        aliases = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for entry in node.names:
                    aliases[entry.asname or entry.name.split(".")[0]] = entry.name if entry.asname else entry.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for entry in node.names:
                    aliases[entry.asname or entry.name] = node.module + "." + entry.name
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for key, message in _cues(node, aliases):
                if len(findings) >= MAX_FINDINGS:
                    truncated = True
                    break
                spec = next(row for row in SKILLS if row[0] == key)
                findings.append({"rule_id": "web-source." + key, "skill": "offensive-" + key,
                    "title": message, "severity": "INFO", "cwe": spec[1],
                    "file_path": relative, "line_start": node.lineno, "line_end": node.end_lineno,
                    "source_sha256": receipt["sha256"], "remediation": spec[2],
                    "message": message + ". " + spec[2] + " Input reachability and impact require independent review.",
                    "code": "",
                    "engine": "web-source-review", "verification_status": "unverified"})
    counts = {row["id"]: 0 for row in catalog()}
    for finding in findings:
        counts[finding["skill"]] += 1
    return {"engine": "web-source-review", "schema_version": 1, "category": "Web Application",
        "reference": SOURCE, "scope": "offline authorized local Python source; no code execution or network requests",
        "skills": [{**row, "candidate_count": counts[row["id"]],
            "review_status": "manual-review-required" if row["implementation"] == "guided-review-only" else "not-assessed" if not receipts else (
                "candidates-require-review" if counts[row["id"]] else "no-cue-observed-not-security-proof")}
            for row in catalog()],
        "findings": sorted(findings, key=lambda f: (f["file_path"], f["line_start"], f["skill"])),
        "source_receipts": receipts, "skipped": skipped, "truncated": truncated,
        "files_examined": examined, "files_parsed": len(receipts),
        "all_skills_automated": False, "real_world_effectiveness": "unverified",
        "limitations": ["Ten narrow Python syntax checks; six skills have guidance only",
            "No taint analysis, import resolution, reachability or sanitization proof; aliases/shadowing may cause false results",
            "Other languages, indirect calls and unselected syntax are not analyzed",
            "A sink, an enabled option or no match does not establish vulnerability or safety",
            "Comments and string contents are not executed or scanned as source expressions",
            "Source filenames and hashes are retained; source snippets, values and credentials are not exported",
            "Skipped directories, excluded files, parse failures and bounds reduce coverage; review completeness manually"]}
