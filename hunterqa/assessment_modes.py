"""Shared provenance and analysis facade over existing engines. No network launch."""
import hashlib
import json
import re
from itertools import islice

from .bounty import _approved_file
from .cloud_inventory_common import bounded_json
from .engagement import digest, utcnow
from .source_files import project_files, read_bounded

MODES = ("DEMO", "LAB", "LIVE")
VERIFICATION = ("Implemented", "Tested with Mocks", "Validated in Local Lab", "Validated Against Real Provider", "Not Yet Verified")
MODULES = {
    "web": ("Web application", "web-source-review", ["web-source-review", "scenario-run", "bounty-assess"]),
    "business": ("Business logic", "business-process-review", ["scenario-run"]),
    "network": ("Internal network", "network-evidence-review", ["service-fingerprint", "tls-service-inspect", "udp-dns-inspect"]),
    "ad": ("Active Directory", "ad-evidence-review", ["ad-directory-preflight", "ad-directory-collect", "ad-review", "access-graph-review"]),
    "cloud": ("Cloud AWS Azure GCP", "cloud-evidence-review", ["cloud-review", "azure-resource-inventory", "gcp-resource-inventory"]),
    "iam": ("Identity and access", "auth-identity-review", ["identity-review", "access-graph-review"]),
    "vulnerability": ("Vulnerabilities and configuration", "config-audit", ["campaign", "cve-check", "workflow-run"]),
    "evidence": ("Evidence correlation", "assessment-evidence-index", ["assessment-correlate", "workflow-export"]),
}


def catalog():
    return [{"id": key, "name": value[0], "analysis_engine": value[1], "modes": list(MODES),
        "review_kind": "offline analysis of supplied evidence" if key not in {"web", "vulnerability"} else "offline source analysis",
        "implementation_status": "Implemented", "verification_status": "Tested with Mocks",
        "real_provider_verified": False, "existing_commands": value[2],
        "limitations": "LIVE selects operator-intended source, not live collection or provider validation. Existing commands retain their own scope and approval gates."}
        for key, value in MODULES.items()]


def _snapshot(path):
    path = _approved_file(path)
    raw = read_bounded(path, 1048576)
    data = bounded_json(raw)
    if not isinstance(data, dict):
        raise ValueError("Expected bounded evidence object")
    if any(data.get(key) == "DEMO" for key in ("execution_source", "mode")) or data.get("synthetic") is True:
        raise ValueError("Synthetic evidence cannot be imported as LAB or LIVE")
    return data, hashlib.sha256(raw).hexdigest()


def _reject_demo_source(path):
    from pathlib import Path
    source = Path(path).expanduser().resolve(strict=True)
    for directory in (source if source.is_dir() else source.parent, *source.parents):
        marker = directory / ".hunterqa-demo.json"
        if marker.exists():
            raise ValueError("Generated demonstration sources cannot be relabeled LAB/LIVE")


def analyze(module, path, *, mode, authorized=False):
    if authorized is not True:
        raise PermissionError("Evidence review requires --authorized")
    if module not in MODULES or mode not in {"LAB", "LIVE"}:
        raise ValueError("Use a supported module and explicit LAB/LIVE source intent")
    _reject_demo_source(path)
    if module in {"web", "vulnerability"}:
        from .cli import _approved_root
        root = _approved_root(str(path))
        receipts = [{"relative_path_sha256": digest(p.relative_to(root).as_posix()), "sha256": hashlib.sha256(read_bounded(p, 262144)).hexdigest()}
            for p in islice(project_files(root), 1500) if p.is_file() and p.stat().st_size <= 262144]
        if module == "web":
            from .web_review import review_project
            result = review_project(root)
        else:
            from .engines.config_audit import audit_project
            from .engines.openapi import audit_openapi
            result = {"findings": audit_project(root) + audit_openapi(root), "engine": "config-audit"}
        return envelope(module, mode, result, receipts, origin="operator-supplied-source")
    data, source = _snapshot(path)
    if module == "business":
        from .business_rules import review
        result = review(data)
    elif module == "ad" and "entries" in data:
        from .ad_directory import analyze as directory_analyze
        result = directory_analyze(data)
    elif module == "evidence":
        from .assessment_correlation import correlate
        if set(data) != {"reports"}:
            raise ValueError("Evidence manifest must contain only reports")
        result = correlate(data["reports"], authorized=True)
    else:
        from . import ad_review, cloud_review, identity_review, network_review
        engine = {"ad": ad_review, "cloud": cloud_review, "iam": identity_review, "network": network_review}[module]
        result = engine.review_evidence(data)
    return envelope(module, mode, result, [{"sha256": source}], origin="operator-supplied-evidence")


def envelope(module, mode, result, receipts, *, origin):
    if module not in MODULES or mode not in MODES or (mode == "DEMO") != (origin == "generated-synthetic"):
        raise ValueError("Execution origin and mode disagree")
    rows = result.get("findings", [])
    if not isinstance(rows, list) or len(rows) > 1000 or not isinstance(receipts, list) or len(receipts) > 1500:
        raise ValueError("Bounded findings and receipts required")
    evidence = []
    for row in receipts:
        if not isinstance(row, dict) or not isinstance(row.get("sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", row["sha256"]):
            raise ValueError("Evidence hash required")
        evidence.append({"id": digest(row), "sha256": row["sha256"], "origin": origin, "execution_source": mode,
            "relative_path_sha256": row.get("relative_path_sha256")})
    stamp = utcnow().isoformat()
    source_fingerprint = digest(evidence)
    findings, seen = [], {}
    for row in rows:
        rule = row.get("rule_id")
        if not isinstance(rule, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", rule):
            raise ValueError("Expected existing analyzer finding rule")
        identity = digest([module, rule, row.get("file_path"), row.get("line_start"), row.get("test_case"), source_fingerprint])
        if identity in seen:
            seen[identity]["duplicate_count"] += 1
            continue
        severity = row.get("severity") if row.get("severity") in {"ERROR", "WARNING", "INFO"} else "INFO"
        item = {"id": identity, "rule_id": rule, "module": module, "execution_source": mode,
            "title": str(row.get("title", "Review candidate"))[:300], "severity": severity,
            "risk": {"ERROR": "high-review-priority", "WARNING": "medium-review-priority", "INFO": "informational"}[severity],
            "cwe": str(row.get("cwe", ""))[:32], "verification_status": "unverified",
            "confidence": {"score": None, "basis": "synthetic-fixture-analysis" if mode == "DEMO" else "supplied-evidence-not-runtime-confirmation"},
            "remediation": str(row.get("remediation") or row.get("message") or "Review the original evidence and enforce the intended security policy.")[:2000],
            "file_path": "external-evidence", "line_start": 1,
            "evidence_ids": [e["id"] for e in evidence if len(evidence) == 1 or e.get("relative_path_sha256") == digest(str(row.get("file_path", "")).replace("\\", "/"))],
            "source_set_sha256": source_fingerprint,
            "created_at": stamp, "duplicate_count": 0}
        seen[identity] = item
        findings.append(item)
    from .scenario_assessment import runtime_identity
    return {"engine": "unified-assessment-review", "schema_version": 1, "module": module, "rule_runtime_sha256": runtime_identity(),
        "execution_source": mode, "synthetic": mode == "DEMO", "generated_at": stamp,
        "implementation_status": "Implemented", "verification_status": "Tested with Mocks" if mode == "DEMO" else "Not Yet Verified",
        "collector": "synthetic-fixture-generator" if mode == "DEMO" else "not-collected-by-this-command",
        "real_provider_verified": False, "findings": findings, "evidence": evidence,
        "analysis_engine": result.get("engine", MODULES[module][1]), "analysis_sha256": digest(result),
        "evidence_links": len(result.get("links", [])), "network_requests": 0, "review_required": True,
        "limitations": ["Source labels describe execution intent; supplied evidence is not authenticated live collection",
            "Triage priority is not independently verified impact or a calibrated probability",
            "Existing collectors, scopes, reports and analyst decisions remain separate and are not overwritten"]}


def load_report(path):
    data = bounded_json(read_bounded(_approved_file(path), 1048576))
    if not isinstance(data, dict) or data.get("engine") != "unified-assessment-review" or data.get("schema_version") != 1 or data.get("module") not in MODULES or data.get("execution_source") not in MODES:
        raise ValueError("Unsupported shared assessment report")
    if data.get("synthetic") is not (data["execution_source"] == "DEMO") or data.get("real_provider_verified") is not False or data.get("verification_status") not in {"Tested with Mocks", "Not Yet Verified"}:
        raise ValueError("Unsupported provenance or verification claim")
    if not isinstance(data.get("findings"), list) or len(data["findings"]) > 1000 or not isinstance(data.get("evidence"), list) or len(data["evidence"]) > 1500:
        raise ValueError("Bounded shared report required")
    evidence_ids = set()
    for row in data["evidence"]:
        if (not isinstance(row, dict) or row.get("execution_source") != data["execution_source"]
                or any(not isinstance(row.get(k), str) or not re.fullmatch(r"[a-f0-9]{64}", row[k]) for k in ("id", "sha256"))
                or (row.get("origin") == "generated-synthetic") != data["synthetic"]):
            raise ValueError("Inconsistent evidence source")
        evidence_ids.add(row["id"])
    for row in data["findings"]:
        if not isinstance(row, dict) or row.get("execution_source") != data["execution_source"] or row.get("verification_status") != "unverified" or not isinstance(row.get("id"), str) or not re.fullmatch(r"[a-f0-9]{64}", row["id"]):
            raise ValueError("Inconsistent finding provenance")
        if (not isinstance(row.get("evidence_ids"), list) or any(not isinstance(v, str) or v not in evidence_ids for v in row["evidence_ids"])
                or row.get("source_set_sha256") != digest(data["evidence"])):
            raise ValueError("Finding evidence references differ")
    return data


def export(path, kind):
    data = load_report(path)
    if kind == "json":
        return json.dumps(data, indent=2) + "\n"
    if kind == "sarif":
        from .sarif_export import export_sarif
        return json.dumps(export_sarif(path), indent=2) + "\n"
    if kind == "html":
        from jinja2 import Environment, PackageLoader, select_autoescape
        env = Environment(loader=PackageLoader("hunterqa", "templates"), autoescape=select_autoescape(["html"]))
        return env.get_template("assessment_export.html").render(report=data)
    raise ValueError("Unsupported export format")
