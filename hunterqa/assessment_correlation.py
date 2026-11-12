"""Join saved evidence digests without promoting claims to vulnerabilities."""
import hashlib
import re

from .bounty import _approved_file
from .cloud_inventory_common import bounded_json
from .scenario_reports import summary
from .source_files import read_bounded


def correlate(inputs, *, authorized=False):
    if authorized is not True:
        raise PermissionError("Evidence correlation requires --authorized")
    if not isinstance(inputs, list) or not 2 <= len(inputs) <= 10:
        raise ValueError("Supply 2..10 saved report files")
    sources, evidence, seen = [], {}, set()
    for path in inputs:
        path = _approved_file(path)
        raw = read_bounded(path, 1048576)
        source = hashlib.sha256(raw).hexdigest()
        if source in seen or summary(path)["status"] != "ready":
            raise ValueError("Use unique supported saved reports")
        seen.add(source)
        report = bounded_json(raw)
        context = report.get("execution_source", "UNCLASSIFIED")
        if context not in {"DEMO", "LAB", "LIVE"}:
            context = "UNCLASSIFIED"
        sources.append({"report_sha256": source, "engine": report["engine"], "execution_source": context})
        witnesses = {source}
        if report["engine"] == "approved-scenario-suite":
            for case in report["cases"]:
                for row in case.get("receipts", []):
                    if isinstance(row, dict) and isinstance(row.get("body_sha256"), str) and re.fullmatch(r"[a-f0-9]{64}", row["body_sha256"]):
                        witnesses.add(row["body_sha256"])
        elif report["engine"] == "unified-assessment-review":
            # load_report, via summary above, checks per-finding/source integrity.
            for row in report["evidence"]:
                witnesses.add(row["sha256"])
        elif report["engine"] == "normalized-access-graph":
            for row in report["queries"]:
                values = row.get("evidence_sha256", [])
                if not isinstance(values, list) or len(values) > 20:
                    raise ValueError("Bounded evidence references required")
                for value in values:
                    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
                        raise ValueError("Invalid evidence reference")
                    witnesses.add(value)
        for witness in witnesses:
            evidence.setdefault(witness, set()).add(source)
    links = [{"evidence_sha256": key, "report_sha256": sorted(values), "meaning": "matching-digest-only"}
        for key, values in sorted(evidence.items()) if len(values) > 1]
    return {"engine": "assessment-evidence-index", "schema_version": 1, "sources": sources, "links": links[:200],
        "mixed_execution_sources": len({row["execution_source"] for row in sources}) > 1,
        "truncated": len(links) > 200, "network_requests": 0, "customer_vulnerabilities_confirmed": 0,
        "limitations": ["A matching hash links saved bytes/claims, not author identity, permission, exploitability or independent confirmation"]}
