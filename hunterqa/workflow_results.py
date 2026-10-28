"""Evidence-linked triage, conservative retest comparison and escaped reports."""
from __future__ import annotations

import hashlib
import html
import json
import os
from collections import Counter
from pathlib import Path

from .bounty import _approved_file, _read_json
from .engagement import _policy_snapshot, digest, utcnow
from .source_files import read_bounded, positive_line
from .workflow_protocol import CATALOG, STAGES
from .workflow_store import Store, run_lock
from .workflow_network import inspect_network

REMEDIATIONS = {
    "CWE-250": "Apply least privilege; review container identity, privileges and required capabilities.",
    "CWE-1104": "Pin a reviewed dependency or image version/digest and establish an update process.",
    "CWE-284": "Review intended access boundaries and restrict access to approved principals.",
    "CWE-306": "Verify runtime authentication and authorization; document required OpenAPI security controls.",
}
OBSERVATION_REMEDIATIONS = {
    "header.hsts.absent": "Review HTTPS-only host policy; enable HSTS after verifying HTTPS coverage and subdomain requirements.",
    "header.nosniff.absent": "Serve correct content types and review adding X-Content-Type-Options: nosniff.",
    "header.csp.absent": "Review a restrictive Content Security Policy against required application scripts and resources; test before enforcing.",
    "cookie.secure.absent": "Review setting Secure on cookies that should only travel over HTTPS.",
    "cookie.httponly.absent": "Review setting HttpOnly on sensitive cookies that application JavaScript does not need to read.",
}


def summarize_run(run, *, store=None):
    owned = store is None
    store = store or Store(run, readonly=True)
    try:
        if owned:
            store.db.execute("BEGIN")  # One consistent snapshot while coordinator writes.
        count, chain = store.verify()
        store.check_results()
        execution = store.meta("execution")
        if digest(execution["review"]) != execution["execution_sha256"]:
            raise ValueError("Execution review fingerprint mismatch")
        steps, candidates, assets, observations, discoveries = [], {}, [], [], []
        review_rows = {row["finding"]: json.loads(row["value"])
                       for row in store.db.execute("SELECT * FROM reviews LIMIT 1001")}
        # Bind review state to its append-only event record as well.
        review_events, recorded_status, charged, network_evidence = {}, None, 0, []
        stored_protocol = _read_json(store.run / "protocol.json", 65_536)
        if digest(stored_protocol) != execution["review"]["protocol_sha256"]:
            raise ValueError("Stored protocol fingerprint mismatch")
        targets_by_step = {step["id"]: step["targets"] for step in stored_protocol["steps"]}
        declarations = {step["id"]: step for step in stored_protocol["steps"]}
        for row in store.db.execute("SELECT value FROM events ORDER BY seq LIMIT 2001"):
            event = json.loads(row[0])
            if event["kind"] == "run-start" and event["details"]["execution_sha256"] != execution["execution_sha256"]:
                raise ValueError("Execution metadata does not match audit record")
            if event["kind"] == "run-start":
                recorded_status = "running"
                if event["details"]["operator"] != store.meta("operator"):
                    raise ValueError("Operator metadata does not match audit record")
            elif event["kind"] == "run-finished":
                recorded_status = event["details"]["status"]
            elif event["kind"] == "run-interrupted":
                recorded_status = "interrupted"
            elif event["kind"] == "run-abandoned":
                recorded_status = "abandoned"
            elif event["kind"] == "quota-reserved":
                charged += event["details"]["requests"]
                if charged != event["details"]["total"]:
                    raise ValueError("Quota event sequence mismatch")
            elif event["kind"] == "network-evidence":
                details = event["details"]
                declaration = declarations[details["step"]]
                kwargs = {}
                if declaration["tool"] == "web-discovery":
                    policy, snapshot_hash = _policy_snapshot(store.run / "profile.json")
                    if snapshot_hash != execution["review"]["policy_sha256"]:
                        raise ValueError("Stored discovery profile fingerprint mismatch")
                    kwargs = {"discovery_policy": policy, "request_budget": declaration["requests"]}
                journal = inspect_network(store.run / f"{details['step']}.network.jsonl", targets_by_step[details["step"]], **kwargs)
                if any(journal[key] != details[key] for key in ("sha256", "intents", "responses", "incomplete_tail")):
                    raise ValueError("Network journal does not match audit record")
                network_evidence.append({"step": details["step"], **journal})
            if event["kind"] == "finding-review":
                review_events[event["details"]["finding"]] = event["details"]["review_sha256"]
        if recorded_status != store.meta("status") or charged != store.meta("charged_requests"):
            raise ValueError("Run status/quota does not match audit record")
        if {key: digest(value) for key, value in review_rows.items()} != review_events:
            raise ValueError("Workflow review does not match audit record")
        for step in store.steps():
            result = json.loads(step["result"]) if step["result"] else {}
            fingerprint = digest(result) if step["result"] else None
            steps.append({"id": step["id"], "tool": step["tool"], "state": step["state"],
                          "error_type": step["error"], "evidence_sha256": fingerprint})
            assets.extend(result.get("assets", []))
            assets.extend(result.get("services", []))
            observations.extend(result.get("observations", []))
            if step["tool"] == "web-discovery" and result:
                discoveries.append({"step": step["id"], "summary": result["discovery"],
                                    "endpoints": result["discovered_endpoints"], "forms": result["forms"],
                                    "limitations": result["limitations"]})
            project = execution["review"]["bindings"][step["id"]].get("project")
            project_hash = digest(project) if project else ""
            for row in result.get("findings", []):
                identity = {"rule": row["rule_id"], "path": row.get("file_path", ""),
                            "line": positive_line(row.get("line_start")),
                            "target": row.get("target_ref_hash", ""), "project": project_hash}
                key = digest(identity)
                evidence = {"step": step["id"], "result_sha256": fingerprint}
                if key in candidates:
                    candidates[key]["evidence"].append(evidence)
                    continue
                cwe = row.get("cwe", "CWE-Unknown")
                review = review_rows.get(key)
                candidates[key] = {"id": key, "rule_id": row["rule_id"],
                    "title": str(row.get("title", "Security review candidate"))[:300],
                    "severity": row.get("severity", "INFO"),
                    "source_severity": row.get("source_severity", row.get("severity", "INFO")),
                    "cwe": cwe, "file_path": row.get("file_path", "external-evidence"),
                    "line_start": identity["line"], "target_ref_hash": identity["target"],
                    "project_ref_hash": project_hash,
                    "verification_status": review["decision"] if review else "unverified",
                    "confidence_basis": "analyst-attestation" if review else "scanner-assertion",
                    "remediation": OBSERVATION_REMEDIATIONS.get(row["rule_id"], REMEDIATIONS.get(cwe, "Independently reproduce the reported condition, assess impact, and review the relevant security control.")),
                    "review": review, "evidence": [evidence]}
                if len(candidates) > 1000:
                    raise ValueError("Workflow candidate limit exceeded")
        findings = list(candidates.values())
        coverage = [{"stage": stage,
                     "selected": sum(CATALOG[s["tool"]][0] == stage for s in steps),
                     "completed": sum(CATALOG[s["tool"]][0] == stage and s["state"] == "succeeded" for s in steps)}
                    for stage in STAGES]
        protocol = _read_json(store.run / "protocol.json", 65_536)
        if digest(protocol) != execution["review"]["protocol_sha256"]:
            raise ValueError("Stored protocol fingerprint mismatch")
        scope = {"policy": execution["review"]["policy_sha256"], "targets": sorted(protocol["targets"]),
                 "projects": sorted(binding["project"] for binding in execution["review"]["bindings"].values()
                                    if "project" in binding)}
        assessment = [{"id": step["id"], "tool": step["tool"], "targets": sorted(step["targets"]),
                       "request_reservation": step["requests"],
                       "discovery_depth": execution["review"]["bindings"][step["id"]].get("max_depth"),
                       "depends_on": sorted(step["depends_on"]),
                       "project": execution["review"]["bindings"][step["id"]].get("project"),
                       "import_format": execution["review"]["bindings"][step["id"]].get("tool")}
                      for step in sorted(protocol["steps"], key=lambda value: value["id"])]
        return {"engine": "hunterqa_workflow_run", "schema_version": 1,
                "run_id": store.meta("run_id"), "status": store.meta("status"),
                "operator": store.meta("operator"),
                "created_at": store.meta("created_at"), "generated_at": utcnow().isoformat(),
                "execution_sha256": execution["execution_sha256"],
                "runtime_sha256": execution["review"]["runtime_sha256"],
                "policy_sha256": execution["review"]["policy_sha256"], "scope_sha256": digest(scope),
                "assessment_sha256": digest(assessment),
                "limits": execution["preflight"]["limits"],
                "charged_requests": store.meta("charged_requests"), "steps": steps,
                "assets": assets[:1000], "observations": observations[:1000],
                "network_evidence": network_evidence,
                "web_discovery": discoveries,
                "findings": findings, "severity_counts": dict(Counter(row["severity"] for row in findings)),
                "review_counts": dict(Counter(row["verification_status"] for row in findings)),
                "coverage": coverage, "audit_events": count, "audit_head_sha256": chain,
                "adapter_coverage": dict(Counter(row["tool"] for row in steps)),
                "next_actions": [{"finding": row["id"], "evidence": row["evidence"],
                                  "action": row["remediation"]} for row in findings
                                 if row["verification_status"] in ("unverified", "needs-review")],
                "limitations": ["Local operator authorization and analyst attestations are not independently verified",
                                "Process isolation is not an operating-system sandbox",
                                "Severity is a source label; status observations do not prove exploitability",
                                "Coverage describes selected adapters, not full ASVS/WSTG compliance",
                                "Audit hashes detect inconsistency, not forgery by a run-directory owner",
                                "Interrupted runs are never automatically replayed"]}
    finally:
        if owned:
            store.close()


def review_finding(run, finding, decision, reviewer, note, evidence, *, authorized=False):
    if not authorized:
        raise PermissionError("Review requires --authorized")
    if decision not in ("confirmed", "false-positive", "needs-review"):
        raise ValueError("Unsupported analyst decision")
    for value, maximum in ((reviewer, 200), (note, 1000)):
        if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(ord(c) < 32 for c in value):
            raise ValueError("Reviewer and note must be bounded single-line text")
    raw = read_bounded(_approved_file(evidence), 2_000_000)
    with run_lock(run):
        summary = summarize_run(run)
        if summary["status"] == "running":
            raise ValueError("Cannot review an active run")
        if finding not in {row["id"] for row in summary["findings"]}:
            raise ValueError("Unknown finding ID")
        value = {"decision": decision, "reviewer": reviewer, "note": note,
                 "evidence_sha256": hashlib.sha256(raw).hexdigest(),
                 "evidence_bytes": len(raw), "time": utcnow().isoformat(),
                 "kind": "local-analyst-attestation"}
        store = Store(run)
        try:
            with store.db:
                store.db.execute("INSERT OR REPLACE INTO reviews VALUES (?, ?)", (finding, json.dumps(value)))
                store.event("finding-review", finding=finding, review_sha256=digest(value))
        finally:
            store.close()
        return value


def compare_runs(first, second):
    a, b = summarize_run(first), summarize_run(second)
    if a["scope_sha256"] != b["scope_sha256"]:
        raise ValueError("Retest comparison requires identical profile, targets and project bindings")
    old, new = {r["id"] for r in a["findings"]}, {r["id"] for r in b["findings"]}
    coverage_equal = [(r["stage"], r["selected"]) for r in a["coverage"]] == [
        (r["stage"], r["selected"]) for r in b["coverage"]]
    comparable = (coverage_equal and a["adapter_coverage"] == b["adapter_coverage"]
                  and a["assessment_sha256"] == b["assessment_sha256"]
                  and a["status"] == b["status"] == "completed")
    return {"first_run": a["run_id"], "second_run": b["run_id"],
            "persistent": sorted(old & new), "new_candidates": sorted(new - old),
            "not_observed": sorted(old - new) if comparable else [],
            "unknown": sorted(old - new) if not comparable else [],
            "limitations": "Absence is not proof of repair. Line changes can alter candidate identities. Independent retest validation is required."}


def export_report(run, out, kind):
    from .workflow_store import approved_directory
    summary = summarize_run(run)
    destination = Path(out).expanduser().absolute()
    approved_directory(destination.parent)
    if kind == "json":
        content = json.dumps(summary, ensure_ascii=True, indent=2)
    elif kind == "sarif":
        # Reuse conservative existing exporter without trusting cached summary.
        from .sarif_export import export_sarif
        import tempfile
        with tempfile.TemporaryDirectory(dir=destination.parent) as temporary:
            from .workflow_store import private_write
            path = Path(temporary) / "findings.json"
            projects = {row["project_ref_hash"] for row in summary["findings"] if row["project_ref_hash"]}
            rows = [dict(row, target_ref_hash=row["target_ref_hash"] or row["project_ref_hash"],
                         file_path="external-evidence" if len(projects) > 1 else row["file_path"])
                    for row in summary["findings"]]
            private_write(path, {"findings": rows})
            content = json.dumps(export_sarif(path), indent=2)
    elif kind == "html":
        esc = lambda value: html.escape(str(value), quote=True)
        rows = "".join(f"<tr><td>{esc(row['rule_id'])}</td><td>{esc(row['severity'])}</td>"
                       f"<td>{esc(row['verification_status'])}</td><td>{esc(row['title'])}<br>"
                       f"{esc(row['file_path'])}:{row['line_start']}<br>{esc(row['remediation'])}"
                       f"<details><summary>Evidence references</summary><pre>{esc(json.dumps(row['evidence'], indent=2))}</pre></details></td></tr>"
                       for row in summary["findings"])
        content = ("<!doctype html><html lang='en'><meta charset='utf-8'>"
                   "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
                   "<meta name='viewport' content='width=device-width, initial-scale=1'><title>HunterQA assessment</title>"
                   "<style>body{font:16px system-ui;max-width:1100px;margin:32px auto;padding:16px}"
                   "pre{white-space:pre-wrap;overflow-wrap:anywhere}"
                   "table{border-collapse:collapse;width:100%;overflow-wrap:anywhere}td,th{border:1px solid #aaa;padding:10px;text-align:left}"
                   "@media print{body{margin:0;font-size:11px}tr{break-inside:avoid}}</style>"
                   f"<h1>HunterQA assessment</h1><p>Run {esc(summary['run_id'])} — {esc(summary['status'])}</p>"
                   f"<p>Charged request reservations: {summary['charged_requests']}. Findings: {len(summary['findings'])}.</p>"
                   "<p>Severity labels and analyst decisions require independent assessment. Use browser Print to save as PDF.</p>"
                   "<h2>Findings and remediation</h2><table><tr><th>Rule</th><th>Source severity</th><th>Review</th><th>Evidence context and remediation</th></tr>"
                   + rows + "</table><h2>Coverage and audit</h2><pre>" + esc(json.dumps(
                       {"coverage": summary["coverage"], "steps": summary["steps"],
                        "audit_head_sha256": summary["audit_head_sha256"]}, indent=2))
                   + "</pre><h2>HTML discovery and forms</h2><pre>" + esc(json.dumps(summary["web_discovery"], indent=2))
                   + "</pre><h2>Limits</h2><ul>" + "".join(f"<li>{esc(x)}</li>" for x in summary["limitations"]) + "</ul></html>")
    else:
        raise ValueError("Report format must be json, html or sarif")
    raw = content.encode("utf-8")
    if len(raw) > 2_000_000:
        raise ValueError("Export exceeds size limit")
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
    return {"format": kind, "bytes": len(raw), "findings": len(summary["findings"])}
