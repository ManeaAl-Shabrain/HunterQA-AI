"""Versioned owned-loopback application benchmark; never a real-world score."""
from __future__ import annotations

import hashlib
import html
import json
import socket
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .assessment_setup import setup_assessment
from .engagement import utcnow, digest
from .web_discovery import setup_discovery
from .workflow_store import approved_directory, private_write

BENCHMARK_TOOLS = ("web-canary-check", "authorization-matrix", "web-discovery", "service-enumeration")


class OwnedFixture(BaseHTTPRequestHandler):
    def do_GET(self):
        if len(self.path) > 2048:
            self.send_error(414)
            return
        parts = urlsplit(self.path)
        if hasattr(self.server, "observed_paths"):
            self.server.observed_paths.append(parts.path)
        value = parse_qs(parts.query).get("q", [""])[0]
        status, media = 200, "text/html"
        if parts.path == "/app/markup/raw":
            body = value
        elif parts.path == "/app/markup/escaped":
            body = html.escape(value)
        elif parts.path == "/app/markup/textarea":
            body = "<textarea>" + value + "</textarea>"
        elif parts.path == "/app/markup/json":
            body, media = json.dumps({"value": value}), "application/json"
        elif parts.path in ("/app/sql/concatenated", "/app/sql/parameterized"):
            # Intentional toy flaw: private in-memory DB, no tables or customer
            # data, one SELECT, query-only mode. Never a production application.
            with sqlite3.connect(":memory:") as db:
                db.execute("PRAGMA query_only=ON")
                db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 4096)
                try:
                    if parts.path.endswith("/parameterized"):
                        db.execute("SELECT ?", (value,)).fetchone()
                    else:
                        db.execute("SELECT '" + value + "'").fetchone()
                    body = "Owned synthetic result"
                except sqlite3.Error:
                    body = "sqlite3.OperationalError: owned fixture rejected its query"
        elif parts.path == "/app/access/broken":
            body = "Owned synthetic object: owner-only according to the fixture contract"
        elif parts.path == "/app/access/denied":
            body, status = "Synthetic access denied", 403
        elif parts.path == "/app/discovery/index":
            body = '''<a href="/app/discovery/child">child</a>
                <a href="/app/discovery/excluded">excluded</a>
                <a href="https://outside.example.test/">outside</a>
                <script>fetch('/app/discovery/script')</script>
                <form action="/app/discovery/form" method="post">
                <input type="password" name="PRIVATE_FIXTURE_NAME" value="PRIVATE_FIXTURE_RESPONSE">
                <input type="hidden" name="PRIVATE_FIXTURE_TOKEN" value="PRIVATE_FIXTURE_RESPONSE"></form>'''
        elif parts.path == "/app/discovery/child":
            body = "Owned discovery child"
        else:
            body, status = "Unknown owned fixture route", 404
        self.send_response(status)
        self.send_header("Content-Type", media)
        # The lab tests inert reflection cues, never browser script execution.
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


def score(labels, findings):
    """Score source-controlled expected rule cues; do not infer exploitability."""
    observed = {}
    for finding in findings:
        observed.setdefault(finding["test_case"], set()).add(finding["rule_id"])
    groups, rows = {}, []
    for case in labels["cases"]:
        expected, actual = set(case["expected"]), observed.pop(case["id"], set())
        group = groups.setdefault(case["class"], {"true_positives": 0, "false_positives": 0, "false_negatives": 0, "true_negatives": 0})
        group["true_positives"] += len(expected & actual)
        group["false_positives"] += len(actual - expected)
        group["false_negatives"] += len(expected - actual)
        group["true_negatives"] += int(not expected and not actual)
        rows.append({"id": case["id"], "class": case["class"], "expected": sorted(expected),
                     "observed": sorted(actual), "matched": expected == actual})
    if observed:
        raise ValueError("Benchmark produced findings outside labeled cases")
    for group in groups.values():
        tp, fp, fn = group["true_positives"], group["false_positives"], group["false_negatives"]
        group.update(precision=tp / (tp + fp) if tp + fp else None,
                     recall=tp / (tp + fn) if tp + fn else None)
    return {"by_class": groups, "cases": rows, "all_cases_matched": all(row["matched"] for row in rows)}


def workflow_controls(results):
    discovery = results["web-discovery"]
    service = results["service-enumeration"]
    inventory = discovery["web_discovery"][0]
    paths = {urlsplit(asset["url"]).path for asset in discovery["assets"]}
    forms = inventory["forms"]
    journal_paths = {urlsplit(record["details"]["target_url"]).path
        for journal in discovery["network_evidence"] for record in journal["records"] if record["kind"] == "intent"}
    return [
        {"id": "html-links-and-forms", "matched": paths == {"/app/discovery/index", "/app/discovery/child"}
            and len(forms) == 1 and forms[0]["method"] == "POST" and forms[0]["submission_enabled"] is False
            and forms[0]["input_types"] == ["password", "hidden"]},
        {"id": "discovery-scope-and-privacy", "matched": journal_paths == paths
            and inventory["summary"]["skipped"] >= 2 and "PRIVATE_FIXTURE" not in json.dumps(discovery)},
        {"id": "tcp-open-and-refused", "matched": [row["outcome"] for row in service["observations"]] == ["connected", "refused"]
            and sum(j["connections"] for j in service["network_evidence"]) == 2
            and sum(j["responses"] for j in service["network_evidence"]) == 0},
    ]


def benchmark_assessments(out_dir, *, authorized=False):
    from .workflow_runner import run_workflow
    if not authorized:
        raise PermissionError("Owned-loopback benchmark requires --authorized")
    root = Path(out_dir).expanduser().absolute()
    approved_directory(root.parent)
    root.mkdir(mode=0o700)
    raw = (Path(__file__).parent / "fixtures" / "assessment-v1.json").read_bytes()
    labels = json.loads(raw)
    private_write(root / "ground-truth.json", labels)
    server = ThreadingHTTPServer(("127.0.0.1", 0), OwnedFixture)
    server.observed_paths = []
    refused = socket.socket()
    refused.bind(("127.0.0.1", 0))  # Keep an owned port reserved without listening.
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        profile = root / "profile.json"
        private_write(profile, {"program": "Owned versioned assessment benchmark", "platform": "local-lab",
            "authorization_reference": "Operator-approved original synthetic loopback fixture only",
            "acknowledged_authorization": True, "allowed_hosts": ["127.0.0.1"],
            "allowed_paths": ["/app"], "excluded_paths": ["/app/discovery/excluded"],
            "methods": ["GET"], "allowed_ports": [server.server_port, refused.getsockname()[1]],
            "max_requests": 20, "interval_seconds": 0.5, "lab_mode": True,
            "allow_http": True, "allow_private_network": True})
        manifests = {"web-canary-check": {"schema_version": 1, "checks": [
            {"id": c["id"], "kind": c["class"], "url": base + c["path"], "parameter": "q"}
            for c in labels["cases"] if c["class"] != "authorization-contract"]},
            "authorization-matrix": {"schema_version": 1,
                "roles": {"other": {"origin": base + "/app/", "authenticated": True}},
                "cases": [{"id": c["id"], "role": "other", "url": base + c["path"],
                    "expect": "deny", "statuses": [403], "body_sha256": None}
                    for c in labels["cases"] if c["class"] == "authorization-contract"]}}
        secret = root / "fixture-credentials.json"
        private_write(secret, {"other": "Bearer HUNTERQA_OWNED_BENCHMARK_FIXTURE"})
        runs, findings, results = [], [], {}
        for tool in BENCHMARK_TOOLS:
            config = root / f"{tool}-config"
            if tool == "web-discovery":
                review = setup_discovery(profile, [base + "/app/discovery/index"], config, max_pages=3, max_depth=1, authorized=True)
            elif tool == "service-enumeration":
                review = setup_assessment(profile, tool, config, targets=[base + "/app/",
                    f"http://127.0.0.1:{refused.getsockname()[1]}/app/"], authorized=True)
            else:
                path = root / f"{tool}.json"
                private_write(path, manifests[tool])
                review = setup_assessment(profile, tool, config, input_file=path,
                    secret_file=secret if tool == "authorization-matrix" else None, authorized=True)
            result = run_workflow(profile, config / "protocol.json", config / "bindings.json", root / f"{tool}-run",
                execution_approval=review["execution_sha256"], protocol_approval=review["preflight"]["protocol_sha256"],
                approved_steps=review["preflight"]["pending_checkpoints"], operator="Owned benchmark operator", authorized=True)
            if result["status"] != "completed":
                raise ValueError("Benchmark workflow did not complete; inspect retained run evidence")
            results[tool] = result
            if tool in manifests:
                findings.extend(result["findings"])
            runs.append({"tool": tool, "runtime_sha256": result["runtime_sha256"],
                "audit_head_sha256": result["audit_head_sha256"],
                "requests": sum(j["intents"] for j in result["network_evidence"])})
        measured = score(labels, findings)
        controls = workflow_controls(results)
        if any(path in server.observed_paths for path in ("/app/discovery/excluded", "/app/discovery/script", "/app/discovery/form")):
            raise ValueError("Owned discovery crossed a fixture exclusion or executed/submitted content")
        report = {"engine": "hunterqa_owned_assessment_benchmark", "schema_version": 1, "generated_at": utcnow().isoformat(),
            "fixture_version": labels["fixture_version"], "ground_truth_sha256": hashlib.sha256(raw).hexdigest(),
            "fixture_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            **measured, "workflow_controls": controls, "runs": runs,
            "all_cases_matched": measured["all_cases_matched"] and all(c["matched"] for c in controls),
            "network_requests": sum(r["requests"] for r in runs),
            "limitations": ["Eight original cue cases plus three owned discovery/TCP controls; labels are not externally audited",
                "This is not a real-world detection rate, competitor benchmark or full standards coverage",
                "No confirmed exploitability is inferred; all underlying findings remain unverified"]}
        private_write(root / "benchmark.json", report)
        return report
    finally:
        refused.close()
        server.shutdown()
        server.server_close()
        thread.join(2)


class StaleBenchmark(ValueError):
    """Evidence comes from different fixture/source/runtime bytes."""


def verify_benchmark(directory):
    """Read and recompute retained evidence; never launch tests or contact hosts.

    This detects inconsistency, not forgery by the evidence-directory owner.
    """
    from .bounty import BountyPolicy, _approved_file, _read_json, _decode_json
    from .source_files import read_bounded
    from .workflow_results import summarize_run
    from .workflow_runner import _runtime_identity
    root = approved_directory(directory)
    report = _read_json(root / "benchmark.json", 2_000_000)
    if not isinstance(report, dict):
        raise ValueError("Expected an owned benchmark report object")
    labels_raw = (Path(__file__).parent / "fixtures" / "assessment-v1.json").read_bytes()
    labels = json.loads(labels_raw)
    if (report.get("engine") != "hunterqa_owned_assessment_benchmark" or type(report.get("schema_version")) is not int or report["schema_version"] != 1):
        raise ValueError("Unrecognized owned benchmark report")
    if (report.get("fixture_version") != labels["fixture_version"]
            or report.get("ground_truth_sha256") != hashlib.sha256(labels_raw).hexdigest()
            or report.get("fixture_source_sha256") != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            or _read_json(root / "ground-truth.json", 65_536) != labels):
        raise StaleBenchmark("Owned fixture labels/source do not match the installed version")
    profile_raw = read_bounded(_approved_file(root / "profile.json"), 32_768)
    policy = BountyPolicy.from_dict(_decode_json(profile_raw))
    if (policy.platform != "local-lab" or policy.allowed_hosts != ("127.0.0.1",) or not policy.lab_mode
            or not policy.allow_private_network or not policy.allow_http or policy.methods != ("GET",)):
        raise ValueError("Benchmark evidence is not scoped to the owned loopback lab")
    runtime = _runtime_identity()
    results, receipts, findings = {}, [], []
    for tool in BENCHMARK_TOOLS:
        result = summarize_run(root / f"{tool}-run")
        if result["status"] != "completed" or result["policy_sha256"] != hashlib.sha256(profile_raw).hexdigest():
            raise ValueError("Benchmark workflow did not complete with its recorded profile")
        if result["runtime_sha256"] != runtime:
            raise StaleBenchmark("Owned benchmark runtime does not match the installed runtime")
        results[tool] = result
        receipts.append({"tool": tool, "runtime_sha256": result["runtime_sha256"],
            "audit_head_sha256": result["audit_head_sha256"],
            "requests": sum(j["intents"] for j in result["network_evidence"])})
        if tool in ("web-canary-check", "authorization-matrix"):
            findings.extend(result["findings"])
    measured, controls = score(labels, findings), workflow_controls(results)
    recomputed = {**measured, "workflow_controls": controls, "runs": receipts,
        "all_cases_matched": measured["all_cases_matched"] and all(c["matched"] for c in controls),
        "network_requests": sum(r["requests"] for r in receipts)}
    if any(digest(report.get(key)) != digest(value) for key, value in recomputed.items()):
        raise ValueError("Benchmark claims do not match retained run evidence")
    return {"status": "integrity_checked", "passed": recomputed["all_cases_matched"],
        "fixture_version": labels["fixture_version"], "tested_adapters": list(BENCHMARK_TOOLS),
        "cases": len(labels["cases"]), "workflow_controls": controls,
        "by_class": measured["by_class"], "network_operations_recorded": recomputed["network_requests"],
        "current_runtime_sha256": runtime,
        "real_world_effectiveness": "unverified",
        "trust": "Local consistency checks only; evidence-directory owner is trusted; no security certification"}
