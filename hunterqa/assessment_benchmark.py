"""Versioned owned-loopback application benchmark; never a real-world score."""
from __future__ import annotations

import hashlib
import html
import json
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .assessment_setup import setup_assessment
from .workflow_store import approved_directory, private_write


class OwnedFixture(BaseHTTPRequestHandler):
    def do_GET(self):
        if len(self.path) > 2048:
            self.send_error(414)
            return
        parts = urlsplit(self.path)
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
        else:
            body, status = "Unknown owned fixture route", 404
        self.send_response(status)
        self.send_header("Content-Type", media)
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
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        profile = root / "profile.json"
        private_write(profile, {"program": "Owned versioned assessment benchmark", "platform": "local-lab",
            "authorization_reference": "Operator-approved original synthetic loopback fixture only",
            "acknowledged_authorization": True, "allowed_hosts": ["127.0.0.1"],
            "allowed_paths": ["/app"], "methods": ["GET"], "allowed_ports": [server.server_port],
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
        runs, findings = [], []
        for tool, manifest in manifests.items():
            path = root / f"{tool}.json"
            private_write(path, manifest)
            config = root / f"{tool}-config"
            review = setup_assessment(profile, tool, config, input_file=path,
                secret_file=secret if tool == "authorization-matrix" else None, authorized=True)
            result = run_workflow(profile, config / "protocol.json", config / "bindings.json", root / f"{tool}-run",
                execution_approval=review["execution_sha256"], protocol_approval=review["preflight"]["protocol_sha256"],
                approved_steps=["assess"], operator="Owned benchmark operator", authorized=True)
            if result["status"] != "completed":
                raise ValueError("Benchmark workflow did not complete; inspect retained run evidence")
            findings.extend(result["findings"])
            runs.append({"tool": tool, "runtime_sha256": result["runtime_sha256"],
                "audit_head_sha256": result["audit_head_sha256"],
                "requests": sum(j["intents"] for j in result["network_evidence"])})
        report = {"engine": "hunterqa_owned_assessment_benchmark", "schema_version": 1,
            "fixture_version": labels["fixture_version"], "ground_truth_sha256": hashlib.sha256(raw).hexdigest(),
            "fixture_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            **score(labels, findings), "runs": runs, "network_requests": sum(r["requests"] for r in runs),
            "limitations": ["Eight original owned application cases in three cue classes; labels are not externally audited",
                "This is not a real-world detection rate, competitor benchmark or full standards coverage",
                "No confirmed exploitability is inferred; all underlying findings remain unverified"]}
        private_write(root / "benchmark.json", report)
        return report
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
