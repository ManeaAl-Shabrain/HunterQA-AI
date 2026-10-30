"""Owned loopback HTTP/Chromium baseline with separately declared case labels."""
from contextlib import closing, contextmanager
import hashlib
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import PackageNotFoundError, version
import json
from pathlib import Path
import sqlite3
from threading import Lock, Thread
from urllib.parse import parse_qs, urlsplit

from .bounty import _read_json
from .engagement import _policy_snapshot, create_plan, digest, run_assessment, utcnow
from .lab_validation import _query
from .runtime_validation import retained_state
from .workflow_runner import _runtime_identity
from .workflow_store import approved_directory, private_write

LABELS = Path(__file__).parent / "fixtures" / "runtime-validation-v1.json"
PUBLIC_MARKER = "HUNTERQA_CANARY_0123456789ABCDEF"


def _identity():
    try:
        playwright = version("playwright")
    except PackageNotFoundError:
        playwright = None
    return digest({"package_runtime": _runtime_identity(), "playwright_package": playwright})


@contextmanager
def owned_service():
    """Only an original two-row in-memory database and six fixed fixture routes."""
    count, lock = [0], Lock()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            with lock:
                count[0] += 1
            parts = urlsplit(self.path)
            headers = [("Content-Type", "text/html; charset=utf-8")]
            try:
                query = parse_qs(parts.query, keep_blank_values=True, strict_parsing=True, max_num_fields=1)
                if set(query) != {"q"} or len(query["q"]) != 1 or len(query["q"][0]) > 256:
                    raise ValueError("Invalid fixture query")
                value = query["q"][0]
                if parts.path in {"/sql/literal", "/sql/bound"}:
                    with closing(sqlite3.connect(":memory:")) as db:
                        db.execute("CREATE TABLE records (owner TEXT, name TEXT, marker TEXT)")
                        db.executemany("INSERT INTO records VALUES (?,?,?)",
                            [("viewer", "visible", "PUBLIC_SYNTHETIC_ROW"), ("owner", "private", PUBLIC_MARKER)])
                        db.commit()
                        db.execute("PRAGMA query_only=ON")
                        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 4096)
                        db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 4096)
                        db.set_progress_handler(lambda: 1, 10000)
                        db.set_authorizer(lambda action, *args: sqlite3.SQLITE_OK
                            if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ) else sqlite3.SQLITE_DENY)
                        rows, _ = _query(db, "bound" if parts.path.endswith("bound") else "literal", value)
                        body = "\n".join(html.escape(row[0]) for row in rows)
                elif parts.path in {"/xss/html", "/xss/csp"}:
                    body = "<!doctype html><body>" + value
                    if parts.path.endswith("csp"):
                        headers.append(("Content-Security-Policy", "default-src 'none'; script-src 'none'"))
                elif parts.path in {"/sql/reflection", "/xss/escaped"}:
                    body = "<!doctype html><body>" + html.escape(value)
                else:
                    raise ValueError("Unknown fixture route")
                raw = body.encode()
                self.send_response(200)
            except (ValueError, sqlite3.Error):
                raw = b"Generic fixture failure"
                self.send_response(400)
            for key, value in headers:
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], count
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def measure(labels, runs):
    if not isinstance(runs, list) or len(runs) != len(labels["cases"]):
        raise ValueError("Expected every independent runtime label")
    metrics, cases = {}, []
    for case, run in zip(labels["cases"], runs):
        if (not isinstance(run, dict) or run.get("id") != case["id"]
                or run.get("kind") != case["kind"] or run.get("state") not in
                {"matched", "not_observed", "inconclusive"}):
            raise ValueError("Invalid runtime case observation")
        score = metrics.setdefault(case["kind"], {"true_positives": 0, "false_positives": 0,
            "false_negatives": 0, "true_negatives": 0, "inconclusive_positive": 0, "inconclusive_negative": 0})
        truth, state = case["expected_state"] == "matched", run["state"]
        if state == "inconclusive":
            score["inconclusive_positive" if truth else "inconclusive_negative"] += 1
        else:
            predicted = state == "matched"
            key = ("true_positives" if predicted else "false_negatives") if truth else (
                "false_positives" if predicted else "true_negatives")
            score[key] += 1
        cases.append({"id": case["id"], "matched": state == case["expected_state"]})
    for score in metrics.values():
        tp, fp, fn, tn = (score[key] for key in ("true_positives", "false_positives", "false_negatives", "true_negatives"))
        positives = tp + fn + score["inconclusive_positive"]
        score.update(precision=tp / (tp + fp) if tp + fp else None,
                     recall=tp / (tp + fn) if tp + fn else None,
                     false_negative_rate=fn / (tp + fn) if tp + fn else None,
                     false_positive_rate=fp / (fp + tn) if fp + tn else None,
                     positive_miss_rate=(fn + score["inconclusive_positive"]) / positives if positives else None)
    return {"cases": cases, "by_class": metrics, "all_cases_matched": all(case["matched"] for case in cases)}


def _runs(root, labels):
    runs, requests = [], 0
    _, policy_hash = _policy_snapshot(root / "scope.json")
    for case in labels["cases"]:
        report = _read_json(root / (case["id"] + ".result.json"), 100_000)
        plan = _read_json(root / (case["id"] + ".plan.json"), 32768)
        if (not isinstance(report, dict) or report.get("engine") != "hunterqa_approved_assessment"
                or type(report.get("schema_version")) is not int or report["schema_version"] != 1
                or type(report.get("stopped")) is not bool or report.get("review_required") is not True
                or report.get("policy_sha256") != policy_hash or report.get("plan_sha256") != digest(plan)
                or not isinstance(plan, dict) or plan.get("policy_sha256") != policy_hash
                or type(report.get("requests")) is not int or not 0 <= report["requests"] <= 5
                or not isinstance(report.get("observations"), list) or len(report["observations"]) != 1
                or not isinstance(report.get("claims"), dict)
                or any(type(report["claims"].get(k)) is not int or report["claims"][k] != 0
                       for k in ("verified_vulnerabilities", "confirmed_zero_days", "cve_ids_created"))):
            raise ValueError("Invalid retained runtime report")
        observation = report["observations"][0]
        if not isinstance(observation, dict) or observation.get("mode") != case["kind"] + "-canary-check":
            raise ValueError("Retained report has a different validation mode")
        validation = observation.get("validation", {})
        state = retained_state(validation, case["kind"], report.get("stopped") is not False) if validation else "inconclusive"
        if (state != "inconclusive" and (report.get("stopped") is not False or report["requests"] != 5
                or len(validation.get("receipts", [])) != 5)):
            raise ValueError("Incomplete runtime evidence cannot have a decisive result")
        runs.append({"id": case["id"], "kind": case["kind"], "state": state, "report_sha256": digest(report)})
        requests += report["requests"]
    return runs, requests


def benchmark(out_dir, *, authorized=False):
    if not authorized:
        raise PermissionError("Owned runtime benchmark requires --authorized")
    root = Path(out_dir).expanduser().absolute()
    approved_directory(root.parent)
    root.mkdir(mode=0o700)
    labels = json.loads(LABELS.read_bytes())
    private_write(root / "ground-truth.json", labels)
    with owned_service() as (port, count):
        profile = root / "scope.json"
        private_write(profile, {"program": "Owned fixed HTTP runtime fixture", "platform": "local-lab",
            "authorization_reference": "Owned ephemeral synthetic loopback endpoints only",
            "acknowledged_authorization": True, "allowed_hosts": ["127.0.0.1"], "allowed_paths": ["/"],
            "excluded_paths": [], "methods": ["GET"], "allowed_ports": [port], "max_requests": 5,
            "interval_seconds": 0.5, "lab_mode": True, "allow_private_network": True, "allow_http": True})
        for case in labels["cases"]:
            contract = {"parameter": "q", "owned_test_endpoint": True}
            if case["kind"] == "sql":
                contract["canary_marker"] = PUBLIC_MARKER
            plan = create_plan(profile, [f"http://127.0.0.1:{port}" + case["path"]],
                mode=case["kind"] + "-canary-check", browser_isolated=case["kind"] == "xss", validation=contract)
            path = root / (case["id"] + ".plan.json")
            private_write(path, plan)
            result = run_assessment(profile, path, digest(plan), root / "STOP", authorized=True)
            private_write(root / (case["id"] + ".result.json"), result)
        served = count[0]
    runs, requests = _runs(root, labels)
    if requests != served:
        raise ValueError("Owned server and request reservations differ")
    report = {"engine": "hunterqa_owned_http_runtime_benchmark", "schema_version": 1,
        "generated_at": utcnow().isoformat(), "fixture_version": labels["fixture_version"],
        "source_identity_sha256": _identity(), "labels_sha256": hashlib.sha256(LABELS.read_bytes()).hexdigest(),
        "runs": runs, **measure(labels, runs), "network_requests": requests, "server_requests": served,
        "customer_vulnerabilities_confirmed": 0, "real_world_effectiveness": "unverified",
        "limitations": ["Six synthetic endpoints, one positive and two negatives per class; not field accuracy",
            "SQL result is a controlled canary behavioral difference, not proof of an arbitrary SQLi mechanism",
            "XSS witness is limited to this reflected SVG event marker with fresh contexts and no external resources",
            "Inconclusive samples are reported separately; positive_miss_rate includes inconclusive positives",
            "Receipts and hashes are local consistency evidence, not independent authenticity"]}
    private_write(root / "benchmark.json", report)
    return report


def verify(directory):
    """Offline consistency only; fresh HTTP/browser validation requires a new run."""
    root = approved_directory(directory)
    report = _read_json(root / "benchmark.json", 100_000)
    labels = json.loads(LABELS.read_bytes())
    if (not isinstance(report, dict) or report.get("engine") != "hunterqa_owned_http_runtime_benchmark"
            or type(report.get("schema_version")) is not int or report["schema_version"] != 1
            or report.get("fixture_version") != labels["fixture_version"]
            or report.get("source_identity_sha256") != _identity()
            or report.get("labels_sha256") != hashlib.sha256(LABELS.read_bytes()).hexdigest()
            or _read_json(root / "ground-truth.json", 100_000) != labels
            or type(report.get("customer_vulnerabilities_confirmed")) is not int
            or report["customer_vulnerabilities_confirmed"] != 0
            or report.get("real_world_effectiveness") != "unverified"):
        raise ValueError("Runtime benchmark is stale, inconsistent or overstated")
    runs, requests = _runs(root, labels)
    measured = measure(labels, runs)
    if (digest(report.get("runs")) != digest(runs) or any(digest(report.get(k)) != digest(v) for k, v in measured.items())
            or type(report.get("network_requests")) is not int or report["network_requests"] != requests
            or type(report.get("server_requests")) is not int or report["server_requests"] != requests):
        raise ValueError("Runtime benchmark claims do not match retained reports")
    return {"status": "retained_consistency_checked", "passed": measured["all_cases_matched"], **measured,
            "network_requests": 0, "browser_launched": False, "fresh_validation_performed": False,
            "real_world_effectiveness": "unverified", "trust": "Evidence-directory owner is trusted; rerun for fresh validation"}
