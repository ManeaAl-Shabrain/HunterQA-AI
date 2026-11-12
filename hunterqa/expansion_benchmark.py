"""Reproducible local expansion acceptance; explicitly separates models from IO."""
import hashlib
import json
import os
import secrets

from . import access_graph, assessment_sessions, scenario_assessment, scenario_lab
from .bounty import _approved_file
from .cli import _approved_root


def _save(path, text):
    _approved_root(str(path.parent))
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(text)


def save(path, value):
    _save(path, json.dumps(value, indent=2) + "\n")


def benchmark(out_dir, *, authorized=False, browser=False):
    if authorized is not True:
        raise PermissionError("Owned benchmark requires --authorized")
    from pathlib import Path
    destination = Path(out_dir).expanduser()
    _approved_root(str(destination.parent))
    if destination.exists() or not destination.is_absolute():
        raise FileExistsError("Use a new absolute owned-benchmark directory")
    secret_root = assessment_sessions.private_path(
        os.environ.get("HUNTERQA_ASSESSMENT_SECRET_ROOT", "") + "/root-check", existing=False).parent
    destination.mkdir(mode=0o700)
    suffix = secrets.token_hex(8)
    vault, key = secret_root / ("owned-" + suffix + ".json"), secret_root / ("owned-" + suffix + ".key")
    result = {"engine": "owned-expansion-benchmark", "schema_version": 1, "fixture_version": scenario_lab.VERSION,
        "checks": [], "network_requests": 0, "real_providers_verified": False, "real_ad_verified": False,
        "real_cloud_verified": False, "real_world_effectiveness": "unverified"}
    with scenario_lab.serve() as lab:
        profile = destination / "profile.json"
        save(profile, scenario_lab.profile(lab))
        assessment_sessions.create(vault, key, json.dumps(scenario_lab.sessions(lab)).encode(), authorized=True)
        cases = [("sqli-" + context, scenario_lab.case("sqli-boolean", lab, context=context), "matched", "actual-http-sqlite")
            for context in ("single-quoted", "double-quoted", "numeric")]
        safe = scenario_lab.case("sqli-boolean", lab)
        safe["url"] = lab["base"] + "/safe"
        cases.append(("parameterized-control", safe, "not_observed", "actual-http-sqlite"))
        for kind in ("workflow", "ssrf-callback", "upload-canary"):
            cases.append((kind, scenario_lab.case(kind, lab), "matched", "actual-owned-http"))
        cases.append(("timing", scenario_lab.case("sqli-timing", lab), "timing_signal", "synthetic-server-delay-measured-over-http"))
        if browser:
            cases.append(("browser-actions", scenario_lab.case("browser-journey", lab), "matched", "actual-chromium-owned-http"))
            for context, path in (("html", "html"), ("single-attribute", "single"), ("double-attribute", "double"), ("dom-fragment", "dom")):
                cases.append(("xss-" + context, {"id": "xss-context", "kind": "xss-context", "owned_test_endpoint": True,
                    "actor": "anonymous", "url": lab["base"] + "/xss-" + path, "parameter": "value", "context": context, "script_urls": []},
                    "matched", "actual-chromium-owned-context"))
        for name, case, expected, evidence_type in cases:
            plan_file = destination / (name + "-plan.json")
            save(plan_file, scenario_lab.plan([case]))
            sessions = {"session_file": str(vault), "session_key": str(key)}
            approval = scenario_assessment.preflight(profile, plan_file, **sessions)["approval_sha256"]
            report = scenario_assessment.run(profile, plan_file, approval, authorized=True, **sessions)
            report_path = destination / (name + "-report.json")
            save(report_path, report)
            state = report["cases"][0]["state"]
            result["checks"].append({"case": name, "expected": expected, "observed": state, "matched": state == expected,
                "evidence_type": evidence_type, "report_file": report_path.name,
                "report_sha256": hashlib.sha256(_approved_file(report_path).read_bytes()).hexdigest()})
            result["network_requests"] += report["requests"]
        result["owned_callback_requests"] = sum(path == "/receive" for _, path in lab["requests"])
        result["uploads_remaining"] = len(lab["uploads"])
    for domain in sorted(access_graph.DOMAINS):
        snapshot = scenario_lab.graph(domain)
        source = destination / (domain + "-model.json")
        save(source, snapshot)
        report = access_graph.review(source, authorized=True)
        save(destination / (domain + "-report.json"), report)
        result["checks"].append({"case": domain + "-entitlements", "expected": "matched", "observed": "matched" if all(row["contract_state"] == "matched" for row in report["queries"]) else "different",
            "matched": all(row["contract_state"] == "matched" for row in report["queries"]), "evidence_type": "synthetic-normalized-permission-model",
            "report_file": domain + "-report.json", "report_sha256": hashlib.sha256(_approved_file(destination / (domain + "-report.json")).read_bytes()).hexdigest()})
    from .service_fingerprints import inspect
    result["tcp_connections"] = 0
    with scenario_lab.services() as endpoints:
        from datetime import timedelta
        from .engagement import utcnow
        for protocol, port in endpoints.items():
            source = destination / (protocol + "-service.json")
            save(source, {"schema_version": 1, "protocol": protocol, "authorization_reference": "Owned service acceptance",
                "acknowledged_authorization": True, "expires_at": (utcnow() + timedelta(minutes=5)).isoformat(),
                "server_ip": "127.0.0.1", "server_port": port, "allow_private_network": True})
            report = inspect(source, authorized=True)
            save(destination / (protocol + "-report.json"), report)
            result["tcp_connections"] += report["connection_attempts"]
            result["checks"].append({"case": protocol + "-identification", "expected": "observed", "observed": report["outcome"],
                "matched": report["outcome"] == "observed", "evidence_type": "actual-loopback-tcp", "report_file": protocol + "-report.json",
                "report_sha256": hashlib.sha256(_approved_file(destination / (protocol + "-report.json")).read_bytes()).hexdigest()})
    result["all_cases_matched"] = all(row["matched"] for row in result["checks"]) and result["uploads_remaining"] == 0
    save(destination / "benchmark.json", result)
    return result
