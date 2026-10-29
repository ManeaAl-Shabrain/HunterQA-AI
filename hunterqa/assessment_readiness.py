"""Read-only local readiness checks. Never authorize or launch an assessment."""
from __future__ import annotations

import importlib.util
import os
import shutil
import sqlite3
import sys
from pathlib import Path

from .assessment_benchmark import StaleBenchmark, verify_benchmark
from .coverage_audit import coverage_audit
from .doctor import _root_is_safe
from .engagement import _policy_snapshot
from . import shared_quota


def assessment_readiness(*, benchmark_dir=None, profile=None):
    checks = []
    def add(name, status, detail, *, required=False):
        checks.append({"name": name, "status": status, "detail": detail, "required": required})

    add("python", "ok" if sys.version_info >= (3, 11) else "fail", "Python 3.11+", required=True)
    for module in ("flask", "packaging"):
        add(module, "ok" if importlib.util.find_spec(module) is not None else "fail", "Core package availability", required=True)
    roots = [Path(v).expanduser() for v in os.environ.get("HUNTERQA_APPROVED_ROOTS", "").split(os.pathsep) if v]
    valid_roots = bool(roots) and all(_root_is_safe(root) for root in roots)
    add("approved_roots", "ok" if valid_roots else "fail", "Existing absolute roots without symlink components; paths are not displayed", required=True)
    add("semgrep", "ok" if shutil.which("semgrep") else "optional_missing", "Needed for Semgrep commands; not required by the fixed HTTP/TCP adapters")
    cloud = all(importlib.util.find_spec(name) is not None for name in ("botocore", "defusedxml"))
    add("cloud_extra", "ok" if cloud else "optional_missing", "Install .[cloud] for AWS account checks; no credential lookup is performed")
    if profile is not None:
        try:
            policy, fingerprint = _policy_snapshot(profile)
            add("scope_profile", "ok", "Profile parsed offline; owner authorization and live target reachability remain unverified")
            scope = {"policy_sha256": fingerprint, "get_admitted": "GET" in policy.methods,
                     "max_requests": policy.max_requests, "interval_seconds": policy.interval_seconds}
        except (OSError, ValueError, TypeError, KeyError, RuntimeError):
            scope = None
            add("scope_profile", "fail", "Invalid or inaccessible profile in approved roots; no target contacted")
    else:
        scope = None
        add("scope_profile", "not_provided", "Each customer assessment still needs its own reviewed scope and execution approval")
    ledger = os.environ.get("HUNTERQA_QUOTA_LEDGER")
    if ledger:
        try:
            quota = shared_quota.status(ledger)
            failed = quota["stopped"] or quota["expired"] or quota["charged_requests"] >= quota["configuration"]["max_requests"] or quota["active_runs"] >= quota["configuration"]["max_active_runs"]
            add("shared_quota", "fail" if failed else "ok", "Configured host-local quota status; admission is rechecked atomically at execution", required=True)
        except (OSError, ValueError, TypeError, KeyError, sqlite3.Error):
            add("shared_quota", "fail", "Configured quota ledger is inaccessible or invalid", required=True)
    else:
        add("shared_quota", "not_configured", "Per-run limits remain active; shared organization enforcement is not implied")
    if benchmark_dir is None:
        evidence = {"status": "not_provided", "passed": False}
    else:
        try:
            evidence = verify_benchmark(benchmark_dir)
        except StaleBenchmark:
            evidence = {"status": "stale", "passed": False, "detail": "Rerun the owned benchmark with this installed fixture/runtime version"}
        except (OSError, ValueError, TypeError, KeyError, IndexError, RuntimeError, sqlite3.Error):
            evidence = {"status": "invalid", "passed": False, "detail": "Retained benchmark evidence failed consistency checks; no test was launched"}
    add("owned_lab_evidence", "ok" if evidence["passed"] else "needs_validation", "Only retained current-runtime evidence is accepted; hashes do not authenticate the directory owner")
    installation = all(c["status"] == "ok" for c in checks if c["required"])
    return {"engine": "hunterqa_assessment_readiness", "schema_version": 1,
        "installation_ready": installation, "supported_owned_lab_checks_passed": installation and evidence["passed"],
        "checks": checks, "scope": scope, "owned_lab_evidence": evidence, "coverage": coverage_audit(),
        "all_seven_areas_complete": False, "production_multi_user_ready": False,
        "real_world_effectiveness": "unverified", "network_requests": 0, "tools_launched": 0, "changes_made": False,
        "authorization": "This report never authorizes a customer test; reviewed scope, protocol, execution and checkpoints are still required",
        "limitations": ["Owned evidence is a retrospective fixture baseline, not a live environment health check",
            "AWS runtime checks have synthetic contract tests only; real cloud readiness is not established",
            "Independent owner grants, multi-user RBAC, OS sandboxing, distributed enforcement and full category coverage remain incomplete"]}
