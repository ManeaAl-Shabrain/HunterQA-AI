"""Offline protocol compiler. This module never launches tools or sends traffic.

Resource ceilings are validated reservations for the independently approved
runner, not runtime enforcement by preflight. Operator review is an attestation,
not authenticated owner consent.
"""
from __future__ import annotations

import math
import re
from datetime import timedelta

from .bounty import _read_json
from .engagement import _expiry, _policy_snapshot, digest, utcnow

STAGES = (
    "asset-discovery", "service-enumeration", "vulnerability-identification",
    "controlled-validation", "evidence-collection", "reporting",
)
# A closed planning catalog. IDs are never resolved to shell commands, imports,
# entry points, executable paths, or instructions supplied by an external report.
CATALOG = {
    "declared-assets": (STAGES[0], False, "Review explicitly declared assets; no discovery traffic"),
    "service-evidence": (STAGES[1], False, "Review previously collected service evidence"),
    "source-review": (STAGES[2], False, "Plan existing local source and configuration review"),
    "external-findings": (STAGES[2], False, "Plan offline Nuclei/ZAP evidence import"),
    "approved-observation": (STAGES[3], True, "Plan a separately reviewed exact HEAD/GET assessment"),
    "approved-account-check": (STAGES[3], True, "Plan a separately reviewed dedicated-account check"),
    "evidence-index": (STAGES[4], False, "Plan evidence fingerprints and analyst review"),
    "report-draft": (STAGES[5], False, "Plan an unverified report and remediation review"),
}
ID = re.compile(r"[a-z][a-z0-9-]{0,47}", re.ASCII)
MAX_PROTOCOL = 65_536


def tool_catalog():
    return [{"id": key, "stage": stage, "active": active, "description": description,
             "workflow_execution_available": key != "approved-account-check"}
            for key, (stage, active, description) in CATALOG.items()]


def _fields(value, expected, label):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError(f"Unknown or missing {label} fields")


def _integer(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{label} must be an integer in {low}..{high}")


def _strings(value, low, high, label):
    if (not isinstance(value, list) or not low <= len(value) <= high
            or any(not isinstance(x, str) for x in value)
            or len(set(value)) != len(value)):
        raise ValueError(f"{label} must be a bounded list of unique strings")


def compile_protocol(profile_path, protocol_path, *, approved_steps=(),
                     approved_fingerprint=None, authorized=False, now=None):
    """Validate all steps before returning any review schedule; perform no DNS.

    Explicit reviews bind to both the entire protocol and exact profile bytes.
    A reviewed step still requires its existing command's independent checks.
    """
    policy, profile_hash = _policy_snapshot(profile_path)
    protocol = _read_json(protocol_path, MAX_PROTOCOL)
    _fields(protocol, ("schema_version", "policy_sha256", "authorization_reference",
                       "starts_at", "expires_at", "targets", "limits", "stop_file", "steps"),
            "protocol")
    _integer(protocol["schema_version"], 1, 1, "schema_version")
    if protocol["policy_sha256"] != profile_hash:
        raise ValueError("Protocol must bind to the exact scope profile bytes")
    if protocol["authorization_reference"] != policy.authorization_reference:
        raise ValueError("Protocol must retain the profile authorization reference")
    current = now or utcnow()
    start, expiry = _expiry(protocol["starts_at"]), _expiry(protocol["expires_at"])
    if not start < expiry or not timedelta(0) < expiry - current <= timedelta(hours=24):
        raise ValueError("Protocol must have an ordered window expiring within 24 hours")
    if expiry - start > timedelta(hours=24):
        raise ValueError("Testing window cannot exceed 24 hours")
    limits = protocol["limits"]
    _fields(limits, ("max_requests", "interval_seconds", "concurrency", "timeout_seconds"), "limits")
    _integer(limits["max_requests"], 0, policy.max_requests, "max_requests")
    _integer(limits["concurrency"], 1, 8, "concurrency")
    _integer(limits["timeout_seconds"], 1, 3600, "timeout_seconds")
    interval = limits["interval_seconds"]
    if (type(interval) not in (int, float)
            or not policy.interval_seconds <= interval <= 60 or not math.isfinite(interval)):
        raise ValueError("interval_seconds must respect the profile minimum and be at most 60")
    if limits["timeout_seconds"] > (expiry - max(start, current)).total_seconds():
        raise ValueError("Timeout reservation exceeds the remaining testing window")
    stop_file = protocol["stop_file"]
    if not isinstance(stop_file, str) or not ID.fullmatch(stop_file):
        raise ValueError("stop_file must be a simple lowercase run-directory name")
    targets = protocol["targets"]
    _strings(targets, 1, 40, "targets")
    # Exact URL checks only. DNS pinning and network validation remain runner duties.
    # A GET-capable profile can also plan its separately reviewed account check.
    method = "HEAD" if "HEAD" in policy.methods else "GET"
    for target in targets:
        policy.authorize_url(target, method)
    steps = protocol["steps"]
    if not isinstance(steps, list) or not 1 <= len(steps) <= 64:
        raise ValueError("Expected 1..64 workflow steps")
    by_id = {}
    requests = duration = 0
    for step in steps:
        _fields(step, ("id", "tool", "depends_on", "targets", "requests",
                       "timeout_seconds", "approval_required"), "step")
        step_id, tool = step["id"], step["tool"]
        if not isinstance(step_id, str) or not ID.fullmatch(step_id) or step_id in by_id:
            raise ValueError("Step IDs must be unique lowercase identifiers")
        if not isinstance(tool, str) or tool not in CATALOG:
            raise ValueError("Tool must belong to the closed planning catalog")
        stage, active, _ = CATALOG[tool]
        _strings(step["depends_on"], 0, 63, "depends_on")
        _strings(step["targets"], 1, 40, "step targets")
        if not set(step["targets"]) <= set(targets):
            raise ValueError("Step targets must belong to the protocol allowlist")
        _integer(step["requests"], 1 if active else 0,
                 limits["max_requests"] if active else 0, "step requests")
        _integer(step["timeout_seconds"], 1, 300, "step timeout_seconds")
        if type(step["approval_required"]) is not bool or (active and not step["approval_required"]):
            raise ValueError("Active validation requires an explicit approval checkpoint")
        if active:
            required_method = "GET" if tool == "approved-account-check" else method
            for target in step["targets"]:
                parts = policy.authorize_url(target, required_method)[0]
                if tool == "approved-account-check" and parts.scheme != "https":
                    raise ValueError("Account checks require HTTPS")
            if step["requests"] < len(step["targets"]):
                raise ValueError("Active reservations must cover every declared target")
        requests += step["requests"]
        duration += step["timeout_seconds"]
        by_id[step_id] = step
    if requests > limits["max_requests"] or duration > limits["timeout_seconds"]:
        raise ValueError("Aggregate step reservations exceed protocol request or time budgets")
    # Require a conservative serial reservation even if a future runner uses
    # concurrency. Include minimum dispatch spacing, not just adapter execution.
    if duration + max(0, requests - 1) * interval > limits["timeout_seconds"]:
        raise ValueError("Aggregate timeout must also reserve request spacing")
    for step in steps:
        for dependency in step["depends_on"]:
            if dependency not in by_id or dependency == step["id"]:
                raise ValueError("Unknown or self-referencing dependency")
            parent_stage = CATALOG[by_id[dependency]["tool"]][0]
            if STAGES.index(parent_stage) > STAGES.index(CATALOG[step["tool"]][0]):
                raise ValueError("Dependencies cannot reverse assessment stages")
    completed, batches = set(), []
    while len(completed) < len(steps):
        ready = sorted(key for key, step in by_id.items()
                       if key not in completed and set(step["depends_on"]) <= completed)
        if not ready:
            raise ValueError("Workflow dependency cycle rejected")
        # Global stage barriers preserve the declared assessment sequence even
        # for independent branches with no explicit cross-stage data dependency.
        earliest = min(STAGES.index(CATALOG[step["tool"]][0])
                       for key, step in by_id.items() if key not in completed)
        ready = [key for key in ready
                 if STAGES.index(CATALOG[by_id[key]["tool"]][0]) == earliest]
        if not ready:
            raise ValueError("Workflow dependency cycle rejected")
        batch = ready[:limits["concurrency"]]
        batches.append(batch)
        completed.update(batch)
    fingerprint = digest(protocol)
    approved_steps = list(approved_steps)
    _strings(approved_steps, 0, 64, "approved steps")
    checkpoints = {key for key, step in by_id.items() if step["approval_required"]}
    if not set(approved_steps) <= checkpoints:
        raise ValueError("Only existing checkpoint steps can be reviewed")
    if approved_steps and (not authorized or approved_fingerprint != fingerprint):
        raise PermissionError("Step review needs --authorized and the exact protocol fingerprint")
    if not approved_steps and approved_fingerprint is not None:
        raise ValueError("A review fingerprint requires at least one checkpoint step")
    pending = sorted(checkpoints - set(approved_steps))
    return {
        "engine": "hunterqa_workflow_preflight", "schema_version": 1,
        "policy_sha256": profile_hash, "protocol_sha256": fingerprint,
        "authorization_reference": policy.authorization_reference,
        "reviewed_at": current.isoformat(), "starts_at": start.isoformat(),
        "expires_at": expiry.isoformat(), "window_open": start <= current < expiry,
        "limits": limits, "reserved_requests": requests,
        "reserved_step_seconds": duration, "stop_file": stop_file,
        "planning_batches": batches, "pending_checkpoints": pending,
        "reviewed_checkpoints": sorted(approved_steps),
        "review_kind": "local_operator_attestation",
        "steps": [{"id": key, "tool": step["tool"],
                   "stage": CATALOG[step["tool"]][0],
                   "depends_on": step["depends_on"],
                   "reserved_requests": step["requests"],
                   "reserved_seconds": step["timeout_seconds"],
                   "active": CATALOG[step["tool"]][1],
                   "review_state": "pending" if key in pending else
                                   "reviewed" if key in checkpoints else "not-required"}
                  for key, step in sorted(by_id.items())],
        "execution_enabled": False, "tools_launched": 0, "network_requests": 0,
        "limitations": ["Preflight only: supported adapters require separate workflow-run execution approval",
                        "Limits are validated reservations, not runtime enforcement",
                        "Local attestations do not verify target-owner authorization",
                        "Step reviews do not authorize existing commands or confirm findings"],
    }
