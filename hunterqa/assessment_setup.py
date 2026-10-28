"""Offline setup for the closed assessment adapter catalog."""
from __future__ import annotations

import math
from datetime import timedelta
from pathlib import Path

from .bounty import _read_json
from .engagement import _policy_snapshot, utcnow
from .workflow_protocol import _integer, _strings
from .workflow_store import approved_directory, private_write

TOOLS = ("authorization-matrix", "service-enumeration", "aws-account-audit", "web-canary-check")


def setup_assessment(profile, tool, out_dir, *, targets=(), input_file=None, secret_file=None, authorized=False):
    from .workflow_runner import execution_plan
    if not authorized:
        raise PermissionError("Assessment setup requires --authorized")
    if tool not in TOOLS:
        raise ValueError("Unsupported assessment adapter")
    policy, fingerprint = _policy_snapshot(profile)
    binding = {}
    if tool == "service-enumeration":
        if input_file is not None or secret_file is not None:
            raise ValueError("Service enumeration accepts exact targets only")
        targets = list(targets)
        requests = len(targets)
    elif tool == "web-canary-check":
        if targets or input_file is None or secret_file is not None:
            raise ValueError("Canaries require an exact manifest and no credentials")
        from .web_canaries import validate_canaries
        manifest = validate_canaries(_read_json(input_file, 65_536), policy)
        targets = list(dict.fromkeys(check["url"] for check in manifest["checks"]))
        requests = 2 * len(manifest["checks"])
        binding = {"file": str(Path(input_file).expanduser().absolute())}
    else:
        if targets or input_file is None or secret_file is None:
            raise ValueError("Use an explicit input manifest and credential file; targets come from the manifest")
        binding = {"file": str(Path(input_file).expanduser().absolute()),
                   "secret_file": str(Path(secret_file).expanduser().absolute())}
        if tool == "authorization-matrix":
            from .access_matrix import validate_matrix
            matrix = validate_matrix(_read_json(input_file, 65_536), policy)
            targets = list(dict.fromkeys(case["url"] for case in matrix["cases"]))
            requests = len(matrix["cases"])
        else:
            from .cloud_account import TARGETS, validate_account
            validate_account(_read_json(input_file, 1024))
            targets, requests = TARGETS[:], 2
    _strings(targets, 1, 40, "assessment targets")
    _integer(requests, 1, policy.max_requests, "assessment requests")
    for target in targets:
        policy.authorize_url(target, "GET" if tool != "service-enumeration" or "HEAD" not in policy.methods else "HEAD")
    spacing = math.ceil((requests - 1) * policy.interval_seconds)
    timeout = max(60, requests * 5 + spacing + 10)
    if timeout > 300:
        raise ValueError("Split the assessment; worker reservation exceeds 300 seconds")
    destination = Path(out_dir).expanduser().absolute()
    approved_directory(destination.parent)
    now = utcnow()
    steps = [{"id": "assess", "tool": tool, "depends_on": [], "targets": targets,
              "requests": requests, "timeout_seconds": timeout, "approval_required": True}]
    for step_id, parent, adapter in (("evidence", "assess", "evidence-index"), ("report", "evidence", "report-draft")):
        steps.append({"id": step_id, "tool": adapter, "depends_on": [parent], "targets": targets,
                      "requests": 0, "timeout_seconds": 10, "approval_required": False})
    protocol = {"schema_version": 1, "policy_sha256": fingerprint,
        "authorization_reference": policy.authorization_reference,
        "starts_at": now.isoformat(), "expires_at": (now + timedelta(hours=1)).isoformat(),
        "targets": targets, "limits": {"max_requests": requests,
            "interval_seconds": policy.interval_seconds, "concurrency": 1,
            "timeout_seconds": timeout + 30 + spacing}, "stop_file": "emergency-stop", "steps": steps}
    destination.mkdir(mode=0o700)
    private_write(destination / "protocol.json", protocol)
    private_write(destination / "bindings.json", {"schema_version": 1, "steps": {
        "assess": binding, "evidence": {}, "report": {}}})
    plan = execution_plan(profile, destination / "protocol.json", destination / "bindings.json")
    private_write(destination / "execution-plan.json", plan)
    return plan
