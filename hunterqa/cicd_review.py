"""Offline CI/CD assurance and selected GitHub Actions JSON declarations."""
from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone

from .bounty import _approved_file
from .source_files import read_bounded

MAX_BYTES = 1_048_576
MAX_FINDINGS = 500
ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
PROFILES = {
    "cicd-pipeline": ("trust_boundaries_reviewed", "dependencies_pinned", "least_privilege_reviewed", "runner_isolation_reviewed", "deployment_approvals_reviewed"),
    "cicd-secrets": ("secret_scope_reviewed", "log_redaction_reviewed", "oidc_trust_reviewed", "artifact_retention_reviewed", "rotation_reviewed"),
}
REFERENCES = ["https://github.com/SnailSploit/Claude-Red/tree/main/Skills/cicd",
    "https://docs.github.com/en/actions/reference/security/secure-use",
    "https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax"]


def catalog():
    return [{"id": "offensive-" + key, "implementation": "offline-cicd-assurance-review", "fields": list(fields),
        "native_json_modes": ["github-actions-json"],
        "active_exploitation_available": False,
        "required_evidence": "Private owner observations or saved GitHub Actions JSON; actual permissions, isolation and secret protection remain unverified"}
        for key, fields in PROFILES.items()]


def _failure():
    raise ValueError("Unsupported cicd evidence shape, selected field or bounds; contents withheld") from None


def _decode(raw):
    def pairs(entries):
        out = {}
        for key, value in entries:
            if key in out:
                _failure()
            out[key] = value
        return out

    def constant(_):
        _failure()

    try:
        data = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Invalid cicd evidence JSON; contents withheld") from None
    stack, count = [(data, 0)], 0
    while stack:
        value, depth = stack.pop()
        count += 1
        if count > 20000 or depth > 40 or (isinstance(value, float) and not math.isfinite(value)):
            _failure()
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
    return data


def _list(value, maximum=100):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > maximum:
        _failure()
    return value


def _report():
    return {"engine": "cicd-evidence-review", "schema_version": 1, "category": "CI/CD & Pipelines",
        "reviewed_at": datetime.now(timezone.utc).isoformat(), "records": [], "findings": [],
        "network_requests": 0, "external_tools_executed": 0, "referenced_files_opened": 0,
        "effective_permissions_verified": False, "secret_protection_verified": False,
        "all_skills_automated": False, "real_world_effectiveness": "unverified", "truncated": False, "candidates_not_retained": 0,
        "references": REFERENCES, "limitations": [
            "Selected offline GitHub Actions JSON declarations only; no YAML parsing or complete workflow validation",
            "No workflow execution, expression evaluation, external action/include resolution, secret extraction or runner access",
            "Repository/org defaults, event restrictions, environments, runner isolation and cloud OIDC trust remain unverified",
            "Jenkins, GitLab and Azure DevOps use owner-observation contracts only; no native parser",
            "Static cues require independent review and do not demonstrate a vulnerability or safe execution",
            "Source names, commands, action references, inputs and secret values are withheld; hashes do not establish provenance or consent"]}


def _record(report, case, skill, context, **fields):
    if len(report["records"]) >= 2000:
        _failure()
    row = {"case": case, "skill": skill, "context": context, "status": "selected-declaration-only", **fields}
    report["records"].append(row)
    return row


def _add(report, case, skill, key, title, fix):
    if len(report["findings"]) >= MAX_FINDINGS:
        report["truncated"] = True
        report["candidates_not_retained"] += 1
        return
    report["findings"].append({"rule_id": "cicd-review." + key.replace("_", "-"), "skill": skill,
        "test_case": case, "title": title, "severity": "INFO", "cwe": "CWE-693",
        "message": title + ". " + fix, "remediation": fix, "code": "", "file_path": "external-evidence",
        "line_start": 1, "line_end": 1, "engine": "cicd-evidence-review", "verification_status": "unverified"})


def _finish(report):
    rows = report["records"]
    report["status"] = "insufficient-evidence" if not rows or all(r["status"] == "insufficient-evidence" for r in rows) else "partial-offline-review"
    return report


def review_evidence(data):
    if not isinstance(data, dict) or set(data) != {"schema_version", "records"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        _failure()
    if not isinstance(data["records"], list) or not 1 <= len(data["records"]) <= 20:
        _failure()
    report, ids, counts = _report(), set(), {}
    for row in data["records"]:
        if not isinstance(row, dict) or set(row) != {"id", "skill", "observations"}:
            _failure()
        if not isinstance(row["id"], str) or not ID.fullmatch(row["id"]) or row["id"] in ids:
            _failure()
        ids.add(row["id"])
        skill, obs = row["skill"], row["observations"]
        if not isinstance(skill, str) or not skill.startswith("offensive-") or skill[10:] not in PROFILES:
            _failure()
        key = skill[10:]
        counts[key] = counts.get(key, 0) + 1
        if counts[key] > 10 or not isinstance(obs, dict) or set(obs) != set(PROFILES[key]) or not all(v is None or type(v) is bool for v in obs.values()):
            _failure()
        for field, value in obs.items():
            if value is False:
                _add(report, row["id"], skill, key + "." + field, "Owner evidence declares incomplete cicd assurance: " + field.replace("_", " "),
                    "Review applicable pipeline configuration and independent evidence; this declaration does not demonstrate a vulnerability.")
        unknown = [f for f, v in obs.items() if v is None]
        _record(report, row["id"], skill, "owner-evidence", unknown_fields=unknown,
            status="insufficient-evidence" if len(unknown) == len(obs) else "partial-declared-evidence")
    return _finish(report)



def _permissions(report, case, value, skill):
    if value is None:
        return "unknown-default"
    if isinstance(value, str) and value in ("read-all", "write-all"):
        if value == "write-all":
            _add(report, case, skill, "permissions-write-all", "All token permissions requested writable", "Replace broad permissions with reviewed job-specific requirements; effective permissions depend on external policy.")
        return value
    if not isinstance(value, dict) or not all(isinstance(k, str) and v in ("read", "write", "none") for k, v in value.items()):
        _failure()
    if any(v == "write" for v in value.values()):
        _add(report, case, skill, "permissions-write", "Selected token permissions requested writable", "Independently review each write permission, including OIDC issuance, against job responsibilities and trust boundaries.")
    return "explicit-map"


def _uses(report, case, value):
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        _failure()
    if value.startswith("./"):
        return
    if "${{" in value:
        key, title = "unresolved-action", "Action or workflow reference contains an unresolved expression"
    elif value.startswith("docker://"):
        if re.fullmatch(r"docker://[^\s@]+@sha256:[0-9a-fA-F]{64}", value):
            return
        key, title = "image-not-digest", "Action image is not pinned to a selected digest form"
    elif re.fullmatch(r"[^\s@]+/[^\s@]+@[0-9a-fA-F]{40}", value):
        return
    else:
        key, title = "action-not-sha", "Remote action or reusable workflow is not pinned to a full commit SHA"
    _add(report, case, "offensive-cicd-pipeline", key, title,
        "Review provenance and pin a reviewed immutable reference; local actions and full SHA/digest syntax alone do not establish trust.")


UNTRUSTED = re.compile(r"\$\{\{[^}]*\bgithub\s*\.\s*(?:event\s*\.\s*(?:issue|pull_request|comment|review|discussion|head_commit|commits)|head_ref)\b", re.I)


def _github(data, receipt):
    if not isinstance(data, dict) or not isinstance(data.get("jobs"), dict) or not 1 <= len(data["jobs"]) <= 100:
        _failure()
    report = _report()
    # Presence is distinct from an inherited setting, including malformed nulls.
    if "permissions" in data and data["permissions"] is None:
        _failure()
    base = data.get("permissions")
    _permissions(report, "ci-" + receipt[:12] + "-workflow", base, "offensive-cicd-pipeline")
    events = data.get("on")
    if events is not None and not isinstance(events, (str, list, dict)):
        _failure()
    if isinstance(events, list) and not all(isinstance(v, str) for v in events):
        _failure()
    elevated = events == "pull_request_target" or isinstance(events, (list, dict)) and "pull_request_target" in events
    total_steps = 0
    for index, job in enumerate(data["jobs"].values(), 1):
        if not isinstance(job, dict):
            _failure()
        case = "ci-" + receipt[:12] + "-job-" + str(index)
        if "permissions" in job and job["permissions"] is None:
            _failure()
        context = _permissions(report, case, job.get("permissions", base), "offensive-cicd-pipeline")
        _record(report, case, "offensive-cicd-pipeline", "github-actions-json", permissions_declaration=context,
            event_context_known=events is not None, runner_isolation_verified=False, environment_approvals_verified=False)
        if elevated:
            _add(report, case, "offensive-cicd-pipeline", "privileged-event", "Workflow declares pull-request-target execution context",
                "Review untrusted checkout, inputs and job conditions independently before allowing privileged execution; no exploit is demonstrated.")
        if "uses" in job:
            if "steps" in job:
                _failure()
            _uses(report, case, job["uses"])
        secrets = job.get("secrets")
        if secrets is not None and not isinstance(secrets, (str, dict)):
            _failure()
        if isinstance(secrets, str):
            if secrets != "inherit":
                _failure()
            _add(report, case, "offensive-cicd-secrets", "secrets-inherit", "Reusable workflow receives inherited secrets",
                "Prefer explicitly selected secret mappings and review the called workflow and environment; secret values are neither read nor reported.")
        steps = _list(job.get("steps"), 200)
        total_steps += len(steps)
        if total_steps > 1000:
            _failure()
        for n, step in enumerate(steps, 1):
            if not isinstance(step, dict) or not ("uses" in step or "run" in step) or "uses" in step and "run" in step:
                _failure()
            c = case + "-step-" + str(n)
            if "uses" in step:
                _uses(report, c, step["uses"])
            if "run" in step:
                run = step["run"]
                if not isinstance(run, str) or len(run) > 32768:
                    _failure()
                if UNTRUSTED.search(run):
                    _add(report, c, "offensive-cicd-pipeline", "untrusted-script-context", "Script directly interpolates a selected untrusted event context",
                        "Pass untrusted input through carefully handled environment variables and review shell/context boundaries; the static cue does not prove injection.")
    report["source_review"] = {"jobs_reviewed": len(data["jobs"]), "steps_reviewed": total_steps,
        "complete_workflow_validation": False, "expressions_evaluated": False, "secret_leak_detection_performed": False,
        "native_source_line_locations_available": False}
    return _finish(report)


def review_file(path, *, authorized=False, mode="normalized"):
    if not authorized:
        raise PermissionError("CI/CD evidence review requires explicit authorization")
    if mode not in ("normalized", "github-actions-json"):
        _failure()
    raw = read_bounded(_approved_file(path), MAX_BYTES)
    data, receipt = _decode(raw), hashlib.sha256(raw).hexdigest()
    report = review_evidence(data) if mode == "normalized" else _github(data, receipt)
    report.update(input_sha256=receipt, input_mode=mode)
    return report
