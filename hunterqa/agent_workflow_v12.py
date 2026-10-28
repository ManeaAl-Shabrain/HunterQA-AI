"""Constrained specialist-agent plans and evidence correlation for HunterQA v1.2.

Agents are *roles and policy-checked tasks*, not shells. LLM output is never
executed, never supplies a tool name, and never overrides the scope policy.
All tasks in this module are planning and offline analyst work.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

from .bounty import BountyPolicy, _approved_file, _read_json, MAX_TARGET_LIST
from .api_surface_v12 import inspect_openapi

SKILLS = (
    {"id": "scope-guard", "mission": "Validate exact authorized program scope and stop conditions.",
     "tool": "bounty-preflight", "execution": "offline", "risk": "low"},
    {"id": "api-reviewer", "mission": "Identify API authorization and business-logic review candidates from a local OpenAPI contract.",
     "tool": "bounty-api-inventory", "execution": "offline", "risk": "low"},
    {"id": "source-reviewer", "mission": "Correlate authorized local source patterns and trust boundaries.",
     "tool": "bounty-campaign", "execution": "explicit_local_authorization", "risk": "review"},
    {"id": "advisory-reviewer", "mission": "Distinguish supported CVE aliases from installed vulnerabilities using an offline snapshot.",
     "tool": "cve-check", "execution": "offline", "risk": "low"},
    {"id": "capture-reviewer", "mission": "Review already captured, sanitized, in-scope proxy evidence offline.",
     "tool": "bounty-import-har", "execution": "offline", "risk": "low"},
    {"id": "verification-reviewer", "mission": "Correlate independently sourced observations without claiming exploitation.",
     "tool": "bounty-correlate", "execution": "offline", "risk": "review"},
    {"id": "report-reviewer", "mission": "Prepare a human-reviewed disclosure draft without automatic submission.",
     "tool": "bounty-report", "execution": "offline", "risk": "manual"},
)
SKILL_BY_ID = {skill["id"]: skill for skill in SKILLS}
MAX_EVIDENCE_FILES = 8
KNOWN_ENGINES = {"hunterqa_authorized_bounty_observation", "hunterqa_v12_offline_api_surface"}
KNOWN_RULES = {
    "header.hsts.absent": "HSTS configuration review",
    "header.nosniff.absent": "Content-type sniffing prevention review",
    "header.csp.absent": "Content Security Policy review",
    "cookie.secure.absent": "Cookie Secure attribute review",
    "cookie.httponly.absent": "Cookie HttpOnly attribute review",
    "api.auth-declaration-review": "Declared API authorization policy review",
    "api.public-write-review": "Explicitly public API write review",
    "api.object-access-review": "Object-level authorization review",
    "api.business-logic-review": "Sensitive business workflow review",
    "api.deprecated-operation-review": "Deprecated API surface review",
}


def _digest(path):
    return hashlib.sha256(_approved_file(path).read_bytes()).hexdigest()


def plan(profile_path, *, api_spec=None, targets_path=None, authorized=False):
    if not authorized:
        raise PermissionError("Explicit --authorized required for engagement planning")
    policy = BountyPolicy.load(profile_path)
    operations = 0
    if api_spec is not None:
        api_report = inspect_openapi(api_spec, profile_path, authorized=True)
        operations = api_report["summary"]["operations"]
    target_count = 0
    if targets_path is not None:
        file = _approved_file(targets_path)
        if file.stat().st_size > MAX_TARGET_LIST:
            raise ValueError("Target list exceeds approved size")
        targets = [x.strip() for x in file.read_text(encoding="utf-8").splitlines()
                   if x.strip() and not x.lstrip().startswith("#")]
        if not targets or len(targets) > policy.max_requests:
            raise ValueError("Target count outside scope budget")
        for target in targets:
            policy.authorize_url(target, "HEAD")
        target_count = len(targets)
    steps = []
    def stage(role, depends, enabled, notes):
        skill = SKILL_BY_ID[role]
        steps.append({
            "id": f"step-{len(steps)+1:02d}",
            "agent_id": role, "tool": skill["tool"],
            "mission": skill["mission"], "execution": skill["execution"],
            "risk": skill["risk"], "dependencies": depends,
            "enabled": enabled, "notes": notes,
            "action": "human_review_only" if skill["risk"] in ("review", "manual")
                      else "operator_started_only",
            "network_requests_executed": 0,
        })
    stage("scope-guard", [], bool(target_count), "Offline exact-host and path authorization; no traffic")
    stage("api-reviewer", ["scope-guard"], api_spec is not None,
          "Offline OpenAPI mapping; route names do not prove vulnerabilities")
    stage("source-reviewer", [], True,
          "Existing local scanning and optional local Qwen are operator-initiated")
    stage("advisory-reviewer", [], True,
          "Only if a validated local OSV advisory snapshot is provided")
    stage("capture-reviewer", ["scope-guard"], True,
          "Already captured HAR from an authorized session only; no replay")
    stage("verification-reviewer", ["api-reviewer", "capture-reviewer"], True,
          "Multi-source correlation; still unverified until human reproduction")
    stage("report-reviewer", ["verification-reviewer"], True,
          "Draft is never automatically submitted to HackerOne or Bugcrowd")
    return {
        "schema_version": 1, "engine": "hunterqa_v12_approved_agent_plan",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "program": policy.program, "platform": policy.platform,
        "policy_sha256": _digest(profile_path),
        "metrics": {"approved_targets_preflighted": target_count,
                    "api_contract_operations": operations,
                    "network_requests_executed": 0, "autonomous_exploits_executed": 0,
                    "confirmed_zero_days": 0},
        "guardrails": {"operator_started_only": True, "no_shell_from_ai": True,
                       "no_evasion": True, "rate_limit": policy.interval_seconds,
                       "max_requests": policy.max_requests,
                       "human_approval_for_active_work": True},
        "skills": list(SKILLS), "steps": steps,
        "limitations": "Read-only task plan, no agent execution and no live network testing. "
                       "Untrusted LLM output is never treated as a command or authorization.",
    }


def correlate(profile_path, report_paths, *, authorized=False):
    """Merge only bounded, approved result types; preserve privacy and uncertainty."""
    if not authorized:
        raise PermissionError("Explicit --authorized required to review evidence")
    if not isinstance(report_paths, (list, tuple)) or not 1 <= len(report_paths) <= MAX_EVIDENCE_FILES:
        raise ValueError("Provide 1..8 local evidence files")
    policy = BountyPolicy.load(profile_path)
    profile_hash = _digest(profile_path)
    groups = {}
    input_summaries = []
    for path in report_paths:
        report = _read_json(path, 1_000_000)
        if not isinstance(report, dict) or report.get("engine") not in KNOWN_ENGINES:
            raise ValueError("Unsupported evidence engine; refuse arbitrary input")
        if report.get("policy_sha256") != profile_hash or report.get("program") != policy.program:
            raise ValueError("Evidence scope provenance differs from current program")
        engine = report["engine"]
        source_hash = _digest(path)
        candidates = (report.get("review_candidates") if engine == "hunterqa_v12_offline_api_surface"
                      else report.get("findings"))
        if not isinstance(candidates, list) or len(candidates) > 250:
            raise ValueError("Invalid or oversized evidence candidates")
        accepted = 0
        for item in candidates:
            if not isinstance(item, dict):
                continue
            rule = item.get("rule_id") if engine == "hunterqa_v12_offline_api_surface" else item.get("id")
            if rule not in KNOWN_RULES:
                continue
            if engine == "hunterqa_v12_offline_api_surface":
                operation_id = item.get("operation_id")
                if not isinstance(operation_id, str) or not re.fullmatch(r"[a-f0-9]{16}", operation_id):
                    continue
                identity = f"api:{operation_id}"
            else:
                raw_url = item.get("source_url")
                if not isinstance(raw_url, str):
                    continue
                try:
                    policy.authorize_url(raw_url, "HEAD" if "HEAD" in policy.methods else "GET")
                except ValueError:
                    continue
                identity = "url:" + hashlib.sha256(raw_url.encode()).hexdigest()[:20]
            key = f"{rule}|{identity}"
            group = groups.setdefault(key, {
                "id": hashlib.sha256(key.encode()).hexdigest()[:20],
                "rule_id": rule, "title": KNOWN_RULES[rule],
                "target_ref_hash": hashlib.sha256(identity.encode()).hexdigest()[:20],
                "evidence": [],
                "confirmed_vulnerability": False, "confirmed_zero_day": False,
                "needs_human_review": True,
            })
            proof = {"source_engine": engine, "document_sha256": source_hash}
            if proof not in group["evidence"]:
                group["evidence"].append(proof)
            accepted += 1
        input_summaries.append({
            "engine": engine, "sha256": source_hash,
            "candidate_observations_accepted": accepted,
        })
    findings = []
    for group in groups.values():
        group["independent_document_count"] = len(group["evidence"])
        group["review_priority"] = ("corroboration_review" if len(group["evidence"]) > 1
                                    else "single_evidence_review")
        findings.append(group)
    findings.sort(key=lambda a: (-a["independent_document_count"], a["rule_id"], a["id"]))
    return {
        "schema_version": 1, "engine": "hunterqa_v12_evidence_correlation",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "program": policy.program, "policy_sha256": profile_hash,
        "summary": {"input_reports": len(input_summaries),
                    "deduplicated_review_candidates": len(findings),
                    "confirmed_vulnerabilities": 0, "confirmed_zero_days": 0},
        "inputs": input_summaries, "review_queue": findings[:200],
        "limitations": "Multiple observations improve prioritization but do NOT "
                       "establish exploitability, impact, independence or zero-day status. "
                       "Targets are hashed; bodies, credentials and raw URLs are omitted.",
    }



def dashboard_summary(plan_path=None, api_path=None, correlation_path=None):
    """Read administrator-selected local outputs only. Never launch an agent."""
    result = {"status": "not_configured", "program": "",
              "steps": [], "operations": 0, "api_candidates": 0,
              "review_candidates": 0, "corroboration_review": 0,
              "network_requests_executed": 0}
    checked = False
    try:
        if plan_path:
            d = _read_json(plan_path, 256_000)
            if (not isinstance(d, dict) or
                    d.get("engine") != "hunterqa_v12_approved_agent_plan" or
                    not isinstance(d.get("steps"), list) or len(d["steps"]) > 12):
                raise ValueError("Not a recognized agent plan")
            checked = True
            result["program"] = str(d.get("program") or "")[:100]
            result["steps"] = [{"agent_id": str(t.get("agent_id") or "")[:40],
                                "mission": SKILL_BY_ID[t["agent_id"]]["mission"],
                                "enabled": t.get("enabled") is True}
                               for t in d["steps"] if isinstance(t, dict)
                               and t.get("agent_id") in SKILL_BY_ID]
        if api_path:
            d = _read_json(api_path, 1_000_000)
            if not isinstance(d, dict) or d.get("engine") != "hunterqa_v12_offline_api_surface":
                raise ValueError("Not a recognized API inventory")
            checked = True
            meta = d.get("summary") if isinstance(d.get("summary"), dict) else {}
            result["operations"] = min(int(meta.get("operations", 0)), 500)
            result["api_candidates"] = min(int(meta.get("review_candidates", 0)), 250)
        if correlation_path:
            d = _read_json(correlation_path, 1_000_000)
            if (not isinstance(d, dict) or
                    d.get("engine") != "hunterqa_v12_evidence_correlation" or
                    not isinstance(d.get("review_queue"), list) or
                    len(d["review_queue"]) > 200):
                raise ValueError("Not a recognized evidence review queue")
            checked = True
            result["review_candidates"] = len(d["review_queue"])
            result["corroboration_review"] = sum(
                item.get("review_priority") == "corroboration_review"
                for item in d["review_queue"] if isinstance(item, dict))
        result["status"] = "ready" if checked else "not_configured"
    except (OSError, ValueError, UnicodeError, TypeError, KeyError):
        result["status"] = "unavailable"
        result["steps"] = []
    return result
