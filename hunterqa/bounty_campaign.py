"""One opt-in engagement manifest connecting existing HunterQA research engines.

Local SAST/graph/Ollama campaign is always separate from the optional HTTP
observation stage. CVE snapshot matching and HAR triage are offline.
All results remain candidates until analyst validation.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .bounty import BountyPolicy, _approved_file, MAX_TARGET_LIST, assess, import_har
from .campaign import run_campaign, _approved_roots, _approved_existing, _write_json
from .engines.cve_intel import run_cve_check


def _preflight_web(profile, targets_path, method):
    targets_file = _approved_file(targets_path)
    if targets_file.stat().st_size > MAX_TARGET_LIST:
        raise ValueError("Target list exceeds size limit")
    targets = [x.strip() for x in targets_file.read_text(encoding="utf-8").splitlines()
               if x.strip() and not x.lstrip().startswith("#")]
    if not targets or len(targets) > profile.max_requests:
        raise ValueError("Invalid or unapproved target budget")
    for target in targets:
        profile.authorize_url(target, method)
    return len(targets)


def run_bounty_campaign(project, out_dir, profile_path, *, authorized=False,
                        with_ai=False, with_web=False, targets_path=None,
                        method="HEAD", snapshot_path=None, har_path=None):
    if not authorized:
        raise PermissionError("Engagement requires explicit --authorized")
    policy = BountyPolicy.load(profile_path)
    roots = _approved_roots()
    source = _approved_existing(project, roots, directory=True)
    if snapshot_path:
        _approved_file(snapshot_path)
    if har_path:
        _approved_file(har_path)
    if with_web:
        if not targets_path:
            raise ValueError("--with-web requires a local explicit --targets list")
        _preflight_web(policy, targets_path, method)
    elif targets_path is not None:
        raise ValueError("Targets are supplied only when --with-web is explicit")

    local = run_campaign(source, out_dir, authorized=True, include_ai=with_ai)
    output = Path(local["output_directory"])
    stages = {"local": {"status": "completed" if local["summary"]["failed_stages"] == 0
                        else "partial", "stages": local["stages"]}}
    summary = {"source_candidates": int(local["summary"].get("research_records", 0)),
               "advisory_records": 0, "unique_cve_groups": 0,
               "http_observations": 0, "web_candidate_observations": 0,
               "zero_days_confirmed": 0}

    def stage(name, action):
        try:
            result = action()
            data = (json.dumps(result, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
            if len(data) > 2_000_000:
                raise ValueError("Engagement artifact too large")
            digest = _write_json(output / f"{name}.json", result)
            stages[name] = {"status": "completed", "sha256": digest, "file": f"{name}.json"}
            return result
        except Exception as exc:
            stages[name] = {"status": "failed", "error_type": type(exc).__name__}
            return None

    if snapshot_path:
        result = stage("bounty_cve", lambda: run_cve_check(source, snapshot_path))
        if result:
            summary["advisory_records"] = len(result.get("matches", []))
            summary["unique_cve_groups"] = len(result.get("cve_groups", []))
    if har_path:
        result = stage("bounty_har", lambda: import_har(profile_path, har_path, authorized=True))
        if result:
            summary["http_observations"] += len(result.get("observations", []))
            summary["web_candidate_observations"] += len(result.get("findings", []))
    if with_web:
        result = stage("bounty_http", lambda: assess(
            profile_path, targets_path, authorized=True, method=method
        ))
        if result:
            summary["http_observations"] += len(result.get("observations", []))
            summary["web_candidate_observations"] += len(result.get("findings", []))

    manifest = {
        "schema_version": 1,
        "engine": "hunterqa_authorized_bounty_campaign",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "program": policy.program, "platform": policy.platform,
        "local_project": str(source),
        "policy_sha256": hashlib.sha256(_approved_file(profile_path).read_bytes()).hexdigest(),
        "stages": stages, "summary": summary,
        "claims": {"confirmed_vulnerabilities": 0, "confirmed_zero_days": 0,
                   "assigned_cves": 0, "false_positive_free": False},
        "human_review_required": True,
        "limitations": (
            "Local research candidates, advisory matches and HTTP observations "
            "are not confirmed security vulnerabilities. Unknown zero-days "
            "require independent controlled reproduction, impact review and "
            "coordinated disclosure."
        ),
    }
    _write_json(output / "engagement.json", manifest)
    return {"output_directory": str(output), **manifest}
