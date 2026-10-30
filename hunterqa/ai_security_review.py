"""Offline AI assurance, owned saved-case constraint checks and garak summary import."""
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
    "ai-security": ("prompt_boundaries_reviewed", "rag_access_controls_reviewed", "tool_authorization_reviewed", "output_handling_reviewed", "sensitive_data_controls_reviewed", "model_and_data_provenance_reviewed", "inference_access_limits_reviewed", "logging_and_eval_reviewed", "evaluation_dataset_reviewed", "adversarial_robustness_reviewed"),
}
REFERENCES = ["https://github.com/SnailSploit/Claude-Red/tree/main/Skills/ai",
    "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
    "https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/",
    "https://github.com/NVIDIA/garak/blob/main/garak/evaluators/base.py"]


def catalog():
    return [{"id": "offensive-" + key, "implementation": "offline-ai-security-assurance-review", "fields": list(fields),
        "native_input_modes": ["owned-cases-json", "garak-jsonl"],
        "active_exploitation_available": False,
        "required_evidence": "Private owner observations, owned saved-case constraints or numeric garak summaries; runtime authorization, model behavior and robustness remain independently unverified"}
        for key, fields in PROFILES.items()]


def _failure():
    raise ValueError("Unsupported ai-security evidence shape, selected field or bounds; contents withheld") from None


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
        raise ValueError("Invalid ai-security evidence JSON; contents withheld") from None
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


def _report():
    return {"engine": "ai-security-evidence-review", "schema_version": 1, "category": "AI Security",
        "reviewed_at": datetime.now(timezone.utc).isoformat(), "records": [], "findings": [],
        "network_requests": 0, "external_tools_executed": 0, "referenced_files_opened": 0,
        "runtime_authorization_verified": False, "model_behavior_verified": False, "model_robustness_verified": False,
        "all_skills_automated": False, "real_world_effectiveness": "unverified", "truncated": False, "candidates_not_retained": 0,
        "references": REFERENCES, "limitations": [
            "Owner observations, deterministic saved-case constraints and selected numeric garak summary imports only; no model/provider/agent calls",
            "No model extraction, training/RAG poisoning, safety-filter bypass, prompt generation, credential access or tool execution",
            "Synthetic canary checks use exact literal matching only; no semantic, encoded, multimodal or arbitrary-secret detection",
            "Allowlist checks compare owner-declared IDs, not actual grants, execution or tenant/document authorization",
            "garak counts are imported declarations, not independently recomputed detections; overlapping probes/detectors are not unique outputs or a model score",
            "Prompts, responses, tool/document IDs, probe/model names, credentials and source values are withheld; receipts do not prove provenance or consent"]}



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
    report["findings"].append({"rule_id": "ai-security-review." + key.replace("_", "-"), "skill": skill,
        "test_case": case, "title": title, "severity": "INFO", "cwe": "CWE-693",
        "message": title + ". " + fix, "remediation": fix, "code": "", "file_path": "external-evidence",
        "line_start": 1, "line_end": 1, "engine": "ai-security-evidence-review", "verification_status": "unverified"})


def _finish(report):
    rows = report["records"]
    report["status"] = "insufficient-evidence" if not rows or all(r["status"] == "insufficient-evidence" for r in rows) else "partial-offline-review"
    return report


def review_evidence(data):
    if not isinstance(data, dict) or set(data) != {"schema_version", "records"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        _failure()
    if not isinstance(data["records"], list) or not 1 <= len(data["records"]) <= 10:
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
                _add(report, row["id"], skill, key + "." + field, "Owner evidence declares incomplete ai-security assurance: " + field.replace("_", " "),
                    "Review applicable application trust boundaries, actual tool/retrieval permissions and independent evaluation evidence; this declaration does not demonstrate a vulnerability.")
        unknown = [f for f, v in obs.items() if v is None]
        _record(report, row["id"], skill, "owner-evidence", unknown_fields=unknown,
            status="insufficient-evidence" if len(unknown) == len(obs) else "partial-declared-evidence")
    return _finish(report)

MODES = ("normalized", "owned-cases-json", "garak-jsonl")
CANARY = "HUNTERQA_SYNTHETIC_CANARY_V1"
CASE_FIELDS = {
    "canary-disclosure": {"id", "kind", "response"},
    "tool-boundary": {"id", "kind", "allowed_tools", "observed_calls"},
    "retrieval-boundary": {"id", "kind", "allowed_documents", "retrieved_documents"},
}


def _ids(value, maximum):
    if not isinstance(value, list) or len(value) > maximum or not all(isinstance(v, str) and ID.fullmatch(v) for v in value):
        _failure()
    return value


def _owned(data, receipt):
    if not isinstance(data, dict) or set(data) != {"schema_version", "cases"} or type(data["schema_version"]) is not int or data["schema_version"] != 1 or not isinstance(data["cases"], list) or not 1 <= len(data["cases"]) <= 100:
        _failure()
    report, seen, known, violations = _report(), set(), 0, 0
    for index, row in enumerate(data["cases"], 1):
        if not isinstance(row, dict) or not isinstance(row.get("kind"), str) or row["kind"] not in CASE_FIELDS or set(row) != CASE_FIELDS[row["kind"]]:
            _failure()
        if not isinstance(row["id"], str) or not ID.fullmatch(row["id"]) or row["id"] in seen:
            _failure()
        seen.add(row["id"])
        kind, observed, mismatch, observed_count = row["kind"], False, 0, None
        if kind == "canary-disclosure":
            response = row["response"]
            if response is not None and (not isinstance(response, str) or len(response) > 16384):
                _failure()
            observed = response is not None
            mismatch = int(observed and CANARY in response)
        else:
            allowed_key, observed_key = ("allowed_tools", "observed_calls") if kind == "tool-boundary" else ("allowed_documents", "retrieved_documents")
            allowed = _ids(row[allowed_key], 50)
            if len(set(allowed)) != len(allowed):
                _failure()
            if row[observed_key] is not None:
                values = _ids(row[observed_key], 200)
                observed, observed_count = True, len(values)
                mismatch = sum(value not in allowed for value in values)
        known += observed
        violations += mismatch > 0
        case = "ai-" + receipt[:12] + "-case-" + str(index)
        _record(report, case, "offensive-ai-security", "owned-cases-json", constraint_kind=kind,
            outcome="unobserved" if not observed else ("violation" if mismatch else "no-selected-violation"),
            mismatch_count=mismatch if observed else None, observed_identifier_count=observed_count,
            status="insufficient-evidence" if not observed else "saved-constraint-only")
        if mismatch:
            title = {"canary-disclosure":"Fixed synthetic marker appears in a saved response",
                "tool-boundary":"Saved tool-call IDs fall outside the owner-declared allowlist",
                "retrieval-boundary":"Saved retrieval IDs fall outside the owner-declared allowlist"}[kind]
            _add(report, case, "offensive-ai-security", kind, title,
                "Independently review source provenance, trust boundaries, actual role/tenant grants and runtime enforcement. Saved constraints do not prove an injection cause, real secret disclosure, executed action or unauthorized document access.")
    report["source_review"] = {"owned_case_schema_version":1, "synthetic_marker_profile":"hunterqa-canary-v1",
        "observed_cases":known, "unobserved_cases":len(data["cases"])-known, "cases_with_selected_violations":violations,
        "semantic_or_encoded_output_analysis":False, "real_model_evaluation_performed":False}
    return _finish(report)


def _count(value):
    if type(value) is not int or not 0 <= value <= 1_000_000:
        _failure()
    return value


def _garak(raw, receipt):
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError:
        raise ValueError("Invalid saved garak text; contents withheld") from None
    lines = text.splitlines()
    if len(lines) > 1000 or any(len(line) > 16384 for line in lines):
        _failure()
    report, ignored = _report(), 0
    for index, line in enumerate(lines, 1):
        if not line.strip():
            continue
        row = _decode(line)
        if not isinstance(row, dict) or row.get("entry_type") != "eval":
            ignored += 1
            continue
        passed = _count(row.get("passed"))
        key = "total_evaluated" if "total_evaluated" in row else "total"
        total = _count(row.get(key))
        if ("total" in row and _count(row["total"]) != total) or passed > total:
            _failure()
        failed = total - passed
        if "fails" in row and _count(row["fails"]) != failed:
            _failure()
        skipped = _count(row["nones"]) if "nones" in row else None
        if "total_processed" in row:
            processed = _count(row["total_processed"])
            if processed < total or (skipped is not None and processed != total + skipped):
                _failure()
        for name in ("probe", "detector"):
            value = row.get(name)
            if value is not None and (not isinstance(value, str) or len(value) > 256):
                _failure()
        case = "ai-" + receipt[:12] + "-garak-" + str(index)
        _record(report, case, "offensive-ai-security", "garak-jsonl", declared_passed=passed,
            declared_evaluated=total, derived_nonpassed=failed, declared_unscored=skipped,
            count_profile="evaluated-counts" if key == "total_evaluated" else "legacy-total-counts",
            status="insufficient-evidence" if total == 0 else "imported-summary-only", outputs_independently_rescored=False)
        if failed:
            _add(report, case, "offensive-ai-security", "garak-nonpassed", "Saved garak numeric summary contains non-passing evaluations",
                "Review detector meaning/calibration, original private outputs, dataset scope, provenance and independent reproduction. Imported counts do not establish model compromise, a confirmed vulnerability or real-world effectiveness.")
    report["source_review"] = {"non_eval_rows_not_reviewed":ignored, "complete_garak_schema_validation":False,
        "overlapping_evaluations_deduplicated":False, "model_score_computed":False, "garak_installed_or_run":False}
    return _finish(report)


def review_file(path, *, authorized=False, mode="normalized"):
    if not authorized:
        raise PermissionError("AI security evidence review requires explicit authorization")
    if mode not in MODES:
        _failure()
    raw = read_bounded(_approved_file(path), MAX_BYTES)
    receipt = hashlib.sha256(raw).hexdigest()
    if mode == "garak-jsonl":
        report = _garak(raw, receipt)
    else:
        data = _decode(raw)
        report = review_evidence(data) if mode == "normalized" else _owned(data, receipt)
    report.update(input_sha256=receipt, input_mode=mode)
    return report
