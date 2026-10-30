"""Offline utility assurance, report quality review and CVSS 3.1 Base arithmetic."""
from __future__ import annotations

from decimal import Decimal, ROUND_CEILING, localcontext

import hashlib
import json
import math
import re
from datetime import datetime, timezone

from .bounty import _approved_file
from .source_files import read_bounded

MAX_BYTES = 2_000_000
MAX_FINDINGS = 500
ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
PROFILES = {
    "fast-checking": ("scope_and_budget_reviewed", "coverage_gaps_reviewed", "evidence_triage_reviewed", "false_positive_controls_reviewed", "validation_approval_reviewed", "handoff_priority_reviewed"),
    "reporting": ("scope_and_limitations_reviewed", "executive_summary_reviewed", "finding_evidence_reviewed", "severity_justification_reviewed", "remediation_reviewed", "retest_status_reviewed", "redaction_and_delivery_reviewed"),
}
REFERENCES = ["https://github.com/SnailSploit/Claude-Red/tree/main/Skills/utility",
    "https://www.first.org/cvss/v3.1/specification-document", "https://www.first.org/cvss/v3.1/examples"]


def catalog():
    return [{"id": "offensive-" + key, "implementation": "offline-utility-assurance-review", "fields": list(fields),
        "native_input_modes": ["finding-report-json"],
        "active_exploitation_available": False,
        "required_evidence": "Private owner observations or saved finding metadata; evidence contents, analyst verdicts, business priority and metric justification remain unverified"}
        for key, fields in PROFILES.items()]


def _failure():
    raise ValueError("Unsupported utility evidence shape, selected field or bounds; contents withheld") from None


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
        raise ValueError("Invalid utility evidence JSON; contents withheld") from None
    stack, count = [(data, 0)], 0
    while stack:
        value, depth = stack.pop()
        count += 1
        if count > 60000 or depth > 40 or (isinstance(value, float) and not math.isfinite(value)):
            _failure()
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
    return data


def _report():
    return {"engine": "utility-evidence-review", "schema_version": 1, "category": "Utility",
        "reviewed_at": datetime.now(timezone.utc).isoformat(), "records": [], "findings": [],
        "network_requests": 0, "external_tools_executed": 0, "referenced_files_opened": 0,
        "evidence_contents_verified": False, "analyst_verdicts_verified": False, "metric_justification_verified": False,
        "all_skills_automated": False, "real_world_effectiveness": "unverified", "truncated": False, "candidates_not_retained": 0,
        "references": REFERENCES, "limitations": [
            "Selected local report metadata, owner observations and CVSS 3.1 Base vector arithmetic only; no target requests or automatic validation",
            "Evidence references, hashes, reviewer labels and duplicate contexts are declarations; no referenced artifact, URL or source file is opened",
            "No automatic finding confirmation, deletion, remediation, deduplication, business-risk ranking, publication or external submission",
            "CVSS arithmetic does not justify metric choices or establish exploitability; CVSS 4.0, Temporal and Environmental scoring are unsupported",
            "Metadata completeness is not report accuracy or customer-delivery approval; unknown fields and missing context remain unverified",
            "Client titles, paths, rule/target/case IDs, evidence values, notes and remediation text are withheld; receipts do not prove provenance or consent"]}



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
    report["findings"].append({"rule_id": "utility-review." + key.replace("_", "-"), "skill": skill,
        "test_case": case, "title": title, "severity": "INFO", "cwe": "CWE-693",
        "message": title + ". " + fix, "remediation": fix, "code": "", "file_path": "external-evidence",
        "line_start": 1, "line_end": 1, "engine": "utility-evidence-review", "verification_status": "unverified"})


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
                _add(report, row["id"], skill, key + "." + field, "Owner evidence declares incomplete utility assurance: " + field.replace("_", " "),
                    "Review applicable scope, evidence completeness, severity justification and independent analyst review; this declaration does not demonstrate a vulnerability.")
        unknown = [f for f, v in obs.items() if v is None]
        _record(report, row["id"], skill, "owner-evidence", unknown_fields=unknown,
            status="insufficient-evidence" if len(unknown) == len(obs) else "partial-declared-evidence")
    return _finish(report)

CVSS_METRICS = {"AV":"NALP", "AC":"LH", "PR":"NLH", "UI":"NR", "S":"UC", "C":"NLH", "I":"NLH", "A":"NLH"}
SEVERITIES = {"NONE", "INFO", "INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL", "WARNING", "ERROR"}
VERIFICATIONS = {"unverified", "needs-review", "confirmed", "false-positive", "remediated"}


def cvss31(vector):
    """FIRST CVSS v3.1 Base equations, using exact decimal arithmetic for Roundup.

    CVSS is owned by FIRST.Org, Inc. and used by permission. Return vector and
    score together; caller choices are not independently verified.
    """
    if not isinstance(vector, str) or len(vector) > 128:
        _failure()
    pieces = vector.split("/")
    if len(pieces) != 9 or pieces[0] != "CVSS:3.1":
        _failure()
    metrics = {}
    for piece in pieces[1:]:
        key, separator, value = piece.partition(":")
        if not separator or key not in CVSS_METRICS or key in metrics or len(value) != 1 or value not in CVSS_METRICS[key]:
            _failure()
        metrics[key] = value
    if set(metrics) != set(CVSS_METRICS):
        _failure()
    with localcontext() as context:
        context.prec = 120
        d = Decimal
        impacts = {"N":d("0"), "L":d("0.22"), "H":d("0.56")}
        iss = 1 - (1-impacts[metrics["C"]]) * (1-impacts[metrics["I"]]) * (1-impacts[metrics["A"]])
        changed = metrics["S"] == "C"
        impact = d("7.52")*(iss-d("0.029"))-d("3.25")*(iss-d("0.02"))**15 if changed else d("6.42")*iss
        av = {"N":"0.85", "A":"0.62", "L":"0.55", "P":"0.20"}[metrics["AV"]]
        ac = {"L":"0.77", "H":"0.44"}[metrics["AC"]]
        pr = {"N":"0.85", "L":"0.68" if changed else "0.62", "H":"0.50" if changed else "0.27"}[metrics["PR"]]
        ui = {"N":"0.85", "R":"0.62"}[metrics["UI"]]
        exploitability = d("8.22")*d(av)*d(ac)*d(pr)*d(ui)
        unrounded = min(d("10"), (impact+exploitability)*(d("1.08") if changed else d("1")))
        score = d("0") if impact <= 0 else (unrounded*10).to_integral_value(rounding=ROUND_CEILING)/10
        severity = "NONE" if score == 0 else ("LOW" if score < 4 else ("MEDIUM" if score < 7 else ("HIGH" if score < 9 else "CRITICAL")))
    return {"profile":"CVSS:3.1-Base", "vector":"CVSS:3.1/"+"/".join(k+":"+metrics[k] for k in CVSS_METRICS),
        "base_score":float(score), "base_severity":severity, "metric_justification_verified":False,
        "attribution":"CVSS is owned by FIRST.Org, Inc. and used by permission",
        "reference":"https://www.first.org/cvss/v3.1/specification-document"}


def _text(value, maximum=4096):
    if value is not None and (not isinstance(value, str) or len(value) > maximum):
        _failure()
    return value


def _report_quality(data, receipt):
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list) or len(data["findings"]) > 1000:
        _failure()
    if "truncated" in data and type(data["truncated"]) is not bool:
        _failure()
    report, contexts = _report(), {}
    for index, finding in enumerate(data["findings"], 1):
        if not isinstance(finding, dict):
            _failure()
        case = "util-" + receipt[:12] + "-finding-" + str(index)
        texts = {key:_text(finding.get(key), 16384 if key in ("title", "remediation", "cvss_justification") else 4096)
            for key in ("title", "remediation", "verification_status", "rule_id", "file_path", "target_ref_hash", "test_case", "test_role", "cvss_vector", "cvss_justification")}
        missing = [key for key in ("title", "remediation", "verification_status", "rule_id") if not texts[key] or not texts[key].strip()]
        verification = texts["verification_status"] if texts["verification_status"] in VERIFICATIONS else "unknown"
        severity = _text(finding.get("severity"), 64)
        severity = severity.upper() if severity and severity.upper() in SEVERITIES else "unknown"
        evidence = finding.get("evidence")
        if evidence is not None and not isinstance(evidence, (str, list, dict)):
            _failure()
        if (isinstance(evidence, list) and len(evidence) > 20) or (isinstance(evidence, str) and len(evidence) > 16384):
            _failure()
        evidence_declared = bool(evidence)
        duplicate = None
        line = finding.get("line_start")
        if line is not None and (type(line) is not int or not 1 <= line <= 10_000_000):
            _failure()
        target = texts["target_ref_hash"]
        has_target = bool(target and re.fullmatch(r"[0-9a-fA-F]{64}", target))
        has_file = bool(texts["file_path"] and texts["file_path"] != "external-evidence")
        if texts["rule_id"] and line is not None and (has_target or has_file):
            identity = tuple(texts[key] for key in ("rule_id", "file_path", "target_ref_hash", "test_case", "test_role"))+(line,)
            duplicate = contexts.get(identity)
            contexts.setdefault(identity, case)
        vector, declared_score = texts["cvss_vector"], finding.get("cvss_score")
        if declared_score is not None and (type(declared_score) not in (int, float) or not 0 <= declared_score <= 10 or not math.isfinite(declared_score)):
            _failure()
        cvss_state, score_matches, label_matches = "not-provided", None, None
        if vector:
            try:
                scored = cvss31(vector)
            except ValueError:
                cvss_state = "outside-supported-base-profile"
            else:
                cvss_state = "supported-vector-arithmetic-only"
                if declared_score is not None:
                    score_matches = Decimal(str(declared_score)) == Decimal(str(scored["base_score"]))
                if severity in ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
                    label_matches = severity == scored["base_severity"]
        _record(report, case, "offensive-reporting", "finding-report-json", missing_metadata_fields=missing,
            evidence_metadata_declared=evidence_declared, verification_declaration=verification,
            severity_declaration=severity, possible_duplicate_of_case=duplicate, cvss_metadata_state=cvss_state,
            declared_base_score_matches_vector=score_matches, declared_severity_matches_vector=label_matches,
            cvss_justification_declared=bool(texts["cvss_justification"] and texts["cvss_justification"].strip()))
        cues = [(bool(missing), "missing-metadata", "Source finding lacks selected reporting metadata"),
            (not evidence_declared, "evidence-metadata-missing", "Source finding has no declared evidence metadata"),
            (verification == "unknown", "verification-unknown", "Source finding lacks a recognized verification declaration"),
            (severity == "unknown", "severity-unknown", "Source finding lacks a recognized severity declaration"),
            (duplicate is not None, "possible-duplicate", "Source finding repeats selected exact source-context metadata"),
            (cvss_state == "outside-supported-base-profile", "cvss-profile-review", "Source vector is outside this selected complete CVSS 3.1 Base profile"),
            (declared_score is not None and not vector, "score-without-vector", "Source declares a CVSS score without a supporting vector"),
            (score_matches is False, "cvss-score-mismatch", "Source base score differs from supplied CVSS 3.1 vector arithmetic"),
            (label_matches is False, "cvss-label-mismatch", "Source severity label differs from supplied CVSS 3.1 Base severity"),
            (bool(vector) and not (texts["cvss_justification"] and texts["cvss_justification"].strip()), "cvss-justification-missing", "Source vector lacks declared metric justification")]
        for condition, key, title in cues:
            if condition:
                _add(report, case, "offensive-fast-checking" if key == "possible-duplicate" else "offensive-reporting", key, title,
                    "Review the original private report, source scope, evidence provenance, analyst decisions and justified severity. Completeness, arithmetic and exact metadata matches do not confirm vulnerabilities, prove evidence, authorize publication or justify deleting findings.")
    if data.get("truncated"):
        _add(report, "util-"+receipt[:12]+"-source", "offensive-fast-checking", "source-truncated", "Source report declares truncated output",
            "Review retained limits and missing coverage in the original report; do not treat the visible findings as a complete assessment.")
    report["source_review"] = {"input_findings":len(data["findings"]), "source_truncation_declared":bool(data.get("truncated")),
        "possible_duplicate_contexts":sum(r["possible_duplicate_of_case"] is not None for r in report["records"]),
        "findings_removed_or_promoted":False, "evidence_references_opened":False, "complete_report_validation":False,
        "cvss_scores_published_by_lint":False}
    return _finish(report)


def render_markdown(report):
    """Render only generated quality fields; never source report text or links."""
    if not isinstance(report, dict) or report.get("engine") != "utility-evidence-review" or report.get("input_mode") != "finding-report-json":
        _failure()
    if not isinstance(report.get("input_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", report["input_sha256"]) or not isinstance(report.get("records"), list) or len(report["records"]) > 1000:
        _failure()
    if not isinstance(report.get("findings"), list) or len(report["findings"]) > MAX_FINDINGS or type(report.get("truncated")) is not bool or type(report.get("candidates_not_retained")) is not int or not 0 <= report["candidates_not_retained"] <= 20000:
        _failure()
    for row in report["records"]:
        if not isinstance(row, dict) or not isinstance(row.get("case"), str) or not re.fullmatch(r"util-[0-9a-f]{12}-finding-[1-9][0-9]{0,3}", row["case"]):
            _failure()
        missing = row.get("missing_metadata_fields")
        if not isinstance(missing, list) or len(missing) > 4 or not all(v in ("title", "remediation", "verification_status", "rule_id") for v in missing):
            _failure()
        if type(row.get("evidence_metadata_declared")) is not bool or not isinstance(row.get("verification_declaration"), str) or row.get("verification_declaration") not in VERIFICATIONS | {"unknown"} or row.get("cvss_metadata_state") not in ("not-provided", "outside-supported-base-profile", "supported-vector-arithmetic-only"):
            _failure()
    lines = ["# HunterQA report quality review", "", "Local metadata review only. Findings and analyst verdicts remain unverified.", "",
        "Input SHA-256: "+report["input_sha256"], "", "| Generated case | Missing selected fields | Evidence declared | Verification declaration | CVSS state |", "| --- | --- | --- | --- | --- |"]
    for row in report["records"]:
        lines.append("| "+row["case"]+" | "+(", ".join(row["missing_metadata_fields"]) or "none selected")+" | "+str(row["evidence_metadata_declared"]).lower()+" | "+row["verification_declaration"]+" | "+row["cvss_metadata_state"]+" |")
    lines.extend(["", "Retained quality candidates: "+str(len(report["findings"])), "Truncated: "+str(report["truncated"]).lower(),
        "Candidates not retained: "+str(report["candidates_not_retained"]), "", "No evidence artifact was opened, finding deleted/confirmed, or client report published.", ""])
    return "\n".join(lines)


def review_file(path, *, authorized=False, mode="normalized"):
    if not authorized:
        raise PermissionError("Utility evidence review requires explicit authorization")
    if mode not in ("normalized", "finding-report-json"):
        _failure()
    raw = read_bounded(_approved_file(path), MAX_BYTES)
    receipt = hashlib.sha256(raw).hexdigest()
    data = _decode(raw)
    report = review_evidence(data) if mode == "normalized" else _report_quality(data, receipt)
    report.update(input_sha256=receipt, input_mode=mode)
    return report
