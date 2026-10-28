"""Offline, authorization-gated analyst review of HunterQA evidence candidates.

This produces human attestations and disclosure drafts, not automatic proof of
exploitability, verified zero-days, official CVEs, or bounty eligibility.
SHA-256-linked history detects accidental editing, NOT intentional forgery.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

from .agent_workflow_v12 import KNOWN_ENGINES, KNOWN_RULES
from .bounty import BountyPolicy, _approved_file, _read_json

ENGINE = "hunterqa_v12_review_dossier"
CORRELATION_ENGINE = "hunterqa_v12_evidence_correlation"
MAX_DOSSIER_BYTES = 750_000
MAX_CASES = 200
MAX_EVENTS = 12
HEX20 = re.compile(r"[a-f0-9]{20}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
ALIAS = re.compile(r"[A-Za-z0-9_.-]{3,40}\Z")
DECISIONS = frozenset({
    "needs_more_evidence", "not_reproducible", "false_positive",
    "out_of_scope", "analyst_validated",
})
VALIDATED = "analyst_validated"
EVENT_FIELDS = (
    "case_id", "from_status", "to_status", "analyst_alias", "impact_summary",
    "reproduction_summary", "artifact_sha256", "artifact_bytes", "timestamp",
    "previous_event_hash",
)


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _identity(profile_path):
    policy = BountyPolicy.load(profile_path)
    return policy, _hash(_approved_file(profile_path).read_bytes())


def _scope_check(data, policy, digest):
    if not isinstance(data, dict) or data.get("program") != policy.program or data.get("policy_sha256") != digest:
        raise ValueError("Evidence does not match the exact authorized program and policy")


def _case_from_item(item):
    if not isinstance(item, dict):
        raise ValueError("Malformed review candidate")
    case_id = item.get("id")
    rule = item.get("rule_id")
    target = item.get("target_ref_hash")
    if (not isinstance(case_id, str) or not HEX20.fullmatch(case_id)
            or rule not in KNOWN_RULES or not isinstance(target, str)
            or not HEX20.fullmatch(target)):
        raise ValueError("Unknown rule or invalid evidence identity")
    if (item.get("confirmed_vulnerability") is not False
            or item.get("confirmed_zero_day") is not False
            or item.get("needs_human_review") is not True):
        raise ValueError("Only unconfirmed human-review evidence can enter a dossier")
    sources = item.get("evidence")
    if not isinstance(sources, list) or not 1 <= len(sources) <= 8:
        raise ValueError("Missing or excessive evidence provenance")
    accepted = []
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("Malformed provenance entry")
        engine, digest = source.get("source_engine"), source.get("document_sha256")
        if engine not in KNOWN_ENGINES or not isinstance(digest, str) or not HEX64.fullmatch(digest):
            raise ValueError("Unrecognized evidence engine or invalid SHA-256")
        proof = {"source_engine": engine, "document_sha256": digest}
        if proof not in accepted:
            accepted.append(proof)
    return {
        "id": case_id, "rule_id": rule, "title": KNOWN_RULES[rule],
        "target_ref_hash": target, "source_evidence": accepted,
        "status": "needs_review", "last_review": None, "history": [],
        "confirmed_zero_day": False, "assigned_cve": None,
    }


def prepare_dossier(profile_path, correlation_path, *, authorized=False):
    """Convert an offline correlated review queue into private, unverified cases."""
    if not authorized:
        raise PermissionError("An explicit --authorized flag is required")
    policy, digest = _identity(profile_path)
    raw = _read_json(correlation_path, MAX_DOSSIER_BYTES)
    if not isinstance(raw, dict) or raw.get("engine") != CORRELATION_ENGINE:
        raise ValueError("Expected an approved HunterQA evidence correlation report")
    _scope_check(raw, policy, digest)
    queue = raw.get("review_queue")
    if not isinstance(queue, list) or not 1 <= len(queue) <= MAX_CASES:
        raise ValueError("Expected 1..200 bounded review candidates")
    cases = [_case_from_item(item) for item in queue]
    if len({case["id"] for case in cases}) != len(cases):
        raise ValueError("Duplicate review candidate IDs")
    return {
        "schema_version": 1, "engine": ENGINE,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "program": policy.program, "platform": policy.platform,
        "policy_sha256": digest,
        "correlation_sha256": _hash(_approved_file(correlation_path).read_bytes()),
        "history_format": "sha256_linked_create_only_versions",
        "cases": cases,
        "summary": {"total": len(cases), "analyst_validated": 0,
                    "unvalidated": len(cases), "confirmed_zero_days": 0},
        "limitations": "Review status is a human attestation, not proof of impact, "
                       "origin, authenticity, exploitability or a new CVE.",
    }


def _note(value, name, minimum=30, maximum=500):
    if not isinstance(value, str) or not minimum <= len(value.strip()) <= maximum:
        raise ValueError(f"{name} must have {minimum}..{maximum} characters")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError(f"{name} must be one line, with no control characters")
    return value.strip()


def _check_case_history(case):
    events = case.get("history")
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise ValueError("Review history invalid or exceeds 12 decisions")
    previous = "0" * 64
    status, last = "needs_review", None
    for event in events:
        if not isinstance(event, dict) or set(event) != set(EVENT_FIELDS) | {"event_sha256"}:
            raise ValueError("Unexpected review event fields")
        if (event["case_id"] != case["id"] or
                event["previous_event_hash"] != previous or
                event["from_status"] != status or event["to_status"] not in DECISIONS):
            raise ValueError("Broken review transition or hash chain")
        alias = event["analyst_alias"]
        if not isinstance(alias, str) or not ALIAS.fullmatch(alias):
            raise ValueError("Invalid reviewer alias")
        if event["to_status"] == VALIDATED:
            if (not isinstance(event["artifact_sha256"], str)
                    or not HEX64.fullmatch(event["artifact_sha256"])
                    or type(event["artifact_bytes"]) is not int
                    or not 1 <= event["artifact_bytes"] <= 1_000_000):
                raise ValueError("Analyst validation needs a reproduction artifact")
            _note(event["impact_summary"], "Impact")
            _note(event["reproduction_summary"], "Reproduction")
        elif (event["artifact_sha256"] is not None or
              event["artifact_bytes"] is not None or
              event["impact_summary"] or event["reproduction_summary"]):
            raise ValueError("Nonvalidated decision has unexpected proof claims")
        calculated = _hash(_canonical({k: event[k] for k in EVENT_FIELDS}))
        if event["event_sha256"] != calculated:
            raise ValueError("Evidence review event hash mismatch")
        previous = calculated
        status = event["to_status"]
        last = {k: event[k] for k in (
            "analyst_alias", "impact_summary", "reproduction_summary",
            "artifact_sha256", "artifact_bytes", "timestamp",
        )}
    if case.get("status") != status or case.get("last_review") != last:
        raise ValueError("Dossier case disagrees with recorded history")


def _load_dossier(path, policy, digest):
    data = _read_json(path, MAX_DOSSIER_BYTES)
    if not isinstance(data, dict) or data.get("engine") != ENGINE or data.get("schema_version") != 1:
        raise ValueError("Invalid HunterQA review dossier schema")
    _scope_check(data, policy, digest)
    cases = data.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("Dossier case list is out of bounds")
    seen = set()
    for case in cases:
        if (not isinstance(case, dict) or
                not isinstance(case.get("id"), str) or not HEX20.fullmatch(case["id"])
                or case["id"] in seen or case.get("rule_id") not in KNOWN_RULES
                or case.get("title") != KNOWN_RULES[case["rule_id"]]
                or not isinstance(case.get("target_ref_hash"), str)
                or not HEX20.fullmatch(case["target_ref_hash"])
                or case.get("confirmed_zero_day") is not False
                or case.get("assigned_cve") is not None):
            raise ValueError("Malformed dossier case")
        seen.add(case["id"])
        _check_case_history(case)
    count = sum(case["status"] == VALIDATED for case in cases)
    summary = data.get("summary")
    if (not isinstance(summary, dict) or summary.get("total") != len(cases)
            or summary.get("analyst_validated") != count
            or summary.get("unvalidated") != len(cases) - count
            or summary.get("confirmed_zero_days") != 0):
        raise ValueError("Dossier summary disagrees with human review decisions")
    return data, cases


def record_review(profile_path, dossier_path, case_id, decision, reviewer, *,
                  impact="", reproduction="", evidence_path=None,
                  authorized=False):
    """Return a NEW dossier version. The CLI saves it to a create-only path."""
    if not authorized:
        raise PermissionError("An explicit --authorized flag is required")
    policy, digest = _identity(profile_path)
    data, cases = _load_dossier(dossier_path, policy, digest)
    if decision not in DECISIONS or not isinstance(case_id, str) or not HEX20.fullmatch(case_id):
        raise ValueError("Invalid case reference or decision")
    if not isinstance(reviewer, str) or not ALIAS.fullmatch(reviewer):
        raise ValueError("Use a simple reviewer alias of 3-40 characters")
    case = next((item for item in cases if item["id"] == case_id), None)
    if case is None:
        raise ValueError("Finding ID was not present in approved dossier")
    if len(case["history"]) >= MAX_EVENTS:
        raise ValueError("Too many revisions for this case")
    if case["status"] == "out_of_scope" and decision == VALIDATED:
        raise ValueError("An out-of-scope case cannot be validated")
    if decision == VALIDATED:
        impact = _note(impact, "Impact summary")
        reproduction = _note(reproduction, "Reproduction summary")
        if evidence_path is None:
            raise ValueError("Analyst validation requires local reproduction evidence")
        evidence = _approved_file(evidence_path)
        size = evidence.stat().st_size
        if not 1 <= size <= 1_000_000:
            raise ValueError("Evidence must be 1..1,000,000 bytes")
        if evidence == _approved_file(dossier_path):
            raise ValueError("A dossier is not valid independent reproduction evidence")
        proof_hash, proof_size = _hash(evidence.read_bytes()), size
    else:
        if evidence_path is not None or impact or reproduction:
            raise ValueError("Only analyst_validated may attach proof and impact notes")
        impact, reproduction, proof_hash, proof_size = "", "", None, None
    previous = case["history"][-1]["event_sha256"] if case["history"] else "0" * 64
    event = {
        "case_id": case_id, "from_status": case["status"],
        "to_status": decision, "analyst_alias": reviewer,
        "impact_summary": impact, "reproduction_summary": reproduction,
        "artifact_sha256": proof_hash, "artifact_bytes": proof_size,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "previous_event_hash": previous,
    }
    event["event_sha256"] = _hash(_canonical(event))
    case["history"].append(event)
    case["status"] = decision
    case["last_review"] = {k: event[k] for k in (
        "analyst_alias", "impact_summary", "reproduction_summary",
        "artifact_sha256", "artifact_bytes", "timestamp",
    )}
    validated = sum(entry["status"] == VALIDATED for entry in cases)
    data["summary"] = {
        "total": len(cases), "analyst_validated": validated,
        "unvalidated": len(cases) - validated, "confirmed_zero_days": 0,
    }
    _load_dossier_in_memory(data, policy, digest)
    return data


def _load_dossier_in_memory(data, policy, digest):
    """Validate the result of a new decision without writing any file."""
    # A single internal temporary round-trip is not needed; validate elements.
    _scope_check(data, policy, digest)
    for case in data["cases"]:
        _check_case_history(case)
    return True


def disclosure_draft(profile_path, dossier_path, *, authorized=False):
    if not authorized:
        raise PermissionError("An explicit --authorized flag is required")
    policy, digest = _identity(profile_path)
    _, cases = _load_dossier(dossier_path, policy, digest)
    selected = [case for case in cases if case["status"] == VALIDATED]
    if not selected:
        raise ValueError("No analyst-validated finding; refusing an unsupported disclosure")
    lines = [
        "# HunterQA AI — Private Bug Bounty Disclosure Draft", "",
        "Program: " + policy.program, "",
        "**Status:** Locally analyst-validated; not confirmed by the bounty program.",
        "**Important:** Review all scope, evidence, permissions and personal data before submission.",
        "",
    ]
    for i, case in enumerate(selected, 1):
        review = case["last_review"]
        lines.extend([
            f"## {i}. {case['title']}", "",
            "- Finding reference: " + case["id"],
            "- CWE / CVE: Not assigned by HunterQA",
            "- Zero-day status: Not established",
            "- Reviewer alias: " + review["analyst_alias"],
            "- Reproduction artifact SHA-256: " + review["artifact_sha256"],
            "- Target fingerprint (not an asset locator): " + case["target_ref_hash"],
            "",
            "**Analyst-stated impact:** " + review["impact_summary"], "",
            "**Analyst-stated reproduction:** " + review["reproduction_summary"], "",
            "**Before submission:** supply exact permitted asset and independently "
            "reproduce minimal impact with a test account. Check duplicates.", "",
        ])
    lines.extend([
        "## Provenance", "",
        "Policy SHA-256: " + digest,
        "Review dossier SHA-256: " + _hash(_approved_file(dossier_path).read_bytes()),
        "",
        "No evidence has been verified by the receiving program. "
        "Hashes are not identity signatures. Nothing was automatically submitted.",
    ])
    return "\n".join(lines) + "\n"


def read_review_summary(path):
    """Return count-only, local report summary suitable for read-only dashboard."""
    empty = {"status": "not_configured", "total": 0,
             "analyst_validated": 0, "unvalidated": 0}
    if not path:
        return empty
    try:
        data = _read_json(path, MAX_DOSSIER_BYTES)
        if not isinstance(data, dict) or data.get("engine") != ENGINE:
            return empty
        cases = data.get("cases")
        if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
            return empty
        statuses = [item.get("status") if isinstance(item, dict) else None for item in cases]
        if any(value not in DECISIONS | {"needs_review"} for value in statuses):
            return empty
        count = statuses.count(VALIDATED)
        return {"status": "ready", "total": len(cases),
                "analyst_validated": count, "unvalidated": len(cases) - count}
    except (OSError, ValueError, TypeError, UnicodeError, KeyError, AttributeError):
        return empty
