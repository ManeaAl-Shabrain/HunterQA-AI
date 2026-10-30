"""Offline social-engineering assurance and saved DMARC/simulation metadata review."""
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
    "phishing": ("owner_authorization_reviewed", "recipient_scope_reviewed", "mail_authentication_reviewed", "simulation_content_reviewed", "credential_collection_avoided", "reporting_path_reviewed", "privacy_and_debrief_reviewed"),
    "social-engineering": ("channel_scope_reviewed", "participant_protection_reviewed", "identity_verification_reviewed", "physical_access_policy_reviewed", "removable_media_policy_reviewed", "stop_and_escalation_reviewed", "training_followup_reviewed"),
}
REFERENCES = ["https://github.com/SnailSploit/Claude-Red/tree/main/Skills/social-engineering",
    "https://www.rfc-editor.org/rfc/rfc9989.html", "https://docs.getgophish.com/api-documentation/campaigns"]


def catalog():
    return [{"id": "offensive-" + key, "implementation": "offline-social-engineering-assurance-review", "fields": list(fields),
        "native_input_modes": ["dmarc-text", "gophish-results-json"],
        "active_exploitation_available": False,
        "required_evidence": "Private owner observations or selected saved DMARC/simulation metadata; live mail controls, participant behavior and exercise authorization remain independently unverified"}
        for key, fields in PROFILES.items()]


def _failure():
    raise ValueError("Unsupported social-engineering evidence shape, selected field or bounds; contents withheld") from None


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
        raise ValueError("Invalid social-engineering evidence JSON; contents withheld") from None
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
    return {"engine": "social-engineering-evidence-review", "schema_version": 1, "category": "Social Engineering",
        "reviewed_at": datetime.now(timezone.utc).isoformat(), "records": [], "findings": [],
        "network_requests": 0, "external_tools_executed": 0, "referenced_files_opened": 0,
        "live_mail_controls_verified": False, "participant_behavior_verified": False, "exercise_authorization_verified": False,
        "all_skills_automated": False, "real_world_effectiveness": "unverified", "truncated": False, "candidates_not_retained": 0,
        "references": REFERENCES, "limitations": [
            "Selected saved DMARC TXT declarations and GoPhish result/config metadata only; no DNS/SMTP/API connections or delivery",
            "No pretext generation, targeting, impersonation, credential collection, landing-page cloning, payload delivery, calls/SMS or physical actions",
            "No full DMARC evaluation, policy discovery/default inheritance, SPF/DKIM verification, receiver enforcement or campaign provenance verification",
            "Latest-state result counts are not cumulative event counts or proof of human behavior; scanners/proxies and source errors can affect outcomes",
            "Upstream skill IDs identify review topics; voice/physical/removable-media controls use owner observations only",
            "Names, emails, addresses, IDs, domains, URLs, credentials, content and timestamps are withheld; receipts do not prove provenance or consent"]}



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
    report["findings"].append({"rule_id": "social-engineering-review." + key.replace("_", "-"), "skill": skill,
        "test_case": case, "title": title, "severity": "INFO", "cwe": "CWE-693",
        "message": title + ". " + fix, "remediation": fix, "code": "", "file_path": "external-evidence",
        "line_start": 1, "line_end": 1, "engine": "social-engineering-evidence-review", "verification_status": "unverified"})


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
                _add(report, row["id"], skill, key + "." + field, "Owner evidence declares incomplete social-engineering assurance: " + field.replace("_", " "),
                    "Review applicable approved simulation scope, mail controls, participant protection and independent evidence; this declaration does not demonstrate a vulnerability.")
        unknown = [f for f, v in obs.items() if v is None]
        _record(report, row["id"], skill, "owner-evidence", unknown_fields=unknown,
            status="insufficient-evidence" if len(unknown) == len(obs) else "partial-declared-evidence")
    return _finish(report)

MODES = ("normalized", "dmarc-text", "gophish-results-json")
RESULT_STATUSES = {"Email Sent":"email_sent", "Email Opened":"email_opened", "Clicked Link":"clicked_link", "Submitted Data":"submitted_data"}


def _dmarc(raw, receipt):
    try:
        text = raw.decode("utf-8-sig").strip()
    except UnicodeError:
        raise ValueError("Invalid saved DMARC text; contents withheld") from None
    if len(text) > 16384 or any(ord(c) < 32 and c not in "\r\n\t" for c in text):
        _failure()
    pieces = text.split(";")
    if pieces and not pieces[-1].strip():
        pieces.pop()
    if not 1 <= len(pieces) <= 100:
        _failure()
    tags = {}
    for index, piece in enumerate(pieces):
        key, separator, value = piece.partition("=")
        key, value = key.strip().lower(), value.strip()
        if not separator or not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", key) or key in tags or len(value) > 4096:
            _failure()
        if index == 0 and (key != "v" or value != "DMARC1"):
            _failure()
        tags[key] = value
    for key in ("p", "sp", "np"):
        if key in tags and tags[key].lower() not in ("none", "quarantine", "reject"):
            _failure()
    for key, values in (("t", ("y", "n")), ("adkim", ("r", "s")), ("aspf", ("r", "s"))):
        if key in tags and tags[key].lower() not in values:
            _failure()
    if "pct" in tags and (not tags["pct"].isascii() or not tags["pct"].isdigit() or len(tags["pct"]) > 3 or int(tags["pct"]) > 100):
        _failure()
    report, case = _report(), "social-" + receipt[:12] + "-dmarc"
    policies = {key:tags[key].lower() if key in tags else "unknown" for key in ("p", "sp", "np")}
    known = {"v", "p", "sp", "np", "t", "pct", "adkim", "aspf", "rua"}
    _record(report, case, "offensive-phishing", "dmarc-text", policy_declarations=policies,
        testing_declaration=tags["t"].lower() if "t" in tags else "unknown", legacy_pct_present="pct" in tags,
        aggregate_reporting_uri_declared=bool(tags["rua"]) if "rua" in tags else None,
        alignment_declarations={key:tags[key].lower() if key in tags else "unknown" for key in ("adkim", "aspf")},
        status="insufficient-evidence" if not any(key in tags for key in known - {"v"}) else "selected-declaration-only")
    for key, value in policies.items():
        if value == "none":
            _add(report, case, "offensive-phishing", "dmarc-" + key + "-none", "Saved DMARC declaration contains " + key + "=none",
                "Review intended monitoring/migration policy and legitimate mail sources before changing handling preferences. Actual domain policy discovery and receiver behavior remain unverified.")
    if tags.get("t", "").lower() == "y":
        _add(report, case, "offensive-phishing", "dmarc-testing", "Saved DMARC declaration requests testing mode",
            "Review intentional test-mode use and receiver compatibility against RFC 9989; no effective policy or mail disposition is computed.")
    if "pct" in tags:
        _add(report, case, "offensive-phishing", "dmarc-legacy-pct", "Saved DMARC declaration contains the legacy pct tag",
            "Review migration and receiver compatibility: RFC 9989 removed pct and introduced t. This reader does not apply percentage-based enforcement or convert policy defaults.")
    report["source_review"] = {"unknown_tags_not_reviewed": len(set(tags) - known), "complete_dmarc_validation": False,
        "policy_defaults_or_inheritance_applied": False, "dns_or_reporting_uris_resolved": False,
        "spf_dkim_alignment_verified": False, "reference_profile": "selected-rfc9989-declarations"}
    return _finish(report)


def _mapping(value):
    if value is None:
        return {}
    if not isinstance(value, dict):
        _failure()
    return value


def _boolean(mapping, key):
    value = mapping.get(key)
    if value is not None and type(value) is not bool:
        _failure()
    return value


def _campaign(data, receipt):
    if not isinstance(data, dict) or not isinstance(data.get("results"), list) or len(data["results"]) > 1000:
        _failure()
    counts = dict.fromkeys((*RESULT_STATUSES.values(), "other_or_unknown"), 0)
    reported_true, reported_false, reported_unknown = 0, 0, 0
    for row in data["results"]:
        if not isinstance(row, dict):
            _failure()
        status = row.get("status")
        if status is not None and (not isinstance(status, str) or len(status) > 64 or any(ord(c) < 32 for c in status)):
            _failure()
        counts[RESULT_STATUSES.get(status, "other_or_unknown")] += 1
        reported = _boolean(row, "reported")
        reported_true += reported is True
        reported_false += reported is False
        reported_unknown += reported is None
    page, smtp = _mapping(data.get("page")), _mapping(data.get("smtp"))
    flags = {key:_boolean(page, key) for key in ("capture_credentials", "capture_passwords")}
    flags["ignore_cert_errors"] = _boolean(smtp, "ignore_cert_errors")
    report, case = _report(), "social-" + receipt[:12] + "-campaign"
    known = sum(counts.values()) - counts["other_or_unknown"] + reported_true + reported_false
    _record(report, case, "offensive-social-engineering", "gophish-results-json", result_record_count=len(data["results"]),
        latest_status_counts=counts, reported_true_count=reported_true, reported_false_count=reported_false,
        reported_unknown_count=reported_unknown, selected_config_declarations=flags,
        status="insufficient-evidence" if not known and all(v is None for v in flags.values()) else "partial-declared-evidence")
    for key, enabled in flags.items():
        if enabled is True:
            _add(report, case, "offensive-phishing", "simulation-" + key, "Saved simulation config explicitly enables " + key.replace("_", " "),
                "Review the approved exercise design, avoid collecting real secrets and require appropriate transport validation. Saved flags do not establish actual collection, delivery or authorization.")
    if counts["submitted_data"]:
        _add(report, case, "offensive-social-engineering", "submitted-data-status", "Saved result metadata declares submitted-data outcomes",
            "Review exercise privacy, debrief and data-minimization procedures using aggregate evidence. Do not import submitted values; labels do not prove credential compromise or human action.")
    report["source_review"] = {"campaign_provenance_verified": False, "recipient_identity_exported": False,
        "timeline_or_content_analyzed": False, "cumulative_funnel_or_effectiveness_computed": False,
        "complete_gophish_schema_validation": False}
    return _finish(report)


def review_file(path, *, authorized=False, mode="normalized"):
    if not authorized:
        raise PermissionError("Social-engineering evidence review requires explicit authorization")
    if mode not in MODES:
        _failure()
    raw = read_bounded(_approved_file(path), MAX_BYTES)
    receipt = hashlib.sha256(raw).hexdigest()
    if mode == "dmarc-text":
        report = _dmarc(raw, receipt)
    else:
        data = _decode(raw)
        report = review_evidence(data) if mode == "normalized" else _campaign(data, receipt)
    report.update(input_sha256=receipt, input_mode=mode)
    return report
