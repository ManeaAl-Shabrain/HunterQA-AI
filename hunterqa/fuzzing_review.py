"""Bounded offline fuzz-campaign evidence and selected AFL++/libFuzzer metrics."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

from .bounty import _approved_file
from .source_files import read_bounded

MAX_BYTES = 1_048_576
MAX_FINDINGS = 500
ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
PROFILES = {
    "fuzzing": ("harness_reviewed", "instrumentation_verified", "seed_corpus_reviewed", "resource_limits_verified"),
    "fuzzing-course": ("owned_lab_verified", "coverage_exercises_reviewed", "crash_triage_reviewed"),
    "bug-identification": ("taint_boundaries_reviewed", "unsafe_operations_reviewed", "fix_regression_reviewed"),
    "vuln-classes": ("classification_reviewed", "impact_evidence_reviewed", "remediation_mapping_reviewed"),
}
INT_FIELDS = ("execs_done", "cycles_done", "corpus_count", "saved_crashes", "saved_hangs", "total_tmout", "exec_timeout", "peak_rss_mb")
DEC_FIELDS = ("execs_per_sec",)
PCT_FIELDS = ("stability", "bitmap_cvg")
EVENTS = ("READ", "INITED", "NEW", "REDUCE", "RELOAD", "pulse", "DONE")
PROGRESS = re.compile(r"^#([0-9]{1,18})[ \t]+([A-Za-z][A-Za-z-]{0,31})(?:[ \t]+(.*))?$")
ERROR = re.compile(r"^(?:==[0-9]{1,10}==[ \t]*)?ERROR: libFuzzer: (deadly signal|timeout|out-of-memory)(?=[ \t(]|$).*$")
METRIC = re.compile(r"(?:^|[ \t])(cov|ft|corp|exec/s):[ \t]+([^ \t]+)")
REFERENCES = ["https://github.com/SnailSploit/Claude-Red/tree/main/Skills/fuzzing",
    "https://llvm.org/docs/LibFuzzer.html", "https://aflplus.plus/docs/status_screen/",
    "https://github.com/AFLplusplus/AFLplusplus/blob/stable/src/afl-fuzz-stats.c"]


def catalog():
    return [{"id": "offensive-" + key, "implementation": "offline-campaign-assurance-review", "fields": list(fields),
        "native_metrics_review_available": key == "fuzzing", "fuzzer_execution_available": False,
        "required_evidence": "Private owner-normalized observations or selected existing AFL++ stats/libFuzzer log; no harness execution, coverage validation or demonstrated vulnerability detection"}
        for key, fields in PROFILES.items()]


def _failure():
    raise ValueError("Unsupported fuzzing evidence syntax, type or bounds; contents withheld") from None


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
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Invalid fuzzing evidence JSON; contents withheld") from None


def validate_evidence(data):
    if not isinstance(data, dict) or set(data) != {"schema_version", "records"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        _failure()
    if not isinstance(data["records"], list) or not 1 <= len(data["records"]) <= 40:
        _failure()
    ids, counts = set(), {}
    for row in data["records"]:
        if not isinstance(row, dict) or set(row) != {"id", "skill", "observations"}:
            _failure()
        if not isinstance(row["id"], str) or not ID.fullmatch(row["id"]) or row["id"] in ids:
            _failure()
        ids.add(row["id"])
        skill = row["skill"]
        if not isinstance(skill, str) or not skill.startswith("offensive-") or skill[10:] not in PROFILES:
            _failure()
        key, obs = skill[10:], row["observations"]
        counts[key] = counts.get(key, 0) + 1
        if counts[key] > 10 or not isinstance(obs, dict) or set(obs) != set(PROFILES[key]) or not all(v is None or type(v) is bool for v in obs.values()):
            _failure()
    return data


def _report():
    return {"engine": "fuzzing-evidence-review", "schema_version": 1, "category": "Fuzzing & Vulnerability Research",
        "reviewed_at": datetime.now(timezone.utc).isoformat(), "records": [], "findings": [],
        "network_requests": 0, "external_tools_executed": 0, "binaries_loaded": 0, "referenced_files_opened": 0,
        "fuzzer_executed": False, "coverage_verified": False, "reproduced": False, "exploitability_verified": False,
        "zero_day_confirmed": False, "all_skills_automated": False, "real_world_effectiveness": "unverified",
        "truncated": False, "candidates_not_retained": 0, "references": REFERENCES,
        "limitations": ["Selected offline observations and metric syntax only; no fuzzer, harness, compiler, binary, input replay or minimizer is run",
            "Counters/logs can be stale, incomplete, concatenated or fabricated; receipt hashes do not prove provenance or consent",
            "Saved crashes/hangs and error markers are not unique vulnerabilities, verified root causes or demonstrated security impact",
            "AFL bitmap occupancy and libFuzzer counters are not source-code coverage percentages or complete standards coverage",
            "No cross-build metric comparison, unique-crash classification, independent detection rate or completed curriculum is established",
            "Native identities, paths, arguments, inputs and source contents are withheld; operator IDs must be neutral"]}


def _add(report, case, skill, key, title, fix, *, line=1):
    if len(report["findings"]) >= MAX_FINDINGS:
        report["truncated"] = True
        report["candidates_not_retained"] += 1
        return
    report["findings"].append({"rule_id": "fuzzing-review." + key.replace("_", "-"), "skill": skill,
        "test_case": case, "title": title, "severity": "INFO", "cwe": "CWE-693",
        "message": title + ". " + fix, "remediation": fix, "code": "", "file_path": "external-evidence",
        "line_start": line, "line_end": line, "engine": "fuzzing-evidence-review", "verification_status": "unverified"})


def _finish(report):
    rows = report["records"]
    report["status"] = "insufficient-evidence" if not rows or all(r["status"] == "insufficient-evidence" for r in rows) else "partial-offline-review"
    return report


def review_evidence(data):
    validate_evidence(data)
    report = _report()
    for row in data["records"]:
        obs = row["observations"]
        for field, value in obs.items():
            if value is False:
                _add(report, row["id"], row["skill"], row["skill"][10:] + "." + field,
                    "Owner evidence declares incomplete fuzzing/research assurance: " + field.replace("_", " "),
                    "Review applicable harness, build and independent evidence; this declaration does not demonstrate a vulnerability.")
        unknown = [f for f, v in obs.items() if v is None]
        report["records"].append({"case": row["id"], "skill": row["skill"], "unknown_fields": unknown,
            "status": "insufficient-evidence" if len(unknown) == len(obs) else "partial-declared-evidence"})
    return _finish(report)


def _lines(raw):
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        _failure()
    if any(ord(c) < 32 and c not in "\r\n\t" for c in text) or "\x7f" in text:
        _failure()
    lines = text.splitlines()
    if len(lines) > 20000 or any(len(line) > 8192 for line in lines):
        _failure()
    return enumerate(lines, 1)


def _integer(value):
    if not re.fullmatch(r"[0-9]{1,18}", value):
        _failure()
    return int(value)


def _decimal(value, percent=False):
    if percent:
        if not value.endswith("%"):
            _failure()
        value = value[:-1]
    if not re.fullmatch(r"[0-9]{1,18}(?:\.[0-9]{1,6})?", value):
        _failure()
    number = float(value)
    if percent and number > 100:
        _failure()
    return number


def _afl(raw, receipt):
    report, seen, metrics, locations = _report(), set(), {}, {}
    selected = (*INT_FIELDS, *DEC_FIELDS, *PCT_FIELDS)
    for number, line in _lines(raw):
        if not line.strip():
            continue
        if ":" not in line:
            _failure()
        key, value = (part.strip() for part in line.split(":", 1))
        if not re.fullmatch(r"[a-z_][a-z0-9_]{0,63}", key) or key in seen:
            _failure()
        seen.add(key)
        if len(seen) > 512:
            _failure()
        if key in selected:
            metrics[key] = _integer(value) if key in INT_FIELDS else _decimal(value, percent=key in PCT_FIELDS)
            locations[key] = number
    case = "fuzz-" + receipt[:12] + "-afl"
    report["records"].append({"case": case, "skill": "offensive-fuzzing", "context": "afl-stats", "declared_metrics": metrics,
        "unknown_fields": [k for k in selected if k not in metrics], "status": "selected-native-syntax-only" if metrics else "insufficient-evidence"})
    for key, condition, title, fix in (
        ("execs_done", lambda n: n == 0, "Stats declare zero executions", "Review capture timing and whether the intended harness actually ran; this snapshot is not a live health check."),
        ("saved_crashes", lambda n: n > 0, "Stats declare saved crash artifacts", "Privately review and independently reproduce artifacts; the count is not a unique vulnerability count."),
        ("saved_hangs", lambda n: n > 0, "Stats declare saved hang artifacts", "Review timeouts, input behavior and reproducibility; hangs alone do not establish a security issue."),
        ("stability", lambda n: n < 100, "Stats declare non-identical instrumentation traces", "Review nondeterminism, harness state and environment; reduced stability is not automatically a target vulnerability."),
        ("total_tmout", lambda n: n > 0, "Stats declare timeout events", "Review harness limits and expected workload independently; do not infer vulnerabilities from this counter.")):
        if key in metrics and condition(metrics[key]):
            _add(report, case, "offensive-fuzzing", "afl." + key, title, fix, line=locations[key])
    report["source_review"] = {"unselected_fields_seen": len(seen) - len(metrics), "snapshot_only": True,
        "bitmap_metric_is_source_coverage": False, "cross_build_comparison_performed": False}
    return _finish(report)


def _libfuzzer(raw, receipt):
    report, events, unsupported, done, previous_runs, restarted = _report(), 0, 0, False, None, False
    for number, line in _lines(raw):
        progress, error = PROGRESS.fullmatch(line), ERROR.fullmatch(line)
        if not progress and not error:
            continue
        if progress and progress[2] not in EVENTS:
            unsupported += 1
            continue
        events += 1
        if events > 200:
            _failure()
        case = "fuzz-" + receipt[:12] + "-event-" + str(events)
        if error:
            report["records"].append({"case": case, "skill": "offensive-fuzzing", "context": "libfuzzer-error-marker",
                "line": number, "diagnostic": error[1], "status": "selected-log-marker-only"})
            _add(report, case, "offensive-fuzzing", "libfuzzer." + error[1].replace(" ", "-"),
                "Log declares a selected libFuzzer diagnostic: " + error[1],
                "Review original log/build provenance and independently reproduce in the owned lab; this marker is not verified impact.", line=number)
            continue
        runs, event, metrics = _integer(progress[1]), progress[2], {}
        for key, value in METRIC.findall(progress[3] or ""):
            if key in metrics:
                _failure()
            if key == "corp":
                if "/" not in value or not value.split("/", 1)[1]:
                    _failure()
                metrics[key] = _integer(value.split("/", 1)[0])  # Byte-size suffix is intentionally opaque.
            else:
                metrics[key] = _integer(value)
        restarted = restarted or (previous_runs is not None and runs < previous_runs)
        previous_runs = runs
        done = done or event == "DONE"
        report["records"].append({"case": case, "skill": "offensive-fuzzing", "context": "libfuzzer-progress", "line": number,
            "event": event, "declared_iterations": runs, "declared_metrics": metrics,
            "unknown_fields": [k for k in ("cov", "ft", "corp", "exec/s") if k not in metrics],
            "status": "selected-native-syntax-only" if metrics else "insufficient-evidence"})
    if events and not done:
        _add(report, "fuzz-" + receipt[:12] + "-capture", "offensive-fuzzing", "libfuzzer.no-done-marker",
            "Capture has no selected DONE progress event", "Review capture completeness; absence does not prove the campaign failed or never completed.")
    if restarted:
        _add(report, "fuzz-" + receipt[:12] + "-capture", "offensive-fuzzing", "libfuzzer.counter-decrease",
            "Captured iteration counters decrease", "Review restarts, concatenation and worker interleaving before interpreting campaign progress.")
    report["source_review"] = {"selected_events_seen": events, "unsupported_progress_events": unsupported, "done_marker_seen": done,
        "single_run_consistency": "not-established" if restarted else "not-verified", "progress_deltas_computed": False,
        "source_coverage_percentage_computed": False, "unique_crashes_computed": False}
    return _finish(report)


def review_file(path, *, authorized=False, mode="normalized"):
    if not authorized:
        raise PermissionError("Fuzzing evidence review requires explicit authorization")
    if mode not in ("normalized", "afl-stats", "libfuzzer-log"):
        _failure()
    raw = read_bounded(_approved_file(path), MAX_BYTES)
    receipt = hashlib.sha256(raw).hexdigest()
    report = review_evidence(_decode(raw)) if mode == "normalized" else (_afl if mode == "afl-stats" else _libfuzzer)(raw, receipt)
    report.update(input_sha256=receipt, input_mode=mode)
    return report
