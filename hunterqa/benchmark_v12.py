"""Offline labeled benchmark for OpenAPI *review-candidate selection*.

This measures whether deterministic HunterQA rules suggest particular checks
on fully synthetic specifications. Labels are NOT real vulnerabilities, and
precision/recall here do NOT measure real-world exploit discovery.

No HTTP, browser, subprocess, AI, or third-party service is used.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

from .api_surface_v12 import METHODS, inspect_openapi
from .bounty import BountyPolicy, _approved_file, _read_json

ENGINE = "hunterqa_v12_offline_review_benchmark"
PACK_ENGINE = "hunterqa_v12_openapi_review_benchmark_pack"
MAX_PACK_BYTES = 120_000
MAX_CASES = 16
MAX_LABELS_PER_CASE = 100
VALID_RULES = frozenset({
    "api.auth-declaration-review", "api.public-write-review",
    "api.object-access-review", "api.business-logic-review",
    "api.deprecated-operation-review",
})
ID_RE = re.compile(r"[a-z][a-z0-9_-]{2,39}\Z")
SAFE_SPEC = re.compile(r"[A-Za-z0-9_-]{3,60}\.json\Z")
VALID_METHODS = frozenset(method.upper() for method in METHODS)


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _operation_hash(method, path):
    return _hash((method + " " + path).encode("utf-8"))[:20]


def _ratio(a, b):
    return round(a / b, 6) if b else None


def _metrics(tp, fp, fn, tn, unexpected=0):
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = (round(2 * precision * recall / (precision + recall), 6)
          if precision is not None and recall is not None and precision + recall
          else None)
    return {
        "true_positive_review_suggestions": tp,
        "false_positive_review_suggestions": fp,
        "missed_review_suggestions": fn,
        "true_negative_review_checks": tn,
        "unlabeled_predictions_counted_as_false_positive": unexpected,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "labeled_negative_false_positive_rate": _ratio(fp - unexpected, tn + fp - unexpected),
    }


def evaluate_pack(profile_path, pack_path, *, authorized=False, inventory=inspect_openapi):
    """Validate local ground-truth cues and score synthetic review suggestions."""
    if not authorized:
        raise PermissionError("Synthetic offline benchmarks require --authorized")
    policy = BountyPolicy.load(profile_path)
    profile_sha = _hash(_approved_file(profile_path).read_bytes())
    pack_file = _approved_file(pack_path)
    pack = _read_json(pack_file, MAX_PACK_BYTES)
    if (not isinstance(pack, dict) or pack.get("engine") != PACK_ENGINE
            or pack.get("schema_version") != 1):
        raise ValueError("Not a supported HunterQA review benchmark pack")
    name = pack.get("name")
    if not isinstance(name, str) or not ID_RE.fullmatch(name):
        raise ValueError("Invalid benchmark pack name")
    cases = pack.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("Benchmark requires 1..16 local synthetic cases")
    visited, results = set(), []
    total_tp = total_fp = total_fn = total_tn = total_unexpected = 0
    spec_digests = []
    for entry in cases:
        if not isinstance(entry, dict) or set(entry) != {"id", "spec", "labels"}:
            raise ValueError("Benchmark case has invalid fields")
        case_id, basename, labels = entry["id"], entry["spec"], entry["labels"]
        if not isinstance(case_id, str) or not ID_RE.fullmatch(case_id) or case_id in visited:
            raise ValueError("Invalid or duplicate benchmark case ID")
        visited.add(case_id)
        if not isinstance(basename, str) or not SAFE_SPEC.fullmatch(basename):
            raise ValueError("Benchmark specification must be a safe relative JSON basename")
        spec_path = pack_file.parent / basename
        spec_file = _approved_file(spec_path)
        if spec_file.parent != pack_file.parent:
            raise ValueError("Benchmark specification escaped the pack folder")
        spec_digests.append({"case_id": case_id, "spec_sha256": _hash(spec_file.read_bytes())})
        if not isinstance(labels, list) or not 1 <= len(labels) <= MAX_LABELS_PER_CASE:
            raise ValueError("Each benchmark case requires 1..100 manually authored labels")
        report = inventory(spec_file, profile_path, authorized=True)
        if (not isinstance(report, dict) or report.get("engine") != "hunterqa_v12_offline_api_surface"
                or report.get("program") != policy.program
                or report.get("policy_sha256") != profile_sha):
            raise ValueError("API inventory lacks exact approved program provenance")
        operations = report.get("operations")
        suggestions = report.get("review_candidates")
        if (not isinstance(operations, list) or len(operations) > 500 or
                not isinstance(suggestions, list) or len(suggestions) > 250):
            raise ValueError("Invalid or oversized review candidate inventory")
        known_operations = set()
        for op in operations:
            if not isinstance(op, dict):
                raise ValueError("Malformed API operation")
            method, path = op.get("method"), op.get("path_template")
            if not isinstance(method, str) or method not in VALID_METHODS or not isinstance(path, str):
                raise ValueError("Invalid operation method/path")
            known_operations.add((method, path))
        labeled = {}
        for label in labels:
            if not isinstance(label, dict) or set(label) != {"method", "path", "rule_id", "expected"}:
                raise ValueError("Benchmark labels require explicit method/path/rule/expected")
            method, path, rule = label["method"], label["path"], label["rule_id"]
            expected = label["expected"]
            if (not isinstance(method, str) or method not in VALID_METHODS or not isinstance(path, str)
                    or len(path) > 240 or (method, path) not in known_operations
                    or not isinstance(rule, str) or rule not in VALID_RULES or type(expected) is not bool):
                raise ValueError("Benchmark label does not match a bounded spec operation")
            key = (method, path, rule)
            if key in labeled:
                raise ValueError("Duplicate benchmark label")
            labeled[key] = expected
        emitted = set()
        for item in suggestions:
            if not isinstance(item, dict):
                raise ValueError("Malformed review suggestion")
            method, path, rule = item.get("method"), item.get("path_template"), item.get("rule_id")
            key = (method, path, rule)
            if (not isinstance(method, str) or not isinstance(path, str)
                    or method not in VALID_METHODS or not isinstance(rule, str) or rule not in VALID_RULES
                    or (method, path) not in known_operations
                    or item.get("confirmed") is not False
                    or item.get("zero_day_confirmed") is not False
                    or item.get("cve_id") is not None):
                raise ValueError("Untrusted or automatically confirmed review result")
            operation_id = hashlib.sha256((method + " " + path).encode("utf-8")).hexdigest()[:16]
            candidate_id = hashlib.sha256((rule + ":" + operation_id).encode("utf-8")).hexdigest()[:20]
            if item.get("operation_id") != operation_id or item.get("id") != candidate_id:
                raise ValueError("Review prediction ID conflicts with deterministic API operation identity")
            if key in emitted:
                raise ValueError("Duplicate candidate prediction")
            emitted.add(key)
        tp = sum(key in emitted for key, expected in labeled.items() if expected)
        fn = sum(key not in emitted for key, expected in labeled.items() if expected)
        tn = sum(key not in emitted for key, expected in labeled.items() if not expected)
        labeled_fp = sum(key in emitted for key, expected in labeled.items() if not expected)
        extra = emitted - labeled.keys()
        fp = labeled_fp + len(extra)
        total_tp += tp
        total_fp += fp
        total_fn += fn
        total_tn += tn
        total_unexpected += len(extra)
        violations = [
            {"rule_id": rule, "method": method, "operation_hash": _operation_hash(method, path),
             "kind": "missed_expected_review" if expected else "unexpected_review"}
            for (method, path, rule), expected in sorted(labeled.items())
            if (expected and (method, path, rule) not in emitted)
            or (not expected and (method, path, rule) in emitted)
        ] + [
            {"rule_id": rule, "method": method, "operation_hash": _operation_hash(method, path),
             "kind": "unlabeled_prediction"}
            for method, path, rule in sorted(extra)
        ]
        results.append({
            "case_id": case_id, "operations": len(known_operations),
            "labeled_checks": len(labeled),
            "metrics": _metrics(tp, fp, fn, tn, len(extra)),
            "violations": violations[:250],
        })
    if total_tp + total_fn == 0 or total_tn == 0:
        raise ValueError("Benchmark must include explicit positive and negative labels")
    metrics = _metrics(total_tp, total_fp, total_fn, total_tn, total_unexpected)
    passed = total_fp == 0 and total_fn == 0
    return {
        "schema_version": 1, "engine": ENGINE,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "program": policy.program, "policy_sha256": profile_sha,
        "benchmark_name": name, "benchmark_sha256": _hash(pack_file.read_bytes()),
        "specs": spec_digests, "case_count": len(results),
        "metrics": metrics,
        "golden_review_expectations_met": passed,
        "cases": results,
        "claims": {"confirmed_vulnerabilities": 0, "confirmed_zero_days": 0,
                   "real_world_detection_accuracy": None, "false_positive_free": False},
        "limitations": "Scores measure deterministic review-cue selection on synthetic "
                       "OpenAPI schemas, NOT true vulnerability detection, exploitability, "
                       "real bug-bounty precision or zero-day discovery. "
                       "All pack files are loaded offline within approved roots.",
    }


def benchmark_gate(result, *, fail_on_review_regression=True):
    """Explicit CI gate; do not confuse a benchmark pass with target security."""
    if not isinstance(result, dict) or result.get("engine") != ENGINE:
        raise ValueError("Unsupported HunterQA benchmark result")
    success = result.get("golden_review_expectations_met")
    if type(success) is not bool:
        raise ValueError("Invalid benchmark pass indicator")
    metrics = result.get("metrics")
    if not isinstance(metrics, dict):
        raise ValueError("Benchmark metrics missing")
    fp = metrics.get("false_positive_review_suggestions")
    fn = metrics.get("missed_review_suggestions")
    if type(fp) is not int or type(fn) is not int or fp < 0 or fn < 0:
        raise ValueError("Invalid benchmark error counts")
    if success != (fp == 0 and fn == 0):
        raise ValueError("Benchmark pass flag conflicts with measured suggestions")
    if fail_on_review_regression and not success:
        raise ValueError("Synthetic review benchmark failed: inspect scored review cues")
    return success


def read_benchmark_summary(path):
    """Return safe, count-only dashboard metrics from a selected local artifact."""
    empty = {"status": "not_configured", "cases": 0, "precision": None,
             "recall": None, "unexpected_reviews": 0}
    if not path:
        return empty
    try:
        data = _read_json(path, 300_000)
        if not isinstance(data, dict) or data.get("engine") != ENGINE:
            return empty
        count, metrics = data.get("case_count"), data.get("metrics")
        if type(count) is not int or not 1 <= count <= MAX_CASES or not isinstance(metrics, dict):
            return empty
        precision, recall = metrics.get("precision"), metrics.get("recall")
        extras = metrics.get("false_positive_review_suggestions")
        if (type(precision) not in (int, float) or type(recall) not in (int, float)
                or not 0 <= precision <= 1 or not 0 <= recall <= 1
                or type(extras) is not int or extras < 0):
            return empty
        return {"status": "ready", "cases": count, "precision": precision,
                "recall": recall, "unexpected_reviews": extras}
    except (OSError, TypeError, ValueError, UnicodeError, KeyError):
        return empty
