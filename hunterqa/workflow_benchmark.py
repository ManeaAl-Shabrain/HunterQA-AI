"""Original offline fixtures, never executed as application code."""
from __future__ import annotations

import tempfile
from pathlib import Path

from .engines.config_audit import audit_project
from .workflow_store import approved_directory


def benchmark_adapters(parent):
    approved_directory(parent)
    cases = [("root-container", "FROM example:1\nUSER root\n", {"hunterqa.docker.root-user"}),
             ("nonroot-container", "FROM example:1\nUSER 10001\n", set()),
             ("mutable-image", "FROM example:latest\nUSER 10001\n", {"hunterqa.docker.latest-tag"})]
    results, tp, fp, fn = [], 0, 0, 0
    with tempfile.TemporaryDirectory(prefix="hunterqa-fixtures-", dir=parent) as folder:
        for name, source, expected in cases:
            root = Path(folder) / name
            root.mkdir(mode=0o700)
            (root / "Dockerfile").write_text(source, encoding="utf-8")
            observed = {row["rule_id"] for row in audit_project(root)}
            tp += len(observed & expected)
            fp += len(observed - expected)
            fn += len(expected - observed)
            results.append({"case": name, "expected": sorted(expected), "observed": sorted(observed),
                            "matched": observed == expected})
    return {"engine": "hunterqa_workflow_fixture_benchmark", "cases": results,
            "true_positives": tp, "false_positives": fp, "false_negatives": fn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "all_cases_matched": all(row["matched"] for row in results), "network_requests": 0,
            "limitations": "Three synthetic configuration fixtures only. This is a regression check, not a real-world accuracy or competitor benchmark."}
