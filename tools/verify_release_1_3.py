"""Offline CLI acceptance for the 1.3 supervised-workflow release."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def verify():
    with tempfile.TemporaryDirectory(prefix="hunterqa-release-130-") as temporary:
        root = Path(temporary).resolve()
        source = root / "source"
        source.mkdir()
        (source / "Dockerfile").write_text("FROM example:latest\nUSER root\n", encoding="utf-8")
        profile = root / "profile.json"
        profile.write_text(json.dumps({"program": "Owned offline release fixture", "platform": "local-lab",
            "authorization_reference": "Owned synthetic files; no external traffic authorized",
            "acknowledged_authorization": True, "allowed_hosts": ["app.example.test"],
            "allowed_paths": ["/"], "excluded_paths": [], "methods": ["HEAD"],
            "allowed_ports": [443], "max_requests": 1, "interval_seconds": 1}), encoding="utf-8")
        env = dict(os.environ, HUNTERQA_APPROVED_ROOTS=str(root))

        def call(*args):
            completed = subprocess.run([sys.executable, "-m", "hunterqa", *map(str, args)],
                env=env, check=True, capture_output=True, text=True, encoding="utf-8", timeout=180)
            return completed.stdout

        assert call("--version").strip() == "HunterQA AI 1.3.0"
        config = root / "plan"
        plan = json.loads(call("workflow-setup", "--profile", profile, "--project", source,
            "--target", "https://app.example.test/", "--out-dir", config, "--authorized"))

        def run(name):
            return json.loads(call("workflow-run", "--profile", profile,
                "--protocol", config / "protocol.json", "--bindings", config / "bindings.json",
                "--approve-execution", plan["execution_sha256"], "--out-dir", root / name,
                "--operator", "Release fixture operator", "--authorized"))

        first = run("run-001")
        assert first["status"] == "completed" and first["charged_requests"] == 0
        assert len(first["findings"]) == 2
        for name in ("summary.json", "report.html", "report.sarif", "run.sqlite3"):
            assert (root / "run-001" / name).is_file(), name
        call("workflow-export", "--run", root / "run-001", "--format", "html", "--out", root / "export.html")
        proof = root / "analyst-note.txt"
        proof.write_text("Owned configuration fixture inspected; deployment impact unverified.", encoding="utf-8")
        call("workflow-review", "--run", root / "run-001", "--finding", first["findings"][0]["id"],
            "--decision", "needs-review", "--reviewer", "Release fixture analyst",
            "--note", "Deployment impact requires review", "--evidence", proof, "--authorized")
        status = json.loads(call("workflow-status", "--run", root / "run-001"))
        assert status["review_counts"]["needs-review"] == 1
        (source / "Dockerfile").write_text("FROM example:1\nUSER 10001\n", encoding="utf-8")
        second = run("run-002")
        assert second["status"] == "completed" and not second["findings"]
        comparison = root / "comparison.json"
        call("workflow-compare", "--first", root / "run-001", "--second", root / "run-002", "--out", comparison)
        assert len(json.loads(comparison.read_text(encoding="utf-8"))["not_observed"]) == 2
        benchmark = root / "benchmark.json"
        call("workflow-benchmark", "--out", benchmark)
        assert json.loads(benchmark.read_text(encoding="utf-8"))["all_cases_matched"]
        print("PASS: HunterQA 1.3.0 offline CLI, workers, review, reports, retest and fixtures; no target traffic")


if __name__ == "__main__":
    verify()
