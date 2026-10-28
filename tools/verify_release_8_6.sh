#!/usr/bin/env bash
# Phase 8.7: fail-fast non-destructive local release acceptance checks.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m compileall -q hunterqa
python -m pytest -q

# Interpret the machine-readable doctor result, not just the printout.
python -m hunterqa doctor --check-ollama --json | python -c '
import json, sys
result = json.load(sys.stdin)
print("Release Doctor:", result["overall"], result["summary"])
if result["summary"]["fail"] or result["overall"] == "not_ready":
    sys.exit("Release Doctor has failed required readiness checks")
'

# Flask smoke checks MUST use a disposable SQLite database and approved root.
# Never create/open/upgrade the user's live instance/ database in tests.
python - <<'PY'
import tempfile
from pathlib import Path
from hunterqa import create_app

class NoScanService:
    def submit(self, scan_id):
        raise AssertionError("Smoke test attempted to run a scan")

with tempfile.TemporaryDirectory(prefix="hunterqa-release-qa-") as directory:
    root = Path(directory)
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "release-qa-temporary-secret",
        "DATABASE": str(root / "smoke.sqlite3"),
        "APPROVED_ROOTS": [str(root)],
        "CAMPAIGN_HISTORY_ROOT": str(root),
        "TRIAGE_REPORT_PATH": str(root / "no-triage.json"),
        "RESEARCH_REPORT_PATH": str(root / "no-research.json"),
        "CVE_REPORT_PATH": str(root / "no-cve.json"),
        "SCAN_SERVICE": NoScanService(),
    })
    with app.test_client() as client:
        for route in (
            "/", "/research", "/triage", "/analytics",
            "/campaigns", "/trends", "/cve-intelligence",
            "/audit", "/capabilities",
        ):
            response = client.get(route)
            if response.status_code != 200:
                raise SystemExit(f"FAIL: {route} -> {response.status_code}")
            print("PASS:", route)
print("PASS: temporary database removed after smoke tests")
PY

# Offline packaging integrity checks with no overwrite of personal files.
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
python tools/build_release.py --repo . --out "$tmp_dir/HunterQA-8.7-source.zip"
python tools/verify_release_archive.py "$tmp_dir/HunterQA-8.7-source.zip"
echo "PASS: regression suite, health checks, isolated routes and release archive"
echo "Review doctor warnings and manually validate the dashboard before tagging stable."
