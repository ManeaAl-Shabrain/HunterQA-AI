#!/usr/bin/env bash
# HunterQA AI 1.1: offline, non-destructive Kali / CI acceptance checks.
# No public or third-party network targets are contacted by this script.
set -Eeuo pipefail
cd "$(dirname "$0")/.."

if ! command -v python >/dev/null 2>&1; then
  echo "FAIL: Python not on PATH" >&2
  exit 1
fi
if ! command -v git >/dev/null 2>&1; then
  echo "FAIL: Git not on PATH" >&2
  exit 1
fi

tmp_dir="$(mktemp -d -t hunterqa-bounty-qa-XXXXXXXX)"
trap 'rm -rf "$tmp_dir"' EXIT

echo "=== HunterQA AI 1.1: offline acceptance ==="
echo "Branch: $(git branch --show-current)"
echo "Commit: $(git rev-parse --short HEAD)"
echo "Scratch directory: temporary, automatically removed"
echo "NOTE: this verification never opens the production SQLite database."

echo "[1/7] Python compile and regression tests"
python -m compileall -q hunterqa zeroscope
python -m pytest -q

echo "[2/7] Create disposable program policy and local HAR fixtures"
TMP_TEST_DIR="$tmp_dir" python - <<'PY'
import json
import os
from pathlib import Path
root = Path(os.environ["TMP_TEST_DIR"])
profile = {
    "program": "Acceptance-only example",
    "platform": "local-lab",
    "authorization_reference": "Disposable testing fixture, no external traffic",
    "acknowledged_authorization": True,
    "allowed_hosts": ["app.example.test"],
    "excluded_hosts": ["admin.example.test"],
    "allowed_paths": ["/"],
    "excluded_paths": ["/private"],
    "methods": ["HEAD"],
    "allowed_ports": [443],
    "max_requests": 2,
    "interval_seconds": 1.0,
}
(root / "profile.json").write_text(json.dumps(profile), encoding="utf-8")
(root / "targets.txt").write_text("https://app.example.test/\n", encoding="utf-8")
(root / "blocked.txt").write_text("https://app.example.test/\nhttps://offscope.example.test/\n", encoding="utf-8")
(root / "test.har").write_text(json.dumps({
    "log": {"entries": [
        {"request": {"url": "https://app.example.test/?secret=do-not-publish",
                     "method": "GET",
                     "headers": [{"name": "Authorization", "value": "Bearer VERY-PRIVATE"}]},
         "response": {"status": 200, "headers": [
             {"name": "Content-Type", "value": "text/html"},
             {"name": "Set-Cookie", "value": "session=PRIVATE-COOKIE; HttpOnly"},
         ], "content": {"text": "PRIVATE-BODY"}}},
        {"request": {"url": "https://offscope.example.test/", "method": "HEAD"},
         "response": {"status": 200, "headers": []}},
    ]}
}), encoding="utf-8")
PY

echo "[3/7] Offline preflight accepts in-scope and denies out-of-scope"
HUNTERQA_APPROVED_ROOTS="$tmp_dir" python -m hunterqa bounty-preflight \
    --profile "$tmp_dir/profile.json" --targets "$tmp_dir/targets.txt"

if HUNTERQA_APPROVED_ROOTS="$tmp_dir" python -m hunterqa bounty-preflight \
    --profile "$tmp_dir/profile.json" --targets "$tmp_dir/blocked.txt" \
    > "$tmp_dir/blocked.log" 2>&1; then
  echo "FAIL: out-of-scope target was not rejected" >&2
  exit 1
fi
echo "PASS: out-of-scope preflight rejected before network I/O"

echo "[4/7] HAR import and no-secret human-review draft"
HUNTERQA_APPROVED_ROOTS="$tmp_dir" python -m hunterqa bounty-import-har \
    --profile "$tmp_dir/profile.json" \
    --har "$tmp_dir/test.har" \
    --out "$tmp_dir/reviewed.json" --authorized
HUNTERQA_APPROVED_ROOTS="$tmp_dir" python -m hunterqa bounty-report \
    --file "$tmp_dir/reviewed.json" \
    --out "$tmp_dir/report-draft.md"

TMP_TEST_DIR="$tmp_dir" python - <<'PY'
import json
import os
from pathlib import Path
root = Path(os.environ["TMP_TEST_DIR"])
report = json.loads((root / "reviewed.json").read_text(encoding="utf-8"))
text = (root / "reviewed.json").read_text(encoding="utf-8")
for private in ["do-not-publish", "VERY-PRIVATE", "PRIVATE-COOKIE", "PRIVATE-BODY"]:
    if private in text:
        raise SystemExit("FAIL: secret persisted into HAR derived report")
if len(report["observations"]) != 1 or report["skipped_out_of_scope_or_invalid"] != 1:
    raise SystemExit("FAIL: scope filtering did not preserve only approved entries")
if report["claims"]["confirmed_zero_days"] != 0:
    raise SystemExit("FAIL: unverified observations were mislabeled zero-day")
print("PASS: HAR safely redacted and unapproved entry skipped")
PY

echo "[5/7] Read-only Flask page using temporary SQLite only"
TMP_TEST_DIR="$tmp_dir" HUNTERQA_APPROVED_ROOTS="$tmp_dir" python - <<'PY'
import os
from pathlib import Path
from hunterqa import create_app

class NoScanService:
    def submit(self, *args, **kwargs):
        raise AssertionError("Unexpected scan from dashboard smoke test")

root = Path(os.environ["TMP_TEST_DIR"])
app = create_app({
    "TESTING": True,
    "SECRET_KEY": "disposable-bounty-test-only",
    "DATABASE": str(root / "disposable.sqlite3"),
    "APPROVED_ROOTS": [str(root)],
    "BOUNTY_REPORT_PATH": str(root / "reviewed.json"),
    "RESEARCH_REPORT_PATH": str(root / "no-report.json"),
    "TRIAGE_REPORT_PATH": str(root / "no-triage.json"),
    "CVE_REPORT_PATH": str(root / "no-cve.json"),
    "CAMPAIGN_HISTORY_ROOT": str(root),
    "SCAN_SERVICE": NoScanService(),
})
with app.test_client() as client:
    for route in ("/", "/research", "/triage", "/analytics",
                  "/campaigns", "/trends", "/cve-intelligence",
                  "/audit", "/capabilities", "/bounty"):
        response = client.get(route)
        if response.status_code != 200:
            raise SystemExit(f"FAIL: {route} returned {response.status_code}")
        print(f"PASS: GET {route} -> HTTP 200")
    html = client.get("/bounty").data
    if b"Acceptance-only example" not in html:
        raise SystemExit("FAIL: bounty report not visible in dashboard")
print("PASS: all 10 dashboard routes and temporary database")
PY

echo "[6/7] Build and verify complete source archive"
python tools/build_release.py \
    --repo . --out "$tmp_dir/HunterQA-v1.1-development-source.zip"
python tools/verify_release_archive.py \
    "$tmp_dir/HunterQA-v1.1-development-source.zip"
TMP_TEST_DIR="$tmp_dir" python - <<'PY'
import os
import zipfile
from pathlib import Path
root = Path(os.environ["TMP_TEST_DIR"])
with zipfile.ZipFile(root / "HunterQA-v1.1-development-source.zip") as archive:
    names = set(archive.namelist())
required = {
    "HunterQA-AI/hunterqa/bounty.py",
    "HunterQA-AI/hunterqa/bounty_campaign.py",
    "HunterQA-AI/hunterqa/templates/bounty.html",
    "HunterQA-AI/docs/BUG_BOUNTY_V1_1.md",
    "HunterQA-AI/LICENSE",
}
missing = required - names
if missing:
    raise SystemExit(f"FAIL: missing files in archive: {missing}")
print("PASS: 1.1 source modules, docs and license included in archive")
PY

echo "[7/7] Exit without touching local research evidence"
echo "PASS: HunterQA AI 1.1 offline smoke checks, scope gates, test suite, and source ZIP"
echo "MANUAL ACCEPTANCE REQUIRED: validate dashboard in Kali and review an authorized program policy."
echo "This test makes no public-network assessment and is not proof of zero-day discovery."
