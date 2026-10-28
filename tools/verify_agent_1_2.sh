#!/usr/bin/env bash
# HunterQA AI 1.2: non-destructive, entirely offline lab acceptance.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
if ! command -v python >/dev/null; then echo "Python is required" >&2; exit 1; fi
if ! command -v git >/dev/null; then echo "Git is required" >&2; exit 1; fi
tmp="$(mktemp -d -t hunterqa-v12-qa-XXXXXXXX)"
trap 'rm -rf "$tmp"' EXIT

echo "=== HunterQA AI 1.2 private, offline QA ==="
echo "Revision: $(git rev-parse --short HEAD)"
echo "[1/6] Existing v1.1 scope/traffic privacy and full test suite"
bash tools/verify_bounty_1_1.sh

echo "[2/6] Generate disposable, approved local API research inputs"
TMP_V12="$tmp" python - <<'PY'
import json
import os
from pathlib import Path
root = Path(os.environ["TMP_V12"])
profile = {
    "program": "Owned HunterQA 1.2 fixture",
    "platform": "local-lab",
    "authorization_reference": "Owned disposable local OpenAPI research fixture",
    "acknowledged_authorization": True,
    "allowed_hosts": ["app.example.test"],
    "methods": ["HEAD"],
    "max_requests": 2,
    "interval_seconds": 1.0,
}
(root / "policy.json").write_text(json.dumps(profile), encoding="utf-8")
(root / "targets.txt").write_text("https://app.example.test/\n", encoding="utf-8")
(root / "outside.txt").write_text("https://not-approved.test/\n", encoding="utf-8")
PY
cp examples/v12_owned_api_openapi.json "$tmp/openapi.json"

echo "[3/6] Offline API inventory and preflighted specialist plan"
HUNTERQA_APPROVED_ROOTS="$tmp" python -m hunterqa bounty-api-inventory \
  --profile "$tmp/policy.json" --spec "$tmp/openapi.json" \
  --out "$tmp/api.json" --authorized
HUNTERQA_APPROVED_ROOTS="$tmp" python -m hunterqa bounty-agent-plan \
  --profile "$tmp/policy.json" --spec "$tmp/openapi.json" \
  --targets "$tmp/targets.txt" --out "$tmp/plan.json" --authorized
if HUNTERQA_APPROVED_ROOTS="$tmp" python -m hunterqa bounty-agent-plan \
  --profile "$tmp/policy.json" --targets "$tmp/outside.txt" \
  --out "$tmp/outside-plan.json" --authorized >/dev/null 2>&1; then
  echo "FAIL: out-of-scope plan unexpectedly accepted" >&2
  exit 1
fi
test ! -e "$tmp/outside-plan.json"
echo "PASS: out-of-scope plan denied without creating output or network traffic"

echo "[4/6] Offline, policy-matched provenance correlation"
HUNTERQA_APPROVED_ROOTS="$tmp" python -m hunterqa bounty-correlate \
  --profile "$tmp/policy.json" --file "$tmp/api.json" \
  --out "$tmp/correlation.json" --authorized
TMP_V12="$tmp" python - <<'PY'
import json
import os
from pathlib import Path
root = Path(os.environ["TMP_V12"])
api = json.loads((root / "api.json").read_text())
plan = json.loads((root / "plan.json").read_text())
correlation = json.loads((root / "correlation.json").read_text())
assert api["summary"]["operations"] == 4
assert api["summary"]["review_candidates"] > 0
assert plan["metrics"]["network_requests_executed"] == 0
assert plan["guardrails"]["no_shell_from_ai"] is True
assert correlation["summary"]["confirmed_zero_days"] == 0
assert correlation["summary"]["deduplicated_review_candidates"] > 0
assert plan["policy_sha256"] == api["policy_sha256"] == correlation["policy_sha256"]
for item in correlation["review_queue"]:
    assert item["confirmed_vulnerability"] is False
print("PASS: API, agent plan, provenance and no-claim review queue")
PY

echo "[5/6] Read-only Agent Lab UI with disposable SQLite"
TMP_V12="$tmp" HUNTERQA_APPROVED_ROOTS="$tmp" python - <<'PY'
import os
from pathlib import Path
from hunterqa import create_app
root = Path(os.environ["TMP_V12"])
class NoScan:
    def submit(self, *args, **kwargs):
        raise AssertionError("Unexpected scan execution from page view")
app = create_app({
    "TESTING": True,
    "SECRET_KEY": "v12-disposable-test-only",
    "DATABASE": str(root / "disposable.sqlite3"),
    "APPROVED_ROOTS": [str(root)],
    "AGENT_PLAN_PATH": str(root / "plan.json"),
    "API_SURFACE_REPORT_PATH": str(root / "api.json"),
    "AGENT_CORRELATION_REPORT_PATH": str(root / "correlation.json"),
    "CAMPAIGN_HISTORY_ROOT": str(root),
    "TRIAGE_REPORT_PATH": str(root / "none-triage.json"),
    "RESEARCH_REPORT_PATH": str(root / "none-research.json"),
    "CVE_REPORT_PATH": str(root / "none-cve.json"),
    "SCAN_SERVICE": NoScan(),
})
with app.test_client() as client:
    for route in ("/", "/research", "/triage", "/analytics", "/campaigns",
                  "/trends", "/cve-intelligence", "/audit", "/capabilities",
                  "/bounty", "/agent-lab"):
        r = client.get(route)
        if r.status_code != 200:
            raise SystemExit(f"FAIL: {route} -> {r.status_code}")
        print("PASS:", route)
    html = client.get("/agent-lab").data
    assert b"Owned HunterQA 1.2 fixture" in html
    assert b"scope-guard" in html
print("PASS: all 11 routes and local no-execution agent dashboard")
PY

echo "[6/6] Verify complete source ZIP, manifest and v1.2 modules"
python tools/build_release.py --repo . --out "$tmp/HunterQA-1.2-development.zip"
python tools/verify_release_archive.py "$tmp/HunterQA-1.2-development.zip"
TMP_V12="$tmp" python - <<'PY'
import json
import os
import zipfile
from pathlib import Path
root = Path(os.environ["TMP_V12"])
with zipfile.ZipFile(root / "HunterQA-1.2-development.zip") as z:
    names = set(z.namelist())
required = {
    "HunterQA-AI/hunterqa/api_surface_v12.py",
    "HunterQA-AI/hunterqa/agent_workflow_v12.py",
    "HunterQA-AI/hunterqa/agent_ai_v12.py",
    "HunterQA-AI/hunterqa/browser_lab_v12.py",
    "HunterQA-AI/hunterqa/replay_v12.py",
    "HunterQA-AI/docs/BROWSER_LAB_V1_2.md",
    "HunterQA-AI/hunterqa/templates/agent_lab.html",
    "HunterQA-AI/docs/V1_2_DEV.md",
    "HunterQA-AI/docs/INSPIRATION_V1_2.md",
    "HunterQA-AI/LICENSE",
}
assert required.issubset(names), required - names
print("PASS: all v1.2 modules and attribution included in ZIP")
PY
echo "PASS: HunterQA AI 1.2 private/offline QA passed."
echo "Manual Kali dashboard acceptance still required before merge or stable release."
