# HunterQA AI Phase 8.4 — OSV advisory accuracy

This builds directly on the existing Phase 8.3 local/offline CVE engine.

New features:
- Support OSV affected.versions matching and conservative OSV PyPI ECOSYSTEM / strict SEMVER introduced, fixed and last_affected events.
- Preserve raw advisory matches, but group records sharing the same CVE identifier *per package/version*; all GHSA and PYSEC IDs remain visible.
- Unsupported ranges, malformed events and unrecognized ecosystems stay unassessed instead of being reported as unaffected.
- Report a separate unique CVE/package group count.

**Current limitations:** The inventory still recognizes exact pinned PyPI declarations from requirements.txt only. npm/package.json and Composer manifests are constraints, not resolved lockfiles, so they are intentionally not claimed as checked. Phase 8.4 does *not* yet implement npm or Composer lockfile resolution, cross-source alias graph validation, CVSS verification, or installed-version attestation.

## Kali

```bash
cd ~/Desktop/HunterQA-AI
source .venv/bin/activate
git fetch origin
git switch --track origin/feature/phase-8-4-advisory-dedup-and-lockfiles
python -m pip install -e '.[dev]'
python -m compileall -q hunterqa
python -m pytest -q
```

Your prior Jinja2 fixture is unchanged and remains under `~/ZeroScope-AI/research-lab/cve-validation-demo`.

```bash
export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"
python -m hunterqa cve-check \
 --project "$HOME/ZeroScope-AI/research-lab/cve-validation-demo" \
 --snapshot "$HOME/ZeroScope-AI/research-lab/osv_validation_demo.json" \
 --out "$HOME/ZeroScope-AI/research-lab/verification/cve_validation_8_4.json" \
 --authorized
python - <<'PY'
import json
from pathlib import Path
report = json.loads((Path.home() / "ZeroScope-AI/research-lab/verification/cve_validation_8_4.json").read_text())
print("Raw advisories:",len(report["matches"]))
print("Unique groups:",len(report["cve_groups"]))
for row in report["cve_groups"]:
    print(row["cve_id"], row["advisory_ids"])
PY
```

The expected test-fixture observation is 8 advisory matches and 4 groups, *provided the saved snapshot is the same*. These groups are not 4 confirmed exploitable vulnerabilities. Official CVEs come from the published aliases, not the model.

Do not merge this draft without running the full Kali tests and reviewing how version normalization handles your real-world lockfiles.
