# HunterQA AI 8.3 — Offline CVE Intelligence

CVE identifiers can be linked to published advisories, but a tool cannot issue official CVEs, guarantee every vulnerability is discovered, or guarantee zero false positives.

## Supported scope

- Explicitly authorized local project and offline OSV JSON advisory snapshot
- Exact declared PyPI versions from requirements.txt, matched against OSV affected[].versions only
- CVE aliases (if supplied in OSV record), SHA-256 provenance, and human verification state
- Browser reporting of matches and coverage limitations; no remote scanning
- No claims for npm/composer version constraints, unsupported ranges, or unmatched software

**A matched declaration is not proof of an installed vulnerable package.** Human review must verify actual versions, affected configuration, reachable code and security impact.

## Kali setup

```bash
cd ~/Desktop/HunterQA-AI
source .venv/bin/activate
git fetch origin
git switch --track origin/feature/phase-8-3-offline-cve-intelligence
python -m compileall -q hunterqa
python -m pytest -q
```

Obtain an OSV-format advisory array from a trusted source, inspect the data, and save it inside the approved research-lab directory as `osv_snapshot.json`. This command does not download advisories.

```bash
export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"

python -m hunterqa cve-check \
  --project "$HOME/ZeroScope-AI/targets" \
  --snapshot "$HOME/ZeroScope-AI/research-lab/osv_snapshot.json" \
  --out "$HOME/ZeroScope-AI/research-lab/verification/hunterqa_cve_intelligence.json" \
  --authorized
```

Use a fresh output filename for subsequent analyses; the command refuses overwrite.

For the dashboard:

```bash
export HUNTERQA_CVE_REPORT="$HOME/ZeroScope-AI/research-lab/verification/hunterqa_cve_intelligence.json"
python run.py
```

Open `http://127.0.0.1:5000/cve-intelligence` in Kali Firefox.

## Research confidence model

1. Pattern or hypothesis: possible weakness, no confirmed impact.
2. Published advisory exact-declaration match: package/version correlation; installed version and scope not proven.
3. Reproducible sanitizer/source evidence: supports an actual defect but not automatically exploitable.
4. Analyst-confirmed finding: requires documented source review, scope assessment and controlled reproduction where applicable.
5. Official CVE ID: must originate from a trusted advisory/CVE Program record; never invented or auto-assigned.

Unmatched dependencies are **not reported as secure**. CVE databases can lag and software can have unknown issues. OSV range-only advisories are deliberately marked unassessed rather than compared incorrectly. Refresh snapshots regularly from a trusted distributor after checking publication dates.

The CLI processes local files only. There is no hidden network fallback and no automatic exploitation or target probing.
