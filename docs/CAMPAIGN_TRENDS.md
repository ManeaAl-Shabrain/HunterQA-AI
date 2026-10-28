# Phase 7.9 — Longitudinal Research Trends

This phase extends the existing local-only HunterQA dashboard. It analyzes already-stored and hash-verified campaign reports without running a scanner, a binary, or model output.

## Kali validation

```bash
cd ~/Desktop/HunterQA-AI
source .venv/bin/activate
git fetch origin
git switch --track origin/feature/phase-7-9-campaign-trends
python -m compileall -q hunterqa
python -m pytest -q
```

Restart your dashboard with:

```bash
export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"
export HUNTERQA_CAMPAIGN_HISTORY_ROOT="$HOME/ZeroScope-AI/research-lab"
python run.py
```

Open `http://127.0.0.1:5000/trends` inside Kali Firefox.

## Interpretation and safeguards

- Only manifest/artifact-hash-consistent campaign snapshots contribute to trends.
- Trends are grouped by the recorded source project; unrelated project findings are never compared.
- Static findings are compared by source path, line, title, and CWE candidate. AI findings are counted separately, not treated as verified.
- Static candidate changes are reported only when both adjacent campaigns have completed static-analysis stages.
- Even completed scans can differ in rules, source revision, and coverage. Newly observed findings **are not confirmed regressions**; missing records **are not proven fixes**.
- SHA-256 manifest checking establishes internal consistency, not forensic authenticity.
- No user-selected filesystem paths, no internet targets, no automatic fuzzing, no auto-applied AI fixes.
- Trends currently provide a bounded in-memory summary of at most 40 recent campaign records and 15 project groups.

Phase 7.9 is stacked on Phase 7.8.1 (PR #5). Validate and merge in dependency order.
