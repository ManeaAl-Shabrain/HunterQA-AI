# HunterQA AI 8.6 — Consolidated Release Candidate

This branch contains the cumulative project (including 8.5 lockfile inventory and 8.6 advisory-quality features) as one source tree. It is a **candidate**, not a certified stable or production-secure release.

## Step 1 — Back up local data

```bash
cd ~/Desktop/HunterQA-AI
git status --short
mkdir -p "$HOME/hunterqa-backup"
cp -a instance "$HOME/hunterqa-backup/instance-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
```

Keep all local research artifacts in your separate research-lab directory. Never commit them or a session secret.

## Step 2 — Check out cumulative branch

```bash
git fetch origin
git switch --track origin/release/hunterqa-ai-8-6-consolidated
source .venv/bin/activate
bash tools/verify_release_8_6.sh
```

If already present, use `git switch release/hunterqa-ai-8-6-consolidated`. Do not switch over uncommitted work.

## Step 3 — Validate CVE demo

```bash
export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"
python -m hunterqa cve-check \
 --project "$HOME/ZeroScope-AI/research-lab/cve-validation-demo" \
 --snapshot "$HOME/ZeroScope-AI/research-lab/osv_validation_demo.json" \
 --out "$HOME/ZeroScope-AI/research-lab/verification/cve_validation_8_6.json" \
 --authorized
python -m json.tool "$HOME/ZeroScope-AI/research-lab/verification/cve_validation_8_6.json" >/dev/null
```

Expected from the user-supplied previously saved Jinja2 fixture: 8 raw advisory matches and 4 deduplicated CVE groups, conditional on the same snapshot contents. A successful CVE correlation is not proof of exploitability.

## Step 4 — Run the local dashboard

```bash
export HUNTERQA_SECRET_KEY="$(cat "$HOME/.config/hunterqa/session-key")"
export HUNTERQA_CAMPAIGN_HISTORY_ROOT="$HOME/ZeroScope-AI/research-lab"
export HUNTERQA_CVE_REPORT="$HOME/ZeroScope-AI/research-lab/verification/cve_validation_8_6.json"
python run.py
```

Only expose the Flask development server on loopback. Check `ss -ltnp | grep ':5000'`. Pages: `/campaigns`, `/trends`, `/analytics`, `/cve-intelligence`, `/triage`.

## Step 5 — Build a single source ZIP

```bash
python tools/build_release.py --repo . --out "$HOME/Desktop/HunterQA-AI-8.6-source.zip"
unzip -t "$HOME/Desktop/HunterQA-AI-8.6-source.zip"
```

The release ZIP builder includes tracked source, tests and documentation, excluding common secrets, log files, databases, compiled and research output files. Manually inspect the tracked source for credentials before sharing.

## Release decision

8.5 and 8.6 have draft PRs; the consolidated branch is intended for full end-to-end Kali verification. **Do not blindly merge all stacked PRs and then the cumulative branch**, as this could duplicate changes. Review the cumulative diff against main or merge in correct dependency order.

A release is only considered verified after the full test suite, health diagnostics, app routes and real local project use cases pass. Report any failures instead of silently marking them successful. Even then, no scanner can guarantee 100% detection or zero false positives. Snapshot freshness metadata and SHA-256 consistency do not authenticate the advisory source.

## Rollback

Switch to a previously verified Git commit/branch. Preserve current evidence and analyst decisions. Restore the database backup only if necessary and after checking migrations.
