# Phase 7.8.1 — Read-only Campaign History and Comparison

This is an extension of the existing HunterQA AI Flask dashboard. It does not execute anything, start scans, or modify evidence. Campaign roots are set by the Kali administrator, not by web requests.

## Kali setup

```bash
cd ~/Desktop/HunterQA-AI
git fetch origin
git switch --track origin/feature/phase-7-8-1-campaign-history
source .venv/bin/activate
python -m compileall -q hunterqa
python -m pytest -q
```

Then restart Flask with the same environment used for local scanning:

```bash
export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"
export HUNTERQA_CAMPAIGN_HISTORY_ROOT="$HOME/ZeroScope-AI/research-lab"
python run.py
```

Open http://127.0.0.1:5000/campaigns **inside the Kali VM**. The page lists direct-child campaign directories that contain `manifest.json`, with stage statuses and SHA-256 artifact checks. Compare `campaign-first` (earlier) with `campaign-ai` (later) using the two dropdowns.

Expected for your earlier runs, if artifact hashes match: 3 standard research records, 4 AI-assisted research records, zero verified zero-days. Counts are not distinct vulnerabilities.

## Integrity and scope

The loader reads only under an administrator-approved local directory. It rejects symlink campaign directories, requires bounded JSON artifacts, and validates artifact names and SHA-256 hashes as recorded in manifests. It has strict input validation on campaign names and does not accept file paths via the browser.

Note that matching hashes **do not prove authenticity** if an attacker can alter both manifest and artifact. Forensic-grade authenticity would require separately protected signed manifests. The current root should be accessible only to trusted local users.

The page compares report candidate keys within the same source project, not vulnerabilities. Missing or added keys can result from rule/model changes, scan coverage, or reporting differences. A clean or empty report does not demonstrate absence of vulnerabilities.

The campaign history is read-only; starting new campaigns is intentionally CLI-only and requires explicit authorization.
