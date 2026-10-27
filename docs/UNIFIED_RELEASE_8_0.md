# HunterQA AI — Unified 8.0 Release Candidate

This branch contains the complete cumulative HunterQA AI codebase through:

- Phase 7.8.1 Campaign History (PR #5)
- Phase 7.9 Research Trends (PR #6)
- Phase 8.0 integration and hardening (this branch)

It is intentionally **one repository and one source tree**. It does not include users' evidence, VM binaries, API tokens, or local databases.

## Checkout on Kali

```bash
cd ~/Desktop/HunterQA-AI
git status --short
git fetch origin
git switch --track origin/feature/phase-8-0-unified-release
source .venv/bin/activate
python -m compileall -q hunterqa
python -m pytest -q
```

If the branch is already available locally use `git switch feature/phase-8-0-unified-release`. Stop if checkout reports dirty files; commit or back them up separately first.

## Run the local Flask browser dashboard

```bash
export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"
export HUNTERQA_CAMPAIGN_HISTORY_ROOT="$HOME/ZeroScope-AI/research-lab"
export HUNTERQA_TRIAGE_REPORT="$HOME/ZeroScope-AI/research-lab/verification/hunterqa_unified_triage.json"
python run.py
```

Open these local-only URLs *inside Kali*:

- `http://127.0.0.1:5000/campaigns` — Phase 7.8.1 Campaign History and comparison
- `http://127.0.0.1:5000/trends` — Phase 7.9 research history and candidate changes
- `http://127.0.0.1:5000/triage` — evidence-based analyst review

## Create ONE complete source ZIP

This exports the actual tested branch contents rather than a partial patch set:

```bash
cd ~/Desktop/HunterQA-AI
python tools/build_release.py --repo . --out "$HOME/Desktop/HunterQA-AI-8.0-source.zip"
unzip -t "$HOME/Desktop/HunterQA-AI-8.0-source.zip"
```

The builder includes tracked project source, tests, and docs. It excludes .git, instance, runtime reports, virtual environments, credentials, databases, logs and binaries. Its SHA-256 release manifest records the packaged files. Inspect the archive before sharing publicly.

## Release procedure

1. Verify all tests and the three dashboard routes locally on Kali.
2. Review source changes and do not merge draft PRs without review.
3. Since feature branches are stacked: merge earlier changes in dependency order, or review the cumulative Phase 8.0 diff against main as a single PR. Do NOT merge both cumulative branch and same changes independently.
4. Back up `instance/hunterqa.sqlite3` before upgrades. Preserve it outside any source ZIP.
5. To rollback, switch to the previous stable Git commit/branch. Restore the database backup only if necessary, taking care not to overwrite newer user decisions.

## Security limits

The Flask development server must stay on `127.0.0.1`. Campaign discovery is read-only; browser-supplied arbitrary filesystem paths are not accepted. Hash matching is consistency evidence, not proof of authenticity. AI output and saved report content are untrusted; research records are not confirmed vulnerabilities or zero-days. Optional local crash replay executes lab binaries and requires a separately isolated VM. This is a release candidate pending Kali validation, not a production security guarantee.
