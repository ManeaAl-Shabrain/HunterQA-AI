# HunterQA AI 1.0.0 — Release Review Checklist

Release candidate source: `release/hunterqa-ai-1-0-review` (cumulative ancestry of 8.7 and earlier).
Review and merge **one aggregate pull request into `main`**, rather than merging all older stacked PRs as well.

## Observed Kali validation (reported by user)

- 119 regression tests passed.
- Release Doctor ready, zero warnings/failures, one optional check skipped.
- 9 Flask routes returned HTTP 200 using a disposable SQLite database.
- 132 source files verified against a SHA-256 release manifest.
- User reported manual dashboard acceptance completed.

These are evidence for the previously checked-out 8.7 branch. Changes in the 1.0 review branch require their own tests and review. Evidence does **not** establish zero false positives, zero-day discovery, complete scan coverage, production multi-user security, or dependency advisory completeness.

## Local verification, without overwriting existing data

```bash
cd ~/Desktop/HunterQA-AI
git status --short
git fetch origin
git switch --track origin/release/hunterqa-ai-1-0-review
source .venv/bin/activate
export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"
export HUNTERQA_SECRET_KEY="$(cat "$HOME/.config/hunterqa/session-key")"
bash tools/verify_release_8_6.sh
```

If branch exists locally use `git switch release/hunterqa-ai-1-0-review`. Stop if `git status` is not clean and safeguard local changes.

## Complete, clean source ZIP

```bash
python tools/build_release.py --repo . --out "$HOME/Desktop/HunterQA-AI-1.0.0-source.zip"
python tools/verify_release_archive.py "$HOME/Desktop/HunterQA-AI-1.0.0-source.zip"
unzip -t "$HOME/Desktop/HunterQA-AI-1.0.0-source.zip"
```

The ZIP includes tracked Python source, Flask templates, tests, scripts and documentation, but excludes common runtime databases, secrets and evidence files. Inspect the archive independently before publication. The manifest validates contents against itself, not against a trusted publisher signature.

## Pre-merge human review gates

- [ ] Verify PR's base is `main` and head is the **single cumulative review branch**.
- [ ] Inspect cumulative security-sensitive diff (routes, scope controls, dependency parsers, shell scripts, CI permissions).
- [ ] Confirm CI tests pass on proposed HEAD commit.
- [ ] Re-run full Kali acceptance after final changes.
- [ ] Re-run Jinja2 OSV fixture: 8 raw advisories, 4 deduplicated CVE aliases (assuming unchanged snapshot).
- [ ] Verify `127.0.0.1:5000` only and active Flask secret persistence.
- [ ] Check previous SQLite database and evidence remain intact; make an offline backup.
- [ ] Inspect bundled ZIP and confirm no secrets, local scan data or vulnerable test binaries are published.
- [ ] Ensure privacy and authorized-scope language is accurate in README and confirm the MIT License and `SECURITY.md` are included in the released archive.
- [ ] Explicitly approve merge and GitHub release publication.

## Safe merge order

There is **no need to merge older draft PRs individually** if the cumulative PR is accepted; all their inherited commits are in the review branch already. GitHub may mark older PRs as automatically merged or leave them open, depending on base branch and merge style. Review and close redundant PRs *only after* main contains their contents. Do not delete release branches or rewrite history before checking their ancestry.

## Recovery

`main` remains unchanged until approved merge. For Kali rollback, note the current commit using `git rev-parse HEAD`, make a backup of `instance/hunterqa.sqlite3`, then switch back to the last known good branch. Never restore the DB over newer analyst reviews without reconciliation.

## Limitations

HunterQA is for local explicitly authorized research. CVE/OSV aliases indicate advisory matching, not automatically confirmed vulnerabilities; duplicate advisories are grouped while sources are retained. Lockfile versions do not attest installation; snapshot freshness metadata is user supplied. AI hypotheses require independent human review. Experimental crash replay must remain inside an isolated VM.
