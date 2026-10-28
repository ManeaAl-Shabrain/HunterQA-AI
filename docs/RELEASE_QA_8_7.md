# HunterQA AI 8.7 — Release QA Candidate

This branch includes all cumulative HunterQA research features from 8.6, plus stronger acceptance testing and source ZIP integrity verification.

## Kali release verification

```bash
cd ~/Desktop/HunterQA-AI
git status --short
git fetch origin
git switch --track origin/release/hunterqa-ai-8-7-qa-candidate
source .venv/bin/activate
export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"
export HUNTERQA_SECRET_KEY="$(cat "$HOME/.config/hunterqa/session-key")"
bash tools/verify_release_8_6.sh
```

This script runs regression tests, Release Doctor (which fails the gate for required failures), disposable-database Flask smoke checks, and a source release integrity check. The script may install declared Python development dependencies; review them before execution.

## Produce one complete source release archive

```bash
python tools/build_release.py --repo . --out "$HOME/Desktop/HunterQA-AI-8.7-source.zip"
python tools/verify_release_archive.py "$HOME/Desktop/HunterQA-AI-8.7-source.zip"
unzip -t "$HOME/Desktop/HunterQA-AI-8.7-source.zip"
```

The verifier does not extract or execute archive content; it compares all packaged files to the archive's SHA-256 manifest and rejects unexpected entries. This ensures internal consistency, **not cryptographic authenticity** against an attacker modifying both ZIP and manifest.

## Release blockers / limitations

- Full Kali test suite, browser validation and isolated replay need operator confirmation.
- Outstanding stacked PRs remain open. Do not merge both all parent changes and the cumulative branch without reviewing the diff.
- No claim of 100% vulnerability discovery, zero false positives, reliable live-target stealth, or zero-day confirmation.
- CVE match is a published advisory correlation, not confirmed exploitability; lockfile versions are not installed-version attestations.
- Do not expose the Flask dev server outside loopback.
- Keep SQLite database, research evidence and session key outside distributable ZIP.

## Rollback

Preserve local analyst database and evidence. Switch back to the last known tested Git branch/commit; restore the database only after checking migration compatibility.
