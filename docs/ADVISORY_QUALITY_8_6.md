# HunterQA AI — Phase 8.6 Advisory Quality

Adds offline snapshot age hints, duplicate ID filtering, conservative conflict handling, and scoped npm/Composer package matching to Phase 8.5. No remote lookups, installed-version attestation, or confirmed vulnerability claims.

Freshness is `unknown` unless a user-supplied `snapshot_metadata.fetched_at` UTC ISO-8601 timestamp exists. Stale snapshots are still parsed, but clearly labeled stale. Source metadata is not authenticated. A SHA-256 match is internal consistency, not independent authenticity.

Example metadata:
```json
{"snapshot_metadata":{"fetched_at":"2026-10-28T00:00:00Z","source":"operator-provided OSV snapshot"},"vulns":[]}
```

## Kali verification

```bash
cd ~/Desktop/HunterQA-AI
git fetch origin
git switch --track origin/feature/phase-8-6-advisory-integrity
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m compileall -q hunterqa
python -m pytest -q
```

Do not conflate a reported CVE alias with confirmed exploitability. OSV snapshots may be incomplete or outdated. The lockfile matching feature remains bounded and must be reviewed against actual project lockfile samples.
