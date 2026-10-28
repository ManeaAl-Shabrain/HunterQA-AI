# Phase 8.5 — Resolved Dependency Intelligence

HunterQA now imports bounded, offline package versions from:
- npm package-lock.json / npm-shrinkwrap.json v2 or v3 package maps (links skipped)
- Composer composer.lock packages and packages-dev
- Poetry poetry.lock
- uv uv.lock registry packages
- Previous pinned requirements.txt records

The inventory labels records as `lockfile_resolved`, `exact_manifest_declaration`, or `unresolved_manifest_constraint`. These are NOT installed-version attestations. Unsupported or malformed sources remain unassessed. Source-file locations remain available as provenance.

**Advisory matching limitations:** OSV exact versions apply to supported ecosystems; current interval matching handles PEP 440 PyPI ECOSYSTEM and strict SEMVER ranges. Packagist range-only records remain unassessed rather than guessed. Snapshot freshness is the operator's responsibility; GHSA/PYSEC/CVE aliases remain grouped by package/version. No zero-day, exploitability, 100% coverage, or zero-false-positive claims.

## Kali steps

```bash
cd ~/Desktop/HunterQA-AI
source .venv/bin/activate
git fetch origin
git switch --track origin/feature/phase-8-5-resolved-lockfile-intelligence
python -m pip install -e '.[dev]'
python -m compileall -q hunterqa
python -m pytest -q
```

Keep using `python -m hunterqa cve-check --project ... --snapshot ... --out NEW_FILENAME.json --authorized` with project and snapshot under HUNTERQA_APPROVED_ROOTS.

Do not merge until full tests run on Kali, lockfile examples from actual projects are inspected, and regression behavior is reviewed.
