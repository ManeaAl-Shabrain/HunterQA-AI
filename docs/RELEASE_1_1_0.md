# HunterQA AI v1.1.0 — Authorized Bug Bounty Edition

**Status:** Stable release for tested, explicitly authorized local/Kali research workflows.

**Repository:** https://github.com/ManeaAl-Shabrain/HunterQA-AI

## New capabilities in 1.1.0

- Exact-host, port, path and method authorization profiles for local labs, approved private engagements and HackerOne/Bugcrowd programs.
- Offline `bounty-preflight` command to reject an out-of-scope target list before any network request.
- Explicitly opt-in, bounded HEAD/GET HTTP assessment with validated and pinned IP destinations, host-based HTTPS certificate verification, no redirect following, request budgets, interval controls, short timeouts and stop-on-429 behavior.
- Offline `bounty-import-har` review for already captured proxy/browser traffic. Scrubs query strings, credentials, cookie values and response bodies from derived results; skips out-of-scope entries.
- Human-review-only `bounty-report` Markdown drafts that do not claim exploitability, bounty eligibility or CVE assignment.
- Unified `bounty-campaign` orchestration over existing source scanning, trust graphs, optional local Qwen hypotheses, optional offline OSV/CVE analysis, optional HAR evidence and explicitly permitted HTTP observations.
- New read-only `/bounty` Flask page; simply visiting the page never launches a scan.
- Hardened CLI create-only outputs for bounty evidence, bounded JSON inputs, saved reports and opt-in acknowledgment.

## Retained from v1.0.1

- Local source/Semgrep/configuration/OpenAPI analysis and dependency inventory.
- AFL++ fuzzing and sanitizer research tools, requiring an isolated authorized VM for executable replay.
- Offline OSV/CVE intelligence, evidence provenance, analyst review and unified dashboard.
- Historical Kali research sources in `labs/research-lab/`.
- MIT license, responsible-disclosure policy and previous tagged GitHub releases.

## Verification

- On Kali, the operator reported **154 passing Python tests**, **10 successful Flask routes**, approved-target preflight acceptance, out-of-scope rejection, HAR redaction, and **160 verified source files** in the development-candidate ZIP.
- The operator also confirmed that the `/bounty` dashboard opened successfully in Kali.
- After stable version stamping, GitHub Actions reruns the regression tests, isolated acceptance, source archive generation and per-file SHA-256 manifest verification on the merged release commit. Official ZIP and checksum are attached to this release.

The exact number of source files in the final official ZIP may differ from the development candidate because stable release documentation and workflows were added.

## Supported research vs. limits

**Ready for controlled use:** offline source and vulnerability assessment, bounded HTTP security-header observations, offline proxy evidence triage, local AI hypotheses and local fuzz/sanitizer evidence.

**Not provided:** unrestricted autonomous pentesting; authenticated browser attacks; exploitation payloads; unrestricted crawling; stealth or evasion; live brute force; automatic HackerOne/Bugcrowd submissions; guaranteed zero-day detection; official CVE allocation; zero false positives; production multi-user security guarantees.

A reported CVE alias describes published advisory data; an AI hypothesis, sanitizer failure, or missing HTTP header does not by itself confirm a new vulnerability or exploitable zero-day. Research must be reproduced, assessed for impact, and disclosed according to the authorized program's terms.

## Install / upgrade on Kali

```bash
cd ~/Desktop/HunterQA-AI
git status --short
git fetch origin --tags
git switch main
git pull --ff-only origin main
source .venv/bin/activate
python -m pip install -e '.[dev]'
bash tools/verify_bounty_1_1.sh
```

For scope files and command examples, read `docs/BUG_BOUNTY_V1_1.md`. Back up your existing `instance/hunterqa.sqlite3` and keep all private engagement profiles, HAR files, local crash evidence and credentials outside public Git.

## Archive and provenance

The release is built from the merged `main` commit that receives the `v1.1.0` tag. `HunterQA-AI-1.1.0-source.zip` contains tracked project source, tests, tools and documentation but intentionally excludes personal evidence, most runtime outputs, binaries, databases and secrets. The accompanying `.sha256` file verifies the release archive's download integrity. Check the workflow and included files before trusting the archive; a SHA-256 manifest is not a third-party authenticity signature.

**License:** MIT applies to HunterQA-owned code; third-party models, tools and advisories retain their own terms.
