# HunterQA development and release notes

## Unreleased · scoped HTML discovery

- Added `discovery-setup` and the supervised `web-discovery` workflow adapter:
  approved seed origins, profile-scoped GET link following, depth/page limits,
  form inventory, and informational header/cookie observations.
- Extended private network-journal validation, JSON/HTML reports, the local
  dashboard, and retest coverage comparison for dynamic discovery.
- Added owned-loopback regression tests, offline positive/negative observation
  controls, and a real Chromium dashboard check in release QA.
- Added the [discovery guide](docs/SCOPED_WEB_DISCOVERY.md) and an honest
  [seven-area implementation roadmap](docs/ASSESSMENT_EXPANSION_ROADMAP.md).

This increment does not implement all requested assessment areas. JavaScript,
session-aware crawling, general active validation, network/AD and cloud runtime
assessment, verified customer grants, OS sandboxing and shared organization quotas
remain incomplete or planned. Published v1.3.0 artifacts are unchanged.

## HunterQA v1.3.0 · Release preparation

Version 1.3.0 consolidates the supervised workflow runner, controlled engagements,
research interoperability, evidence review, reporting and maintenance work below.
README and Zero to Start are rewritten for the current CLI and include original
HunterQA release artwork. See [the complete release inventory](docs/RELEASE_1_3_0.md)
and [publication policy](docs/VERSIONING.md). A manual exact-SHA publisher is ready;
no new tag or GitHub release is implied until it is run successfully after merge.

## Changes consolidated from the development line

The subsequent [controlled workflow runner](docs/WORKFLOW_RUNNER.md) adds durable
run/step state, fixed supervised workers, per-run request reservations and rate
controls, cancellation/watchdogs, local review checkpoints, evidence-linked
triage, retest comparison, automatic JSON/HTML/SARIF reports, a read-only run
dashboard and original fixture benchmarks. This is a local single-operator
baseline, not a multi-user authorization service or OS sandbox. Existing account,
browser, Semgrep and crash/fuzz commands keep their independent controls.

The testing-protocol foundation adds `workflow-tools` and `workflow-preflight`:
offline exact-scope checks, six-stage DAG planning, aggregate resource
reservations, and fingerprint-bound local review checkpoints. This increment
does not execute workflows or enforce runtime limits. See the
[platform architecture and rollout plan](docs/TESTING_PROTOCOL.md).

Further development additions include ten original non-executing review playbooks,
a private policy-bound research journal/context resume, offline Nuclei HTTP JSONL
and ZAP traditional JSON evidence adapters, conservative SARIF export, and a reusable
source-only GitHub Action. See the [seven-reference comparison](docs/FRAMEWORK_COMPARISON_2026_10.md)
and [usage/limits](docs/RESEARCH_WORKFLOWS.md). These are original implementations;
external framework source and offensive skills are not vendored or executed.

Current source adds a read-only assessment dashboard, offline same-plan
comparison, stricter loopback-only AI transport, dashboard peer/Host and CSP
controls, resilient analyzer import, conservative advisory withdrawal handling,
OpenAPI anonymous-authentication interpretation, bounded local file reads,
private create-only crash output, stricter archive verification, and additional
quality/rule acceptance checks. See [review scope and limits](docs/REPOSITORY_REVIEW_2026_10.md).
These changes do not replace the immutable v1.2.0 release archive or constitute
a new stable release or security certification.

# HunterQA AI v1.2.0 — Stable Authorized AI Research & Verification

**Version:** 1.2.0
**Channel:** stable
**Platform:** Kali Linux / single-operator use, Python 3.11+
**License:** MIT for original HunterQA code
**Previously released:** v1.0.0, v1.0.1, v1.1.0 — preserved

## Overview

HunterQA AI v1.2.0 consolidates the v1.1 authorization-gated research
capabilities with the existing local source/CVE/fuzzing engines and newly
tested offline OpenAPI review, constrained specialist-agent task planning,
optional local Qwen suggestions, an owned browser lab, safe HEAD evidence
replay, analyst verification dossiers, and synthetic review-rule benchmarks.

It is **not** unrestricted autonomous exploitation, stealth scanning, a
remote authenticated pentest browser, or guaranteed zero-day discovery.

## New in 1.2.0

- **Offline OpenAPI 3.0/3.1 research:** method/route inventory and human
  review prompts for security declarations, resource IDs, sensitive writes
  and deprecated routes. Local JSON only; no outbound URL fetches.
- **Seven original specialist roles:** deterministic, scope-aware
  research plans for API/source/advisory/capture/scope/verification/report
  review. AI cannot execute arbitrary shell commands or expand scope.
- **Optional private Qwen (Ollama):** loopback-only, sanitized aggregate
  metadata, strict allowlist of role recommendations and no tool execution.
- **Human evidence correlation:** whitelisted HunterQA reports, exact
  program-policy fingerprint and hashed target identifiers.
- **Owned Playwright Chromium lab:** ephemeral 127.0.0.1-only browser,
  one explicitly authorized login POST, strict request/redirect controls
  and no exported passwords, cookies, HTML, screenshots or HAR. Real
  browser tests verify an unapproved cross-port redirect sends no traffic.
- **Controlled sanitized HAR HEAD replay:** only approved, policy-matched
  entries, no credentials, cookies, request bodies, redirects or retries.
- **Offline repeatability:** compare two approved HEAD runs; identical
  response codes do not prove exploitation.
- **Analyst verification dossier:** private create-only versions, signed-
  *looking but not digitally signed* SHA-256-linked review history, explicit
  manual reproduction note and disclosure draft for analyst-validated cases.
- **Synthetic review-rule benchmark:** two original non-deployed OpenAPI
  contracts, ten expected review prompts and twenty-one negative checks.
  TP/FP/FN/TN and precision/recall describe *synthetic rule prompts*,
  NOT actual real-world vulnerability detection accuracy.
- **Read-only AI Agent Lab:** `/agent-lab` displays only safe aggregate
  artifact summaries; it never runs scans, replays or agents.

## Preserved from v1.1

Local SAST/Semgrep, source graph analysis, Qwen hypotheses, offline
OSV/CVE matching, lab fuzzing/sanitizer research, scoped HEAD/GET
observations, HAR import, evidence triage, existing Flask dashboards
and private SQLite history remain supported.

## Stable release verification

The publishing workflow validates the *exact merged main commit*:
- Python package/syntax checks and full regression suite
- Previous v1.1 scope and privacy acceptance
- Complete v1.2 end-to-end offline workflow (OpenAPI → plan →
  correlation → review dossier → manual fixture attestation →
  private draft; HEAD repeatability and strict synthetic benchmark)
- All eleven local Flask dashboard routes with disposable SQLite
- Two separate real Chromium tests against ephemeral owned 127.0.0.1
  servers, including blocked cross-port redirect
- Version 1.2.0 markers, source archive SHA-256 manifest, exact
  required source documents, source ZIP and checksum upload

CI runs on GitHub-hosted Ubuntu; passing CI does not automatically
certify every Kali VM or independently verify security vulnerabilities.

## Kali upgrade and verification

```bash
cd ~/Desktop/HunterQA-AI
git status --short
git fetch origin --tags
git switch main
git pull --ff-only origin main
source .venv/bin/activate
python -m pip install -e '.[dev,browser]'
python -m playwright install chromium
hunterqa --version
bash tools/verify_agent_1_2.sh
HUNTERQA_REAL_BROWSER_CI=1 python -m pytest -q tests/test_browser_lab_playwright_v12.py
```

Inspect and preserve uncommitted Kali-only work BEFORE switching
branches. Back up private SQLite research databases before upgrade.

Run the local web interface with `python run.py` and open
`http://127.0.0.1:5000/agent-lab` inside Kali. Optional artifact paths
must be explicitly set through the approved environment configuration.

## Non-goals and important safety limits

- No authenticated testing of live third-party bug bounty websites by
  the Playwright lab: it accepts only an owned 127.0.0.1 application.
- No WAF bypass, monitoring evasion, request camouflage, rotating
  identities, credential attacks, unrestricted crawling or shell
  execution from model-generated instructions.
- No automatically issued CVEs, proved zero-days or guaranteed accuracy.
  Review prompts, missing headers and AI hypotheses are unconfirmed.
- A reviewer attestation is not independent reproduction proof;
  SHA-256-linked history is not an identity signature.
- Playwright request interception is NOT a host firewall: isolate
  untrusted browser code at OS/network level.
- Follow actual program scope, automation rules and disclosure terms.
- No automatic HackerOne/Bugcrowd submissions.
- Not certified for public multi-user hosting.

## Assets, historical releases and license

- Source ZIP: `HunterQA-AI-1.2.0-source.zip`
- Integrity checksum: `HunterQA-AI-1.2.0-source.zip.sha256`
- Immutable Git tag: `v1.2.0` pointing at the reviewed main commit
- Per-file manifest: `HunterQA-AI/RELEASE_MANIFEST.json`,
  release value `1.2.0`
- Historical tags v1.0.0, v1.0.1, v1.1.0 remain unchanged and published.

See `docs/VERSIONING.md`, `docs/V1_2_DEV.md`,
`docs/BROWSER_LAB_V1_2.md`, `docs/REVIEW_V1_2.md`,
`docs/BENCHMARK_V1_2.md` and `docs/INSPIRATION_V1_2.md`.

HunterQA-owned code is MIT-licensed. Third-party frameworks
mentioned as design references retain their own licenses;
no AGPL source or third-party exploit modules were copied.
