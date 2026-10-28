# HunterQA AI

**Local-first, authorization-gated AI-assisted security research for Kali Linux.**

[![Latest stable release](https://img.shields.io/github/v/release/ManeaAl-Shabrain/HunterQA-AI?label=stable)](https://github.com/ManeaAl-Shabrain/HunterQA-AI/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Release QA](https://github.com/ManeaAl-Shabrain/HunterQA-AI/actions/workflows/release-qa.yml/badge.svg)](https://github.com/ManeaAl-Shabrain/HunterQA-AI/actions/workflows/release-qa.yml)

HunterQA AI unifies **local source assessment, offline API review, vulnerability/advisory correlation, optional local AI hypotheses, isolated crash research, authorized low-noise HTTP observations, and human-reviewed findings** in a Python CLI and a Flask dashboard.

- **Latest published stable version:** [v1.2.0](https://github.com/ManeaAl-Shabrain/HunterQA-AI/releases/tag/v1.2.0)
- **Supported environment:** Python **3.11+**, Kali Linux / local single-operator workstation; CI uses Ubuntu and Python 3.13.
- **Repository:** [ManeaAl-Shabrain/HunterQA-AI](https://github.com/ManeaAl-Shabrain/HunterQA-AI)
- **Primary interface:** `hunterqa` / `python -m hunterqa` (CLI) and `http://127.0.0.1:5000` (local dashboard).
- **License:** MIT for HunterQA-owned source; third-party tools/models have separate licenses.
- **Important:** This is **not** autonomous exploitation, an unrestricted pentesting agent, public multi-user hosting, or a guarantee of CVE/zero-day discovery. Findings require independent, authorized human validation.

## Development: approved assessment plans

Current source adds an optional CLI workflow: `engagement-plan` →
`engagement-preflight` → fingerprint-approved `engagement-run`.
It supports exact HEAD/GET observations, a benign WAF canary, one dedicated-account
HTTPS login check, and narrow remote HTTPS Playwright form review with JavaScript
disabled. Expiring plans, profile binding, request budgets, DNS-pinned transport,
and a stop-file control constrain each invocation. The existing loopback browser
lab keeps its original scope.

`engagement-compare` compares saved results from the same exact plan and policy
offline. The read-only `/assessments` dashboard displays saved observations and
optional baseline differences without starting traffic.

`engagement-package` prepares reviewed disclosure/CVE request packages from
analyst-validated dossiers; it sends nothing and assigns no CVE IDs. Status
observations remain unverified. There is no credential guessing, WAF evasion,
arbitrary exploit execution, or guaranteed discovery. These additions are not in
the immutable v1.2.0 release archive. See [setup, limits and examples](docs/APPROVED_ASSESSMENTS.md).

## Start here — from a new Kali VM

- **[Zero to Start — full Kali + HunterQA setup guide](https://github.com/ManeaAl-Shabrain/HunterQA-AI/blob/main/zero%20to%20start.md)**: A beginner-friendly walkthrough from VM installation and Python setup to verified offline workflow, authorized assessment methodology, optional AI/browser testing, finding validation, reports, and troubleshooting.
- **Quick verification:** `hunterqa --version` → `hunterqa doctor` → `bash tools/verify_agent_1_2.sh`.
- **Safety:** Live testing requires written permission, exact target scope and explicit method/rate limits. The guide uses fictional sample assets for offline exercises.

## Contents

- [Purpose and use cases](#purpose-and-use-cases)
- [Features in v1.2.0](#features-in-v120)
- [How HunterQA works](#how-hunterqa-works)
- [Requirements](#requirements)
- [Installation and updates](#installation-and-updates)
- [Quick start: fully offline research workflow](#quick-start-fully-offline-research-workflow)
- [Optional AI, browser, and HTTP features](#optional-ai-browser-and-http-features)
- [Run the dashboard](#run-the-dashboard)
- [Commands and documentation](#commands-and-documentation)
- [Security and limitations](#security-and-limitations)
- [Tests and release integrity](#tests-and-release-integrity)
- [Version history](#version-history)

## Purpose and use cases

Use HunterQA to:

- Review **source code, API contracts, dependency manifests, and configurations** from a project you own or are authorized to assess.
- Triage source-scanner, sanitizer, and already captured HTTP evidence into **unverified research candidates**.
- Build a **bounded analyst work plan** and optionally ask a local Qwen model which review roles to prioritize.
- Compare local advisory snapshots against declared package versions; **an advisory match is not proof that an installed service is exploitable**.
- Examine captured HAR files **offline**, with scope filters and redacted outputs.
- Conduct **explicitly authorized, limited HEAD/GET observations** only where a program permits that automation.
- Test an **owned application bound to `127.0.0.1`** with an ephemeral Chromium browser and optional single approved login POST.
- Record reproducibility decisions and generate **private disclosure drafts only from analyst-validated cases**.
- Run synthetic, labeled QA to detect regressions in **review-cue suggestions**, not to claim real-world vulnerability accuracy.

## Features in v1.2.0

| Area | Available functionality | Verification boundary |
| --- | --- | --- |
| Local SAST and configuration audit | Semgrep-backed local rules, configuration checks, static OpenAPI checks, dependencies and SARIF import | Findings are patterns/candidates, not exploits |
| Trust graph and local AI | Source trust-boundary review; optional localhost Ollama/Qwen hypotheses | No LLM-created arbitrary tool execution or automatic verification |
| Offline CVE intelligence | User-supplied OSV/advisory snapshots and declared dependency version correlation | Not a live CVE feed; version/range coverage is incomplete |
| Lab crash research | AFL++ workflows, bounded replay and ASan/UBSan log parsing | Run executable experiments only in an isolated owned lab |
| Authorized bug bounty assessment | Exact-host/path/port policies, offline preflight, bounded HEAD/GET, offline HAR sanitization | No mass crawling, authentication attacks, stealth/WAF bypass, or automatic submission |
| API review | Local OpenAPI 3.0/3.1 inventory, authorization declarations, object IDs, sensitive operations | No contract-server requests; potential issues require runtime tests |
| Specialist research roles | Seven predefined analyst roles with deterministic, non-executing task plans | These are constrained plans, **not autonomous attackers** |
| Evidence correlation | Same-policy, whitelisted-source candidate deduplication with hashed references | Multiple observations do not prove impact |
| Owned browser lab | Optional Playwright Chromium against one approved `127.0.0.1` service, with one approved login POST | Not an external bug bounty browser; browser guards are not a firewall |
| Controlled HEAD replay | Recheck sanitized in-scope HAR endpoints without forwarding sessions or credentials | HEAD results may differ from authenticated GET; no automatic retry |
| Human verification | Private review dossiers, linked decision history, reproduction-note attestations, disclosure drafts | Human attestations are not independently authenticated or exploit proofs |
| Synthetic benchmark | 10 expected review cues and 21 negative labels across two original synthetic contracts | Accuracy applies **only to these review rules/fixtures** |
| Flask dashboard | Read-only research cards and local scan interface on loopback | Not for internet-facing or shared production deployment |
| Assessment history | Read-only saved run metadata and offline same-plan status/body comparison | Missing evidence is unknown; changes require human review |

## How HunterQA works

**Default: private, local-first analysis.** Only separately selected commands send limited traffic.

1. **Authorize and define scope**
   - Set `HUNTERQA_APPROVED_ROOTS` to directories you control.
   - Create a private program profile for bounty workflows, including precise hosts, ports, exclusions, authorization reference, and limits.
   - Check a target list with `bounty-preflight` **before any optional HTTP assessment**.
2. **Collect local evidence**
   - Run an approved source campaign, inspect a local OpenAPI JSON file, or import previously captured HAR / offline advisory data.
   - Keep raw captures, project data, account secrets, and local SQLite outside the public repository.
3. **Map research tasks**
   - `bounty-agent-plan` organizes fixed review roles; optional `bounty-ai-review` asks *local* Ollama to prioritize known roles.
   - The model does not select arbitrary shell tools, issue network requests, or certify vulnerabilities.
4. **Correlate and verify**
   - `bounty-correlate` deduplicates **matching-policy** local evidence.
   - `bounty-review-init` creates a private dossier; analysts record `not_reproducible`, `false_positive`, `needs_more_evidence`, `out_of_scope`, or `analyst_validated`.
   - A validated case requires a matching, explicitly attested local reproduction note, but still needs independent impact review.
5. **Report responsibly**
   - `bounty-review-export` creates a **manual disclosure draft** for analyst-validated cases only.
   - Nothing is automatically submitted to HackerOne, Bugcrowd, or a CVE authority.

**Workflow at a glance:**

```text
Written permission + approved local roots
    |
    +--> Local source/SAST, dependency and optional offline CVE review
    +--> OpenAPI JSON --> API review candidates
    +--> Sanitized HAR --> offline review / optional scoped HEAD replay
    |
    v
Fixed specialist plan (+ optional local Qwen prioritization)
    |
    v
Same-program evidence correlation
    |
    v
Private analyst dossier --> authorized manual reproduction --> review decision
    |
    +--> Private disclosure draft (validated cases only)
    +--> Read-only local dashboards
```

## Requirements

- **Required:** Linux/Kali, Git, Python 3.11+, pip and a Python virtual environment.
- **Python packages:** installed from `pyproject.toml`; Flask and packaging are runtime dependencies. Pytest is in the optional `dev` group.
- **For local source scanning:** install the **Semgrep** executable separately and make it available on `PATH`.
- **For AI analysis:** install and run **Ollama** locally; model example: `qwen2.5-coder:3b`. No remote AI provider is required.
- **For the owned browser lab:** optional `playwright` Python extra and Chromium browser; needs compatible Linux libraries.
- **For memory/sanitizer research:** separately install appropriate Clang, AFL++ and compiler instrumentation; isolate executable tests.
- **No external dependencies are required** to parse the included synthetic OpenAPI fixtures or run the basic offline benchmark.

## Installation and updates

### New Kali installation

```bash
git clone https://github.com/ManeaAl-Shabrain/HunterQA-AI.git
cd HunterQA-AI

python3 -m venv .venv
source .venv/bin/activate

python -m pip install -e '.[dev]'
hunterqa --version
```

- Expected installed version from current `main`: **HunterQA AI 1.2.0**.
- Add browser testing only if needed: `python -m pip install -e '.[dev,browser]'` and `python -m playwright install chromium`.
- Initialize a local session key using `bash tools/setup_verify_kali.sh`. It creates `~/.config/hunterqa/session-key` with restricted permissions if missing.
- Install optional Semgrep/Ollama/AFL++ only for the corresponding engines.

### Update an existing Kali checkout

```bash
cd ~/Desktop/HunterQA-AI

# Review and preserve any local edits BEFORE switching branches.
git status --short --untracked-files=all
git fetch origin --tags
git switch main
git pull --ff-only origin main

source .venv/bin/activate
python -m pip install -e '.[dev]'
hunterqa --version
```

- Use your **actual repository path** if it is not under `~/Desktop`.
- Do not force-reset a branch or commit private evidence just to make a pull succeed.
- Back up `instance/hunterqa.sqlite3` and your private research folders before making environment changes.
- Historic versions remain tagged; use [Releases](https://github.com/ManeaAl-Shabrain/HunterQA-AI/releases) when you need to inspect an earlier version.

## Quick start: fully offline research workflow

The examples use **fictional** `app.example.test`. They are for **offline JSON processing only**—never attempt to scan that hostname. Create a private research directory:

```bash
cd ~/Desktop/HunterQA-AI
source .venv/bin/activate

mkdir -p "$HOME/ZeroScope-AI/research-lab/v12"

cp examples/bounty_profile.example.json "$HOME/ZeroScope-AI/research-lab/v12/profile.json"
cp examples/bounty_targets.example.txt "$HOME/ZeroScope-AI/research-lab/v12/targets.txt"
cp examples/v12_owned_api_openapi.json "$HOME/ZeroScope-AI/research-lab/v12/openapi.json"

export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/research-lab"
folder="$HOME/ZeroScope-AI/research-lab/v12"

python -m hunterqa bounty-api-inventory \
  --profile "$folder/profile.json" \
  --spec "$folder/openapi.json" \
  --out "$folder/inventory-001.json" --authorized

python -m hunterqa bounty-agent-plan \
  --profile "$folder/profile.json" \
  --spec "$folder/openapi.json" \
  --targets "$folder/targets.txt" \
  --out "$folder/plan-001.json" --authorized

python -m hunterqa bounty-correlate \
  --profile "$folder/profile.json" \
  --file "$folder/inventory-001.json" \
  --out "$folder/correlation-001.json" --authorized

python -m hunterqa bounty-review-init \
  --profile "$folder/profile.json" \
  --correlation "$folder/correlation-001.json" \
  --out "$folder/dossier-001.json" --authorized
```

- **All commands above are offline.** No web request or browser session is started.
- `--authorized` records your acknowledgment; it cannot independently establish legal permission.
- New v1.2 bounty output files are created privately (mode `0600`) and **must have new names** for subsequent runs.
- Review IDs and subsequent commands for human reproduction, evidence-attached decisions, and report export are explained in [docs/REVIEW_V1_2.md](docs/REVIEW_V1_2.md).
- To run the labeled synthetic benchmark, see [docs/BENCHMARK_V1_2.md](docs/BENCHMARK_V1_2.md).

## Optional AI, browser, and HTTP features

### Local Qwen suggestions (optional)

```bash
ollama list

python -m hunterqa bounty-ai-review \
  --plan "$folder/plan-001.json" \
  --model qwen2.5-coder:3b \
  --out "$folder/ai-review-001.json" --authorized
```

- Requires a running local Ollama service and the model to be installed.
- The v1.2 reviewer sends **bounded aggregate plan data** to localhost and accepts only known role identifiers.
- A model suggestion is an analyst priority, **not vulnerability evidence**.

### Owned Playwright browser lab (optional)

- Limited to a self-owned service bound to **127.0.0.1** on **one explicitly approved port**.
- May submit **one** approved login POST with disposable credentials from local environment variables; it does **not** automate public website authentication.
- Does not export passwords, cookies, page HTML, HAR, or screenshots.
- Browser interception is **not a system firewall**. Use an isolated VM/network environment for untrusted browser code.
- Setup, scope-policy example, and local test: [docs/BROWSER_LAB_V1_2.md](docs/BROWSER_LAB_V1_2.md).

### Authorized HEAD/GET and HAR workflows (optional)

- First create a **real, program-specific approved scope profile** and target list outside Git.
- Run `bounty-preflight --profile ... --targets ...` to check format and exact declared scope **without network**.
- Run `bounty-assess ... --method HEAD --authorized --out ...` **only when the program permits automation**. This makes real network requests within strict policy and request budgets.
- `bounty-import-har` reads an existing capture **offline**; `bounty-replay-head` optionally sends a credential-free HEAD to the preflighted, previously sanitized targets.
- No credential forwarding, automatic redirect following, rate-limit bypass, mass scanning, or stealth evasion.
- Exact example commands and scope restrictions: [docs/BUG_BOUNTY_V1_1.md](docs/BUG_BOUNTY_V1_1.md).

## Run the dashboard

```bash
cd ~/Desktop/HunterQA-AI
source .venv/bin/activate

export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/research-lab"
export HUNTERQA_SECRET_KEY="$(cat "$HOME/.config/hunterqa/session-key")"

# Optional: display saved approved local v1.2 research reports.
export HUNTERQA_AGENT_PLAN="$HOME/ZeroScope-AI/research-lab/v12/plan-001.json"
export HUNTERQA_API_SURFACE_REPORT="$HOME/ZeroScope-AI/research-lab/v12/inventory-001.json"
export HUNTERQA_AGENT_CORRELATION_REPORT="$HOME/ZeroScope-AI/research-lab/v12/correlation-001.json"
export HUNTERQA_REVIEW_DOSSIER="$HOME/ZeroScope-AI/research-lab/v12/dossier-001.json"

python run.py
```

- **Overview:** [http://127.0.0.1:5000](http://127.0.0.1:5000)
- **Bug Bounty Lab:** [http://127.0.0.1:5000/bounty](http://127.0.0.1:5000/bounty)
- **AI Agent Lab:** [http://127.0.0.1:5000/agent-lab](http://127.0.0.1:5000/agent-lab)
- Additional local pages: Projects, Research Lab, Unified Triage, Hypotheses, Analytics, Campaign History/Trends, CVE Intelligence, Capabilities, and Audit.
- The **read-only bounty/agent dashboards** load administrator-selected approved local reports. Visiting these pages does not launch scans or replay network traffic.
- The general project scan interface requires explicit authorized inputs; never expose the Flask development server to a public network.
- Other optional report variables include `HUNTERQA_BOUNTY_REPORT`, `HUNTERQA_BROWSER_LAB_REPORT`, `HUNTERQA_HEAD_REPLAY_REPORT` and `HUNTERQA_BENCHMARK_REPORT`.
- If the session key is missing, first run `bash tools/setup_verify_kali.sh`. Never commit the key.

## Commands and documentation

### CLI command groups

- **Readiness:** `hunterqa --version`, `hunterqa doctor`, `hunterqa capabilities`.
- **Local research:** `campaign`, `scan`, `audit`, `trust-graph`, `hypothesize`, `propose-fix`, `cve-check`.
- **Source/evidence utilities:** `import-sarif`, `parse-sanitizer`, `research-report`, `verify-crashes`.
- **Authorized bounty:** `bounty-preflight`, `bounty-assess`, `bounty-import-har`, `bounty-report`, `bounty-campaign`.
- **v1.2 offline API/agents:** `bounty-api-inventory`, `bounty-agent-plan`, `bounty-ai-review`, `bounty-correlate`.
- **v1.2 browser/replay:** `bounty-browser-lab`, `bounty-replay-head`, `bounty-repeatability`.
- **v1.2 verification:** `bounty-review-init`, `bounty-reproduction-note`, `bounty-review-decide`, `bounty-review-export`, `bounty-benchmark`.
- Get the exact parameters with `python -m hunterqa COMMAND --help`; many actions require `--authorized`.

### Reference guides

- **From zero:** [Zero to Start — complete Kali VM and HunterQA walkthrough](https://github.com/ManeaAl-Shabrain/HunterQA-AI/blob/main/zero%20to%20start.md).

- **Start here:** [v1.2 Kali workflow](docs/V1_2_DEV.md) · [Architecture](docs/ARCHITECTURE.md) · [Security boundaries](SECURITY.md).
- **Bounty:** [Authorization and HAR](docs/BUG_BOUNTY_V1_1.md) · [Browser Lab](docs/BROWSER_LAB_V1_2.md).
- **Verification:** [Analyst review workflow](docs/REVIEW_V1_2.md) · [Synthetic benchmark](docs/BENCHMARK_V1_2.md).
- **Project quality:** [Limitations](docs/LIMITATIONS.md) · [Release versioning](docs/VERSIONING.md) · [v1.2.0 release notes](docs/RELEASE_1_2_0.md).
- **External references and licenses:** [AI research inspiration review](docs/INSPIRATION_V1_2.md).
- **Additional engines:** Browse [docs/](docs/) for CVE ranges, trust graphs, remediation safety, research trends, and audit history.

## Security and limitations

- **Authorization is mandatory:** only test assets/accounts for which you have written permission and where the applicable program terms allow the selected method.
- **Local-first is the default:** `bounty-assess`, `bounty-replay-head`, and the owned browser lab perform **explicitly requested** traffic; most v1.2 research/verification commands work offline.
- **No bypassing controls:** no WAF bypass, monitoring evasion, proxy rotation, stealth scanning, brute force, credential attacks, or unrestricted autonomous exploitation.
- **Never trust AI as proof:** a Qwen hypothesis, missing header, review cue, CVE alias, sanitizer diagnostic, or HEAD status difference does not independently confirm a security vulnerability.
- **No guaranteed zero-days:** HunterQA does not issue CVEs, prove novelty, or promise detection of all issues. Coordinate any confirmed discovery with affected maintainers.
- **Browser scope is deliberately narrow:** the original Chromium lab supports owned loopback applications. Development `engagement-run` additionally supports exact approved remote HTTPS form checks with JavaScript disabled; see [assessment limits](docs/APPROVED_ASSESSMENTS.md). Playwright interception is not a network isolation boundary.
- **Private evidence:** do not commit `instance/`, `.env`, local HAR captures, auth material, private report files, fuzz output or user data. Use approved folders with least-privilege permissions.
- **Not a hosted service:** Flask runs on `127.0.0.1:5000` using the development server; public/multi-user deployment is not supported.
- **Integrity vs authenticity:** ZIP SHA-256 checks verify file integrity against a manifest, not publisher identity, official CVE assignment, or external security certification.
- **Responsible disclosure:** see [SECURITY.md](SECURITY.md).

## Tests and release integrity

Development quality checks also cover undefined names/unused imports, reviewed
static security warnings, installed dependency advisories, and real Semgrep
positive/negative fixtures. Ubuntu CI exercises Python 3.11 and 3.13.
See the [repository review and verification scope](docs/REPOSITORY_REVIEW_2026_10.md).

```bash
python -m pip install --upgrade pip setuptools
python -m pip install -e '.[dev,quality]'
python -m ruff check hunterqa zeroscope tools --select F
python -m bandit -r hunterqa zeroscope tools -ll
python -m pip_audit --skip-editable --progress-spinner off
# With the separately installed Semgrep executable:
python tools/verify_semgrep_rules.py
```

Dependency advisory checks require internet access and do not audit HunterQA's
own source or establish that an installation is vulnerability-free.

### Full offline regression and local browser integration

```bash
cd ~/Desktop/HunterQA-AI
source .venv/bin/activate

python -m compileall -q hunterqa zeroscope
python -m pytest -q
bash tools/verify_agent_1_2.sh

# Optional real Chromium acceptance: owned temporary 127.0.0.1 only.
python -m pip install -e '.[dev,browser]'
python -m playwright install chromium
HUNTERQA_REAL_BROWSER_CI=1 \
  python -m pytest -q tests/test_browser_lab_playwright_v12.py
```

- The original **v1.2.0 stable publishing workflow passed on GitHub**. See [v1.2.0 release](https://github.com/ManeaAl-Shabrain/HunterQA-AI/releases/tag/v1.2.0).
- Release QA uses disposable fixtures, tests authorization failures and redaction, verifies dashboard routes including saved assessments, and checks the source archive and per-file SHA-256 manifest.
- The synthetic benchmark's **10 expected / 21 negative review labels** do not measure real-world bug-detection precision.
- GitHub Actions tests run on Ubuntu; re-check browser dependencies and local permissions on Kali.

### Verify a locally built source archive

```bash
python tools/build_release.py \
  --repo . --out "$HOME/Desktop/HunterQA-AI-1.2.0-source.zip"

python tools/verify_release_archive.py \
  "$HOME/Desktop/HunterQA-AI-1.2.0-source.zip"
```

- This is a **new local build from your current tracked checkout**, not necessarily byte-for-byte identical to the historical tagged ZIP.
- For the **official v1.2.0 archive**, download the release ZIP **and** its corresponding `.sha256` checksum from [GitHub Releases](https://github.com/ManeaAl-Shabrain/HunterQA-AI/releases/tag/v1.2.0), then verify with `sha256sum -c HunterQA-AI-1.2.0-source.zip.sha256`.
- Do **not** retag v1.2.0 or overwrite historical artifacts when updating the README.

## Version history

| Version | Release focus | Availability |
| --- | --- | --- |
| [v1.0.0](https://github.com/ManeaAl-Shabrain/HunterQA-AI/releases/tag/v1.0.0) | Initial stable local research foundation | Historical stable |
| [v1.0.1](https://github.com/ManeaAl-Shabrain/HunterQA-AI/releases/tag/v1.0.1) | Kali Research Lab and release verification | Historical stable |
| [v1.1.0](https://github.com/ManeaAl-Shabrain/HunterQA-AI/releases/tag/v1.1.0) | Authorized Bug Bounty Edition, scope controls and HAR | Historical stable |
| **[v1.2.0](https://github.com/ManeaAl-Shabrain/HunterQA-AI/releases/tag/v1.2.0)** | Offline AI Agent Lab, owned browser, evidence validation and benchmark | **Latest published stable** |

- Versioning policy: [docs/VERSIONING.md](docs/VERSIONING.md) — MAJOR.MINOR.PATCH; potential next fixes in `v1.2.1` and compatible new features in `v1.3.0`.
- The **v1.2.0 Git tag and release ZIP are immutable historical artifacts**. New documentation commits to `main` do not alter the released tag.
- See [Releases](https://github.com/ManeaAl-Shabrain/HunterQA-AI/releases) for downloads and checksums.

---

**Use HunterQA only on systems you own or have permission to assess. Treat every generated finding as a hypothesis until verified and disclosed responsibly.**
