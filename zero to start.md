# Zero to Start — HunterQA AI on Kali Linux

> **Complete beginner-to-operator guide:** install Kali in a VM, configure HunterQA AI, run the tools, perform authorized vulnerability assessments, review evidence and prepare reports.
>
> **Version covered:** HunterQA AI **v1.2.0 Stable**. Check [GitHub Releases](https://github.com/ManeaAl-Shabrain/HunterQA-AI/releases/latest) for a newer stable version. This document is a public setup guide, **not** authorization to test any external target.

## Table of contents

1. [What HunterQA does](#1-what-hunterqa-does)
2. [Prepare your Kali VM](#2-prepare-your-kali-vm)
3. [Install HunterQA AI from scratch](#3-install-hunterqa-ai-from-scratch)
4. [Verify the entire installation](#4-verify-the-entire-installation)
5. [First complete offline workflow](#5-first-complete-offline-workflow)
6. [Configure optional local Qwen AI](#6-configure-optional-local-qwen-ai)
7. [Start and use the web dashboard](#7-start-and-use-the-web-dashboard)
8. [How to perform authorized security assessments](#8-how-to-perform-authorized-security-assessments)
9. [HTTP observations, scope and HAR](#9-http-observations-scope-and-har)
10. [Playwright owned-browser lab](#10-playwright-owned-browser-lab)
11. [Validate findings and create a security report](#11-validate-findings-and-create-a-security-report)
12. [Other tools and commands](#12-other-tools-and-commands)
13. [Updates, backups and versions](#13-updates-backups-and-versions)
14. [Troubleshooting](#14-troubleshooting)
15. [Final readiness checklist](#15-final-readiness-checklist)

---

## 1. What HunterQA does

- **HunterQA AI** is an authorization-gated, local-first security research platform for a **single operator**, with a Python CLI and local Flask dashboard.
- **Implemented in v1.2.0:**
  - Source/configuration/Semgrep and SARIF analysis.
  - Local dependency inventory and offline OSV/CVE-advisory correlation.
  - OpenAPI 3.0/3.1 inventory for authorization, object-reference and sensitive-operation **review cues**.
  - Seven fixed specialist-agent research roles and optional local Ollama/Qwen suggestions.
  - Bounded, expressly authorized HEAD/GET HTTP observations.
  - Offline HAR import, evidence correlation and conservative HEAD replay.
  - Owned **127.0.0.1-only** Chromium/Playwright browser lab with an optional single approved login.
  - Human-review dossiers, reproduction attestations and disclosure drafts.
  - Synthetic rule-calibration benchmarks and a read-only AI Agent Lab.
  - Local fuzz/sanitizer crash evidence review in isolated owned labs.
- **Not supported:** unrestricted autonomous exploitation, stealth/WAF bypass, password attacks, remote authenticated Playwright pentesting, automatic submission, automatic CVE assignment, or guaranteed zero-day discovery.
- **Remember:** review candidates, model hypotheses, missing headers and advisory matches are **not confirmed vulnerabilities**.

## 2. Prepare your Kali VM

### Hardware and downloads

- Install a hypervisor: **VirtualBox** or **VMware**.
- Download a Kali installer or prebuilt virtual-machine image from the [official Kali website](https://www.kali.org/get-kali/).
- Enable Intel VT-x / AMD-V hardware virtualization if necessary.
- Suggested starting configuration:
  - **CPU:** 2–4 virtual processors.
  - **RAM:** 4 GB for basic research; **8 GB or more** preferred for browser/AI tasks.
  - **Storage:** 50–80 GB expandable virtual disk.
  - **Network:** **NAT** for downloads and ordinary updates; an **isolated/host-only** network for deliberately vulnerable practice services.
- Install Kali, choose a strong password and keep the machine's test traffic away from your normal home/work network.
- **Do not bridge** deliberately vulnerable lab machines onto an accessible LAN or expose them publicly.

### Update Kali first

```bash
sudo apt update
sudo apt full-upgrade -y
sudo reboot
```

- Reopen Terminal after reboot.
- Take a **clean baseline VM snapshot** before adding additional research dependencies.

### Install required packages

```bash
sudo apt install -y \
  git curl ca-certificates \
  python3 python3-venv python3-pip \
  build-essential

python3 --version
git --version
```

- HunterQA requires **Python 3.11+**.
- Always install project Python packages in a dedicated virtual environment.
- Avoid using Kali's system Python with `pip --break-system-packages`.

### Create a private evidence area

```bash
mkdir -p "$HOME/ZeroScope-AI/targets" \
         "$HOME/ZeroScope-AI/research-lab/v12"

chmod 700 "$HOME/ZeroScope-AI" \
          "$HOME/ZeroScope-AI/targets" \
          "$HOME/ZeroScope-AI/research-lab" \
          "$HOME/ZeroScope-AI/research-lab/v12"
```

- **`targets/`:** approved local application source and assessment materials.
- **`research-lab/`:** private policies, HAR/evidence files, plans and reports.
- Never commit real credentials, original captures, customer data or engagement reports to the public GitHub repository.

## 3. Install HunterQA AI from scratch

### Clone the official project

```bash
cd ~/Desktop
git clone https://github.com/ManeaAl-Shabrain/HunterQA-AI.git
cd HunterQA-AI

git branch --show-current
git status --short
git fetch origin --tags
```

- Normal operation uses `main`, which tracks the current project.
- If you must reproduce the exact v1.2.0 release, use `git switch --detach v1.2.0` after fetching tags; a detached tag is for **running**, not normal development.
- Read [VERSIONING.md](docs/VERSIONING.md) for release policy.

### Create a Python virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

- The terminal typically shows `(.venv)` after activation.
- `-e` installs the current checkout in editable mode; `[dev]` adds testing dependencies.

### Confirm the package

```bash
hunterqa --version
hunterqa --help
hunterqa capabilities
hunterqa doctor
```

- On the v1.2.0 checkout, the version should be **HunterQA AI 1.2.0**.
- For any feature: `hunterqa COMMAND --help`.
- If the `hunterqa` console command isn't found, try `python -m hunterqa --help` in the activated venv.

### Initialize the dashboard session key

```bash
bash tools/setup_verify_kali.sh
```

- This setup script verifies the local Kali environment and provisions a session key if needed at `~/.config/hunterqa/session-key`.
- Keep the key secret. Do not upload it or copy it into an issue, PR or report.

## 4. Verify the entire installation

### Offline regression + end-to-end workflow

```bash
cd ~/Desktop/HunterQA-AI
source .venv/bin/activate

python -m compileall -q hunterqa zeroscope
python -m pytest -q
bash tools/verify_agent_1_2.sh
```

- Runs existing v1.1 scope checks and the v1.2 offline research workflow using disposable files.
- Checks API inventory, specialist plan, evidence correlation, review dossier, reproduction-note fixture, report draft, repeatability and synthetic benchmark.
- Exercises **11 local dashboard routes** and verifies a source ZIP with per-file SHA-256.
- **Does not scan any external website.**
- A passing test run verifies expected software behavior, **not** real-world vulnerability-detection accuracy.

### Optional real Chromium testing

```bash
python -m pip install -e '.[dev,browser]'
python -m playwright install chromium

HUNTERQA_REAL_BROWSER_CI=1 \
  python -m pytest -q tests/test_browser_lab_playwright_v12.py
```

- These tests launch a disposable owned `127.0.0.1` server and check a permitted login and blocked cross-port redirect.
- Browser routes are **not a network firewall**. Run untrusted browser code only in a network-isolated lab.
- Take a new snapshot named **HunterQA v1.2.0 — tested install** once your local tests pass.

## 5. First complete offline workflow

**Goal:** use the included fictional JSON data to get review candidates, a specialist plan, correlated evidence and a human-review dossier **with zero external HTTP requests**.

### Step 1 — Copy samples to your PRIVATE workspace

```bash
cd ~/Desktop/HunterQA-AI
source .venv/bin/activate

folder="$HOME/ZeroScope-AI/research-lab/v12"

cp examples/bounty_profile.example.json "$folder/profile.json"
cp examples/bounty_targets.example.txt "$folder/targets.txt"
cp examples/v12_owned_api_openapi.json "$folder/openapi.json"

export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"
```

- The example domain **`app.example.test` is fictional**.
- Use sample files only for offline examples; **never send network scans or real HTTP assessments to this domain**.
- A program profile is an explicit record of authorization boundaries, **not evidence that a third party granted permission**.

### Step 2 — Analyze a local API contract

```bash
hunterqa bounty-api-inventory \
  --profile "$folder/profile.json" \
  --spec "$folder/openapi.json" \
  --out "$folder/inventory-001.json" --authorized
```

- **Purpose:** list local API routes, methods, declared security and manually reviewable object/authorization cues.
- **Limitation:** the schema cannot prove that a deployed service is vulnerable.

### Step 3 — Plan analyst-agent roles

```bash
hunterqa bounty-agent-plan \
  --profile "$folder/profile.json" \
  --spec "$folder/openapi.json" \
  --targets "$folder/targets.txt" \
  --out "$folder/plan-001.json" --authorized
```

- **Purpose:** make a non-executing plan for the fixed specialist research roles.
- **Limitation:** this command doesn't launch automatic exploitation or approve new targets.

### Step 4 — Correlate evidence offline

```bash
hunterqa bounty-correlate \
  --profile "$folder/profile.json" \
  --file "$folder/inventory-001.json" \
  --out "$folder/correlation-001.json" --authorized
```

- **Purpose:** deduplicate only known candidate signals with matching policy provenance.
- **Limitation:** correlated observations are still **unverified**.

### Step 5 — Create an analyst review dossier

```bash
hunterqa bounty-review-init \
  --profile "$folder/profile.json" \
  --correlation "$folder/correlation-001.json" \
  --out "$folder/dossier-001.json" --authorized
```

- **Purpose:** create a case list for manual evidence review.
- **Do not mark a synthetic candidate validated merely to make the report export succeed.**

### Step 6 — View finding IDs

```bash
python - "$folder/dossier-001.json" <<'PY'
import json
import sys
from pathlib import Path

dossier = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for item in dossier["cases"]:
    print(item["id"], item["rule_id"], item["status"])
PY
```

- Use the exact **20-character case ID** for later decisions.
- Outputs are private and **create-only**; reruns must use **new filenames** such as `inventory-002.json`.

## 6. Configure optional local Qwen AI

- Install [Ollama for Linux](https://ollama.com/download/linux) using its official setup instructions.
- Start the local Ollama service, then obtain the approved model:

```bash
ollama pull qwen2.5-coder:3b
ollama list
```

- Use the supported local model `qwen2.5-coder:3b` or `qwen2.5-coder:7b`; the larger model needs more resources.
- With the local model running, review the saved specialist plan:

```bash
hunterqa bounty-ai-review \
  --plan "$folder/plan-001.json" \
  --model qwen2.5-coder:3b \
  --out "$folder/ai-review-001.json" --authorized
```

- **Purpose:** prioritizes **known**, approved analyst review roles from aggregate local plan metadata.
- **Safety:** AI output cannot execute arbitrary shell commands or change the target allowlist.
- **Result:** hypothesis/prioritization, **not** proof of a flaw.

## 7. Start and use the web dashboard

```bash
cd ~/Desktop/HunterQA-AI
source .venv/bin/activate

folder="$HOME/ZeroScope-AI/research-lab/v12"
export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"
export HUNTERQA_SECRET_KEY="$(cat "$HOME/.config/hunterqa/session-key")"

export HUNTERQA_API_SURFACE_REPORT="$folder/inventory-001.json"
export HUNTERQA_AGENT_PLAN="$folder/plan-001.json"
export HUNTERQA_AGENT_CORRELATION_REPORT="$folder/correlation-001.json"
export HUNTERQA_REVIEW_DOSSIER="$folder/dossier-001.json"

python run.py
```

| Local address | What it's for |
| --- | --- |
| `http://127.0.0.1:5000/` | Overview and local research dashboard |
| `http://127.0.0.1:5000/bounty` | Authorized Bug Bounty Lab |
| `http://127.0.0.1:5000/agent-lab` | Agent roles, API findings, validation and benchmark summaries |

- Other available routes include Projects, Research, Triage, Analytics, Trends, CVE Intelligence, Capabilities and Audit.
- Visiting `/bounty` or `/agent-lab` **does not start an active scan**.
- Stop the server with **Ctrl+C** in the terminal.
- Do not publish the Flask development service to the internet.

## 8. How to perform authorized security assessments

Follow these phases for **owned applications or systems with explicit written permission**.

### Phase 0 — Authorization and assessment plan

- Identify the real asset owner and obtain written testing permission.
- List exact **hosts, ports, paths, IPs, allowed methods, exclusions and test accounts**.
- Confirm permitted activity: document/source review, low-noise HTTP checks, service discovery, authenticated tests, scanning, fuzzing, reporting.
- Agree on **time window, rate limits, emergency contact and immediate stop conditions**.
- Avoid other users' private data, destructive changes, financial operations and DoS/stress tests.

### Phase 1 — Inventory the attack surface

- Collect authorized source, API specifications, architecture, dependencies, configurations and test accounts.
- Document important entry points:
  - Login/session flows and permission checks.
  - Public versus restricted API paths.
  - Resource identifiers and owner/tenant boundaries.
  - Sensitive operations, file uploads and dependency services.
- Use `bounty-api-inventory` for **offline** OpenAPI review.
- For service discovery, use only approved tools/ranges in an **owned lab**; open ports do not automatically mean vulnerabilities.

### Phase 2 — Static security checks

- Ask the CLI for the exact supported commands:

```bash
hunterqa audit --help
hunterqa scan --help
hunterqa campaign --help
hunterqa trust-graph --help
hunterqa cve-check --help
hunterqa import-sarif --help
```

- Review local code/configurations for:
  - Secrets, unsafe defaults and debug features.
  - Authentication and object-level authorization.
  - Input validation, SQL query construction, unsafe deserialization.
  - File handling/path traversal and sensitive information exposure.
  - CORS, sessions, cookie attributes and security headers.
  - Dependency versions against local advisory data.
- Use local Semgrep/SARIF sources where available.
- A rule match or advisory association is only a **research candidate** until validated.

### Phase 3 — Non-destructive application security checks

- **Authentication:** confirm sign-in/session boundaries with owned accounts; no credential stuffing.
- **Authorization:** compare two owned test identities to confirm that each is limited to its permitted data.
- **Sessions:** inspect normal cookie protections and expected logout behavior.
- **API controls:** compare declared methods, intended access and actual authorized behavior.
- **Inputs:** test with harmless synthetic values; avoid destructive payloads or oversized traffic.
- **Configuration:** inspect TLS, headers, CORS, debug exposure and unnecessary services.
- **Availability:** never load-test, fuzz production at scale or disrupt service without separate written approval.
- Record status codes, configuration observations and actual behavior—but distinguish them from verified impact.

### Phase 4 — Reproduce and assess impact

- Select one candidate and document **expected** versus **observed** behavior.
- Reproduce with the **minimum safe steps**, using permitted test identities and owned data.
- Confirm the affected version, asset, prerequisites and repeatability.
- Explain tangible confidentiality/integrity/availability impact, not just a scary scanner title.
- Assign severity from demonstrated conditions and impact; note any uncertainty.
- Record false positives and non-reproducible reports accurately.

### Phase 5 — Remediate, retest and disclose

- Suggest fixes such as correct server-side authorization, input validation, least privilege, patching and safe configuration.
- Retest in an approved environment.
- Prepare a private security report with impact, reproduction steps, evidence and remediation.
- Follow the owner's program rules and coordinated disclosure window.
- Never upload sensitive evidence or unannounced vulnerability details publicly.

## 9. HTTP observations, scope and HAR

### Create a **real, explicitly approved** scope profile

```bash
cp examples/bounty_profile.example.json \
  "$folder/approved-real-profile.json"
```

- Edit `allowed_hosts`, `excluded_hosts`, `allowed_paths`, `excluded_paths`, `methods`, `allowed_ports`, `max_requests`, `interval_seconds` and `authorization_reference`.
- Use the **actual approved program policy**, not the fictional example.
- Create a private file `$folder/approved-real-targets.txt` with one exact approved URL per line.
- The following preflight is **offline** and does not establish permission on its own:

```bash
hunterqa bounty-preflight \
  --profile "$folder/approved-real-profile.json" \
  --targets "$folder/approved-real-targets.txt" --method HEAD
```

### Optional live HEAD observation

**Only when the asset owner/program explicitly permits these automated requests:**

```bash
hunterqa bounty-assess \
  --profile "$folder/approved-real-profile.json" \
  --targets "$folder/approved-real-targets.txt" \
  --method HEAD \
  --out "$folder/http-head-001.json" --authorized
```

- This **does send HTTP requests**. It applies exact scope and budget restrictions.
- Stop on authorization denials, rate limits, server errors or owner instructions.
- It has no WAF bypass, proxy rotation or automatic exploitation.

### Offline import of an authorized HAR

```bash
hunterqa bounty-import-har \
  --profile "$folder/approved-real-profile.json" \
  --har "$folder/authorized-capture.har" \
  --out "$folder/imported-har-001.json" --authorized
```

- This import is **offline**.
- Raw HAR may contain authentication tokens and private records; protect the original.

### Optional conservative HEAD replay

```bash
hunterqa bounty-replay-head \
  --profile "$folder/approved-real-profile.json" \
  --har-report "$folder/imported-har-001.json" \
  --out "$folder/replayed-head-001.json" --authorized
```

- Replay **sends real network HEAD requests**, so it needs separate active-traffic permission.
- It doesn't forward user cookies, sessions or request bodies.
- Comparing two replay reports is **offline**:

```bash
hunterqa bounty-repeatability \
  --profile "$folder/approved-real-profile.json" \
  --first "$folder/replayed-head-001.json" \
  --second "$folder/replayed-head-002.json" \
  --out "$folder/repeatability-001.json" --authorized
```

- Stable or changed response codes are **not** vulnerability proofs.
- Additional rules: [Authorized Bounty Guide](docs/BUG_BOUNTY_V1_1.md).

## 10. Playwright owned-browser lab

- **Only supported for a test application you own**, bound to `127.0.0.1` on one explicitly approved port.
- Install browser support as shown in section 4.
- Use a private profile with:
  - `platform: "local-lab"`
  - `allowed_hosts: ["127.0.0.1"]`
  - `allowed_ports: [8765]` (or your actual test port)
  - `methods: ["GET","HEAD"]`
  - `lab_mode: true`, `allow_private_network: true`, `allow_http: true`
  - Correct allowed/excluded paths and request budgets.
- With your owned app genuinely running, the basic command is:

```bash
hunterqa bounty-browser-lab \
  --profile "$folder/browser-scope.json" \
  --url "http://127.0.0.1:8765/" \
  --out "$folder/browser-observation-001.json" --authorized
```

- A single explicitly allowed login POST is optional; see the [Browser Lab Guide](docs/BROWSER_LAB_V1_2.md) for `--login --login-post-path /login` and selector/credential requirements.
- Outputs contain hashes and counts, **not HTML, passwords, cookies or screenshots**.
- Playwright request guards are **not a firewall**. Use a disposable OS/network-isolated lab.

## 11. Validate findings and create a security report

### Review statuses

| Decision | When to use |
| --- | --- |
| `needs_more_evidence` | Not enough support to decide |
| `not_reproducible` | Behavior could not be repeated |
| `false_positive` | Initial issue hypothesis is unsupported |
| `out_of_scope` | Testing is not authorized |
| `analyst_validated` | A permitted analyst attests to controlled reproduction; third-party impact remains unverified |

### Record a case decision

```bash
hunterqa bounty-review-decide \
  --profile "$folder/profile.json" \
  --dossier "$folder/dossier-001.json" \
  --case REPLACE_WITH_EXACT_20_HEX_CASE_ID \
  --decision needs_more_evidence \
  --reviewer local_analyst \
  --out "$folder/dossier-002.json" --authorized
```

- All updated dossiers must use **new filenames**; earlier versions remain untouched.
- A `false_positive`, `not_reproducible` or `needs_more_evidence` case must **not** be exported as a proven vulnerability.

### Only after genuine authorized reproduction

- Create a `bounty-reproduction-note` with the **same policy, case ID and analyst alias**, using truthful `--expected` and `--observed` information plus `--attest`.
- Then use `bounty-review-decide --decision analyst_validated` with human-authored `--impact`, `--reproduction`, and the matching `--evidence` note.
- Do not create an attestation unless you actually performed the approved test.
- See [Analyst Review & Disclosure Guide](docs/REVIEW_V1_2.md) for exact reviewed CLI examples.

### Export a validated private Markdown draft

```bash
hunterqa bounty-review-export \
  --profile "$folder/profile.json" \
  --dossier "$folder/dossier-validated-002.json" \
  --out "$folder/private-disclosure-draft.md" --authorized
```

- This works **only when the given dossier contains analyst-validated cases**. Filename is an example; don't use a nonexistent dossier.
- HunterQA does not submit findings automatically.

### Your final security report should contain

- Assessment title, tester, date and written scope.
- Executive summary of what was reviewed.
- Exact tools, package versions, and allowed methods.
- Finding category, affected approved asset and impacted feature.
- Expected behavior, actual result and minimal safe reproduction.
- Evidence summary, artifact hashes and private storage locations.
- Real impact, severity, assumptions and confidence.
- Proposed remediation, retest procedure, exclusions and remaining risks.
- Disclosure/retest owner and current status.

## 12. Other tools and commands

| CLI command | Purpose | Safety boundary |
| --- | --- | --- |
| `hunterqa scan`, `audit`, `trust-graph` | Local source/configuration review | Local approved projects |
| `hunterqa campaign` | Bounded local source research campaign | Explicitly approved local inputs |
| `hunterqa hypothesize` | Optional local LLM research hypotheses | Not validated evidence |
| `hunterqa import-sarif` | Review existing SARIF results | Doesn't execute the scanner |
| `hunterqa cve-check` | Compare local dependency/advisory snapshot | Doesn't prove deployment exposure |
| `hunterqa parse-sanitizer`, `verify-crashes` | Research owned crash/sanitizer evidence | Isolated lab only |
| `hunterqa bounty-campaign` | Local SAST, optional HAR/advisory and optional web observations | `--with-web` requires actual permission |
| `hunterqa bounty-benchmark` | Synthetic OpenAPI review-prompt scoring | **Not real-world vulnerability accuracy** |
| `hunterqa bounty-report` | Create human-reviewed bounty report draft | Does not submit externally |

- Use `hunterqa COMMAND --help` to see exact arguments rather than guessing.
- Read [README.md](README.md), [Architecture](docs/ARCHITECTURE.md), [Security Policy](SECURITY.md) and [v1.2 Release Notes](docs/RELEASE_1_2_0.md).

## 13. Updates, backups and versions

### Update to the latest reviewed main checkout

```bash
cd ~/Desktop/HunterQA-AI
git status --short --untracked-files=all
git fetch origin --tags
git switch main
git pull --ff-only origin main

source .venv/bin/activate
python -m pip install -e '.[dev]'
hunterqa --version
bash tools/verify_agent_1_2.sh
```

- Check and preserve uncommitted local code before switching branches.
- Back up private research data and `instance/hunterqa.sqlite3` using encrypted, authorized storage.
- Never force-reset to discard a private evidence file or bypass a protected branch.
- The current `main` branch can change after v1.2.0; use a tagged checkout to reproduce an exact historical release.
- GitHub releases are under [Releases](https://github.com/ManeaAl-Shabrain/HunterQA-AI/releases).
- Verify the matching official ZIP and checksum after download:

```bash
sha256sum -c HunterQA-AI-1.2.0-source.zip.sha256
```

- Expected: `OK`. A checksum checks file integrity against the provided digest; it is not an external authenticity certification.

## 14. Troubleshooting

| Problem | Action |
| --- | --- |
| `hunterqa: command not found` | Activate `.venv`; run `python -m hunterqa --help` |
| `No module named hunterqa` | From project root, run `python -m pip install -e '.[dev]'` |
| Unsupported Python version | Run `python3 --version`; use Python 3.11+ |
| Permission or approved-root failure | Check `HUNTERQA_APPROVED_ROOTS` and whether the exact local file resides inside it |
| Output already exists | Use a **new** `--out` filename; files are intentionally create-only |
| Preflight denies a target | Fix the policy/target mismatch; **do not bypass** the denied scope |
| Ollama unavailable | Check local service, `ollama list`, supported model name and RAM |
| Chromium missing | Install `.[dev,browser]`, Chromium and required Linux libraries |
| Dashboard unavailable | Run `python run.py` in the venv, verify port 5000 and local session key |
| Git pull fails with local edits | Inspect `git status`, save changes and retry; don't force reset |
| Tests fail | Read the first error and address it before treating the installation as ready |

## 15. Final readiness checklist

- [ ] Kali VM installed, updated and snapshotted.
- [ ] Python 3.11+, Git and private venv configured.
- [ ] HunterQA cloned, installed and version verified.
- [ ] `hunterqa doctor` and `hunterqa capabilities` work.
- [ ] Full offline acceptance passes without external targets.
- [ ] Optional local Ollama and owned Chromium lab work where needed.
- [ ] Private research folders are outside Git, with restrictive permissions.
- [ ] Real scope and written authorization exist **before any live check**.
- [ ] Approved hosts, paths, accounts, methods and rate limits are documented.
- [ ] Every candidate is marked honestly as unverified, false-positive, unrepeatable or analyst-validated.
- [ ] Reproduction evidence is truthful and scoped.
- [ ] Final report includes real impact, remediation and limitations.
- [ ] No secrets, credentials, private HAR, SQLite, customer data or raw vulnerability evidence are uploaded publicly.

---

## Official project references

- [HunterQA AI README](README.md)
- [v1.2.0 Stable Release](docs/RELEASE_1_2_0.md)
- [Kali Workflow](docs/V1_2_DEV.md)
- [Bug Bounty Authorization](docs/BUG_BOUNTY_V1_1.md)
- [Owned Chromium Browser Lab](docs/BROWSER_LAB_V1_2.md)
- [Finding Verification & Disclosure](docs/REVIEW_V1_2.md)
- [Synthetic Benchmark](docs/BENCHMARK_V1_2.md)
- [Versioning Policy](docs/VERSIONING.md)
- [Security Policy](SECURITY.md)

**Rule of thumb:** **permission → scope → inventory → safe review → manual reproduction → severity → remediation → private report**. HunterQA supports the workflow, but does not replace the human responsibility to verify findings and follow testing rules.
