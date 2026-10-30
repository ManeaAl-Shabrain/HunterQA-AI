# HunterQA — Zero to Start

Get from installation to a working local lab with retained evidence. You do not
need a website, customer credentials, an AI model or a cloud account.

Use **current source**: the package reports `1.3.0`, but the original v1.3.0
archive lacks later lab/review commands. This is a bounded owned-fixture
benchmark, not a full attack or proof of complete coverage.

## 1. Install

### Kali / Linux

Use Python 3.11+:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip
git clone https://github.com/ManeaAl-Shabrain/HunterQA-AI.git
cd HunterQA-AI
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
hunterqa --version
git rev-parse HEAD
```

### Windows PowerShell

Install Python 3.11+ and Git first. No script execution policy change is needed:

```powershell
git clone https://github.com/ManeaAl-Shabrain/HunterQA-AI.git
cd HunterQA-AI
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\hunterqa.exe --version
git rev-parse HEAD
```

Already installed? Preserve local edits, switch to a clean `main` checkout, run
`git pull --ff-only`, then repeat the installation command. Do not update during
an active assessment. Back up the complete private case directory first.
Record the commit with your evidence; the version number alone is insufficient.

## 2. Create a private workspace

Keep the same terminal open in the repository directory. Choose the commands
for your operating system; the environment variables apply to this terminal only.

Linux:

```bash
umask 077
mkdir -p "$HOME/hunterqa-private"
chmod 700 "$HOME/hunterqa-private"
export HUNTERQA_APPROVED_ROOTS="$HOME/hunterqa-private"
export HUNTERQA_LAB="$HOME/hunterqa-private/lab-$(date +%Y%m%d-%H%M%S)"
hunterqa assessment-readiness
```

Windows:

```powershell
$caseRoot = Join-Path $env:USERPROFILE 'hunterqa-private'
New-Item -ItemType Directory -Path $caseRoot -Force | Out-Null
$env:HUNTERQA_APPROVED_ROOTS = $caseRoot
$env:HUNTERQA_LAB = Join-Path $caseRoot ('lab-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
.\.venv\Scripts\hunterqa.exe assessment-readiness
```

Use a private Windows account directory with suitable access permissions. Expect
`installation_ready: true`; lab evidence has not yet been provided. Optional
missing packages do not prevent the built-in HTTP/TCP lab.

## 3. Run the owned lab

This step authorizes testing of HunterQA’s own loopback fixture only. It starts
the service, runs four bounded workflows, saves evidence and closes the service.
No external target is accepted.

Linux:

```bash
hunterqa assessment-benchmark --out-dir "$HUNTERQA_LAB" --authorized
hunterqa assessment-readiness --benchmark-dir "$HUNTERQA_LAB" --require-owned-lab
```

Windows:

```powershell
.\.venv\Scripts\hunterqa.exe assessment-benchmark --out-dir $env:HUNTERQA_LAB --authorized
.\.venv\Scripts\hunterqa.exe assessment-readiness --benchmark-dir $env:HUNTERQA_LAB --require-owned-lab
```

| Expected result | Meaning |
| --- | --- |
| `all_cases_matched: true` | Eight application cases and three workflow controls matched |
| `network_requests: 18` in the benchmark | 16 fixture HTTP requests and two TCP connections recorded |
| `supported_owned_lab_checks_passed: true` | Installation and recomputed current-runtime evidence passed |
| `real_world_effectiveness: unverified` | This does not measure field accuracy or complete coverage |
| `production_multi_user_ready: false` | Hosted multi-tenant production use is not ready |

Cases cover inert markup reflection, SQL-error cues, access contracts, HTML
links/forms, scope/privacy and open/refused TCP connections. Findings remain
unverified candidates. This does not prove executable XSS or general SQL injection
exploitability, and does not exercise all 79 catalog entries.

## 4. Read the evidence

Open the private directory named by `HUNTERQA_LAB` in your file manager.

| Artifact | Purpose |
| --- | --- |
| `benchmark.json` | Expected/observed cases, metrics and workflow controls |
| `ground-truth.json` | Versioned expected labels |
| `web-canary-check-run/report.html` | Printable reflection/SQL-error candidate report |
| `authorization-matrix-run/report.html` | Access-contract candidate report |
| Each `*-run` directory | Workflow state, reports, audit and network evidence |

Keep the whole directory. Readiness recomputes retained evidence; the summary
alone is insufficient. Hashes check consistency, not independent authenticity.

To view the canary run on the local dashboard, in the same terminal:

```bash
# Linux
export HUNTERQA_WORKFLOW_RUN="$HUNTERQA_LAB/web-canary-check-run"
python run.py
```

```powershell
# Windows
$env:HUNTERQA_WORKFLOW_RUN = Join-Path $env:HUNTERQA_LAB 'web-canary-check-run'
.\.venv\Scripts\python.exe run.py
```

Open `http://127.0.0.1:5000/workflows`. Stop the server with Ctrl+C. Optional local
accounts are described in [operator access](docs/OPERATOR_ACCESS.md).

Export or print `report.html` from your browser to save a PDF. After recording
analyst decisions, use `workflow-export` to create an updated report; the original
HTML does not refresh itself. See the [command reference](docs/COMMAND_REFERENCE.md)
for commands and their execution modes.

## 5. Choose your next task

| Task | Guide |
| --- | --- |
| Check implemented and missing features | [Feature checklist](docs/FEATURE_READINESS_CHECKLIST.md) |
| Choose a category/evidence reader | [23-category index](docs/CATEGORY_REVIEW_INDEX.md) |
| Prepare an approved organization assessment | [Beginner’s guide](docs/AUTHORIZED_ASSESSMENT_BEGINNER_GUIDE.md) and [templates](templates/README.md) |
| Run selected adapters with reviewed approvals | [Workflow runner](docs/WORKFLOW_RUNNER.md) and [adapters](docs/ASSESSMENT_ADAPTERS.md) |
| Try fixed HTTP SQL/XSS controls with Chromium | [Controlled runtime validation](docs/CONTROLLED_RUNTIME_VALIDATION.md) |
| Verify a saved signed ID token or run owned OIDC/session controls | [Identity assurance](docs/OIDC_SESSION_ASSURANCE.md) |
| Review report quality or CVSS 3.1 Base | [Utility guide](docs/UTILITY_REVIEW.md) |

A customer assessment is separate. It needs written permission, exact targets,
methods, limits, dates and checkpoints. Fill private copies of templates outside
this repository. A URL or `--authorized` flag alone is not permission or a test plan.

## Troubleshooting

| Problem | Action |
| --- | --- |
| Command not found | Activate `.venv` on Linux; use the full executable path on Windows |
| Lab command unknown | Update current source and reinstall; the old archive lacks it |
| Outside approved roots | Set `HUNTERQA_APPROVED_ROOTS` to an existing absolute private directory in this terminal |
| Output already exists | Choose a fresh lab name and preserve the previous run |
| Evidence is `stale` | After code/dependency changes, run again into a new directory |
| Evidence is `invalid` | Retain the failed run, inspect missing/changed artifacts and rerun after fixing the cause |
| Quota admission fails | Review the configured shared ledger and authorized remaining budget |

The built-in lab needs only the core installation. Install optional dependencies
**before** producing evidence: `.[cloud]` for AWS account checks, `.[browser]` plus
Playwright Chromium for browser workflows, or `.[dev,quality]` for developer
verification. Semgrep and Ollama are separate optional tools. See
[readiness](docs/READINESS.md) for further setup and verification commands.
