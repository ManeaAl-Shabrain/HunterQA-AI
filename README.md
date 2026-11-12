# HunterQA

![HunterQA cybersecurity workflow: scope, assess, evidence and report](docs/assets/hunterqa-cybersecurity-infographic.png)

HunterQA is a local workspace for authorized security assessments. Review code
and saved evidence, run selected checks within an approved scope, and produce
reports you can review and retest. It starts locally; separate workspace profiles
add approved accounts, Local/Google/Entra sign-in and administrator MFA.

**Python 3.11+ · Kali/Linux recommended · CLI and local dashboard**

[Zero to Start](<zero to start.md>) ·
[Beginner’s assessment guide](docs/AUTHORIZED_ASSESSMENT_BEGINNER_GUIDE.md) ·
[Templates](templates/README.md) · [Category index](docs/CATEGORY_REVIEW_INDEX.md)

For your own computer, use [localhost setup](docs/PERSONAL_LOCALHOST_SETUP.md):
Local + MFA works offline; Google and Entra stay optional. No public domain or
hosting is required.

## Is it ready?

**Ready for supported local review workflows and the built-in owned lab.** It is
still a development platform, not a complete autonomous pentesting system or a
production multi-user service. Giving it a URL does not run every vulnerability
test or prove that a website is secure.

The package version remains **1.3.0**. Current `main` includes later development
features absent from the original [v1.3.0 release](https://github.com/ManeaAl-Shabrain/HunterQA-AI/releases/tag/v1.3.0).
Use current source for this guide. Record `git rev-parse HEAD` with your evidence;
the version number alone does not identify the installed features.

## Available capabilities

| Capability | Implemented today |
| --- | --- |
| Source/configuration review | Selected built-in checks; optional Semgrep and local Ollama suggestions |
| Web observations | Scoped HEAD/GET and HTML discovery; opt-in same-origin HTTPS JavaScript/cookie-session discovery |
| Owned browser lab | Optional JavaScript-rendered links and local login context, restricted to owned loopback |
| Owned SQL lab | Eight fixed in-memory impact/control cases and deterministic evidence replay |
| Controlled validation | Fixed owned-endpoint SQL canary differentials and Chromium XSS witnesses; baseline/negative/repeat controls |
| Validation cues | Fixed inert-markup/SQL-error comparisons and explicit role/anonymous access contracts |
| Identity assurance | Optional offline RS256 ID-token verification; owned OIDC/PKCE/session/tenant HTTP fixtures |
| Infrastructure/cloud | Scoped TCP/TLS, SSH identification and UDP DNS; selected AWS/Azure/GCP queries |
| Workspace access | Separate identity/data stores, local roles, independent Local/Google/Entra login, encrypted admin TOTP and a controlled HTTPS gateway |
| Saved evidence review | Selected API, identity, cloud, container, network and other artifact readers |
| Category packs | 23 categories and 79 catalog entries, with implemented modes in the category index |
| Workflow controls | Scope checks, approvals, budgets, timeouts, stop requests and optional host-local shared quotas |
| Reporting | Analyst review, HTML/JSON/SARIF exports, retest comparison, report-quality checks and CVSS 3.1 Base arithmetic |
| Dashboard | Local workflow/evidence views; optional viewer, analyst and admin accounts |

Catalog entries include guided and declaration-based reviews. They are not 79
automated attack modules. Saved settings and scanner candidates need independent
review; neither confirms exploitability by itself.

## Install and try the lab

On Kali/Linux:

```bash
git clone https://github.com/ManeaAl-Shabrain/HunterQA-AI.git
cd HunterQA-AI
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
hunterqa --version

umask 077
mkdir -p "$HOME/hunterqa-private"
chmod 700 "$HOME/hunterqa-private"
export HUNTERQA_APPROVED_ROOTS="$HOME/hunterqa-private"
export HUNTERQA_LAB="$HOME/hunterqa-private/lab-$(date +%Y%m%d-%H%M%S)"
hunterqa assessment-benchmark --out-dir "$HUNTERQA_LAB" --authorized
hunterqa assessment-readiness --benchmark-dir "$HUNTERQA_LAB" --require-owned-lab
```

The lab starts and closes its own `127.0.0.1` service. It tests eight labeled
application cases and three discovery/TCP controls across four workflows, keeping
evidence in your private directory. It accepts no external target. A normal run
records 18 network operations. Passing establishes only this fixture baseline,
not general exploitability or real-world effectiveness.

[Zero to Start](<zero to start.md>) covers Windows, expected results, reports and
troubleshooting. Use a fresh output directory for each run.

## What remains incomplete

All seven broad assessment areas remain **partial**. Rendered discovery supports
bounded same-origin anchors, selected slash hash routes and conventional cookie login.
General authenticated target crawling, comprehensive active vulnerability validation, target SSO and
business workflows, OS/AD attack paths, broad multi-cloud permissions, hosted
independently validated tenant isolation, independently verified owner grants, OS isolation and
distributed enforcement remain unfinished. Real-world detection effectiveness is **unverified**.

The SQL lab is a separate in-memory fixture; it does not validate the HTTP
SQL-error scanner or establish customer findings. See the [SQL lab guide](docs/OWNED_SQL_VALIDATION.md).

See the [feature checklist](docs/FEATURE_READINESS_CHECKLIST.md) before choosing
an engagement. Authorization does not enable missing functionality.

## Guides

| Need | Read |
| --- | --- |
| First approved assessment | [Beginner’s guide](docs/AUTHORIZED_ASSESSMENT_BEGINNER_GUIDE.md) and [templates](templates/README.md) |
| CLI commands and execution modes | [Command reference](docs/COMMAND_REFERENCE.md) |
| Rendered links, selected SPA routes and reference coverage | [Scoped browser guide](docs/SCOPED_RENDERED_DISCOVERY.md) |
| Runtime checks and per-class metrics | [Controlled validation](docs/CONTROLLED_RUNTIME_VALIDATION.md) |
| Signed tokens and OIDC/session fixtures | [Identity assurance](docs/OIDC_SESSION_ASSURANCE.md) |
| Certificate and hostname verification on one approved endpoint | [Scoped TLS inspection](docs/SCOPED_TLS_INSPECTION.md) |
| Observe one approved SSH endpoint's advertised identification | [Scoped SSH identification](docs/SCOPED_SSH_IDENTIFICATION.md) |
| One approved UDP DNS question and expected-answer comparison | [Scoped UDP DNS inspection](docs/SCOPED_UDP_DNS_INSPECTION.md) |
| Bounded Azure resource inventory with an explicit temporary token | [Azure inventory](docs/SCOPED_AZURE_INVENTORY.md) |
| Bounded GCP project asset inventory with an explicit temporary token | [GCP inventory](docs/SCOPED_GCP_INVENTORY.md) |
| Query selected permissions reported for a supplied GCP caller token | [GCP permission check](docs/SCOPED_GCP_PERMISSIONS.md) |
| Understand Azure/GCP request time bounds and slow-response handling | [Cloud transport deadlines](docs/CLOUD_TRANSPORT_DEADLINES.md) |
| Expansion status | [Seven-area progress](docs/EXPANSION_PROGRESS.md) |
| Shared local limits for workflows and native TLS/SSH/DNS/cloud commands | [Native shared quotas](docs/NATIVE_SHARED_QUOTAS.md) |
| Workflow planning/approvals | [Workflow runner](docs/WORKFLOW_RUNNER.md) |
| Adapters and shared quotas | [Adapter guide](docs/ASSESSMENT_ADAPTERS.md) |
| Lab evidence and readiness | [Readiness](docs/READINESS.md) |
| Workspace accounts, SSO and controlled serving | [Workspaces](docs/PRODUCTION_WORKSPACES.md) and [OIDC](docs/OPERATOR_SSO.md) |
| Local, Google and Entra login with mandatory Admin MFA | [Unified authentication](docs/UNIFIED_AUTHENTICATION.md) |
| Linux Compose/systemd profile and WSL2 setup | [Deployment guide](docs/LINUX_DEPLOYMENT.md), [accepted requirements and gaps](docs/ACCEPTED_PLATFORM_REQUIREMENTS.md) |
| Private workspace backup, recovery and credential renewal | [Recovery guide](docs/WORKSPACE_RECOVERY.md) |
| Production acceptance and remaining gaps | [Completion gates](docs/PRODUCTION_COMPLETION.md) |
| All category guides | [Category index](docs/CATEGORY_REVIEW_INDEX.md) |
| Report quality/scoring | [Utility guide](docs/UTILITY_REVIEW.md) |
| Release packaging/version policy | [Versioning](docs/VERSIONING.md) |
| Releases/security reports | [Releases](https://github.com/ManeaAl-Shabrain/HunterQA-AI/releases) and [security policy](SECURITY.md) |

Use only systems you own or have explicit written permission to assess, within
the agreed scope. Keep completed templates, credentials and client evidence
outside this repository. `--authorized` records your acknowledgement; it does not
verify ownership or replace written approval.
