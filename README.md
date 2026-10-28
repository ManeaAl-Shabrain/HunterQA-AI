# HunterQA AI

![HunterQA cybersecurity infographic: scope, review, assess, evidence, verify, report](docs/assets/hunterqa-cybersecurity-infographic.png)

**A local-first cybersecurity assessment workspace for explicitly authorized research.**

Plan controlled assessments, inspect source and API evidence, run fixed approved workflows, review findings, and produce traceable reports.

**Version:** v1.3.0 · **Python:** 3.11+ · **Primary platform:** Kali/Linux · **Deployment:** local, single operator

[Zero to Start](<zero to start.md>) · [Authorized Assessment — Beginner’s Guide](docs/AUTHORIZED_ASSESSMENT_BEGINNER_GUIDE.md) · [Templates folder](templates/README.md)

[Release notes](docs/RELEASE_1_3_0.md) · [Workflow guide](docs/WORKFLOW_RUNNER.md) · [Security policy](SECURITY.md) · [Published releases](https://github.com/ManeaAl-Shabrain/HunterQA-AI/releases)

> **Published release:** [v1.3.0](https://github.com/ManeaAl-Shabrain/HunterQA-AI/releases/tag/v1.3.0). Historical tags and assets remain immutable. The additional beginner assessment guide and templates are post-release documentation available on current `main`; they are not included in the original v1.3.0 archive.

## Start here

| Order | Important resource | What to do |
| --- | --- | --- |
| 1 · Install | [zero to start.md](<zero to start.md>) | Set up Kali/Linux, verify HunterQA and complete the owned offline lesson. |
| 2 · Understand | [Authorized Assessment — Beginner’s Guide](docs/AUTHORIZED_ASSESSMENT_BEGINNER_GUIDE.md) | Follow the first organization-approved assessment: permission, scope, plan review, observation and evidence. |
| 3 · Prepare | [templates folder](templates/README.md) | Copy the scope/target templates and approval, run, report and retest worksheets to a private case directory; follow the folder README. |

The templates include the same [scope JSON](templates/HunterQA-scope-template.json),
[target TXT](templates/HunterQA-targets-template.txt) and
[configuration-review instructions](templates/HunterQA-first-configuration-review.md)
provided in the beginner walkthrough. Fill private copies outside this public
repository; do not upload organization approvals, contacts or assessment evidence.

## Navigate

1. [Start here](#start-here)
2. [What is included](#what-is-included)
3. [Install and verify](#install-and-verify)
4. [Choose a workflow](#choose-a-workflow)
5. [Dashboard and reporting](#dashboard-and-reporting)
6. [Command reference](#command-reference)
7. [Controls and limits](#controls-and-limits)
8. [Updates and releases](#updates-and-releases)

## What is included

| Area | Available in 1.3.0 | Interpretation |
| --- | --- | --- |
| Workflow execution | Persistent run state, dependency scheduling, seven fixed adapters, explicit review checkpoints | A controlled local runner; no arbitrary tool execution |
| Runtime controls | Per-run request reservations, concurrency ceilings, supervised deadlines, emergency stop, independent worker watchdogs | Separate runs have independent budgets |
| Source and configuration | Semgrep CLI/campaign integration; configuration/OpenAPI/dependency inspection | Patterns and declarations are candidates |
| API and dependency evidence | Offline OpenAPI review, declared dependency inventory, local advisory matching | No automatic live CVE feed or proof of exploitability |
| Approved HTTP assessments | Exact HEAD/GET observations and separate expiring engagement plans | Explicit scope and permission required before traffic |
| Account/browser checks | Separate dedicated-account HTTPS check and narrow remote browser mode; owned loopback browser lab | Not integrated as general workflow workers |
| Evidence interoperability | Offline Nuclei HTTP JSONL/ZAP imports, SARIF import/export | Importing does not launch or authorize a scanner |
| Review and retesting | Project-aware deduplication, analyst attestations, evidence hashes, conservative run comparison | Missing findings are not automatically fixed |
| Reporting and interface | JSON, printable HTML, SARIF, saved-run dashboards | PDF through browser Print; no automatic upload |
| Research support | Original playbooks, private journals, optional local Ollama hypotheses, trust graph | Model suggestions never certify a vulnerability |
| Quality and packaging | Original synthetic fixtures, Linux CI, real Chromium lab tests, verified source manifest | Fixture scores are not real-world accuracy claims |

The workflow runner's `source-review` adapter performs configuration, JSON OpenAPI and declared dependency review. Semgrep, authenticated/browser checks and lab fuzzing retain their independent commands and controls.

## Install and verify

```bash
git clone https://github.com/ManeaAl-Shabrain/HunterQA-AI.git
cd HunterQA-AI

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev,quality]'

hunterqa --version
hunterqa doctor --json
python -m pytest -q
python tools/verify_release_1_3.py
```

Expected version for this source: **HunterQA AI 1.3.0**. Current `main` includes the latest documentation. The immutable `v1.3.0` tag preserves the published release snapshot; later documentation additions require current `main` or their separate downloads.

| Optional component | Needed for |
| --- | --- |
| Semgrep executable on PATH | `scan`, source campaigns and rule checks |
| Local Ollama with a supported Qwen model | Optional AI hypotheses/review |
| `.[browser]` and Playwright Chromium | Browser workflows and browser acceptance tests |
| Clang/AFL++ and an isolated owned lab | Executable crash/fuzz research |

Missing optional tools do not prevent the basic offline workflow. Follow the [full setup guide](<zero to start.md>) for prerequisites, private workspace creation and a complete demo.

## Choose a workflow

### ① Start offline

Set `HUNTERQA_APPROVED_ROOTS` to an explicitly authorized local directory. Keep source, configuration and run output in separate subdirectories.

```bash
hunterqa workflow-setup --help
hunterqa workflow-tools
hunterqa research-playbooks
```

`workflow-setup` creates a starter protocol and bindings without starting tests. The default starter is offline. Review the generated plan, then use `workflow-run` with its exact execution fingerprint and your operator reference.

### ② Run a reviewed assessment

```text
Written authorization + exact allowlist
                  ↓
Protocol + tool bindings + dependency review
                  ↓
Execution fingerprint + explicit checkpoint approvals
                  ↓
Supervised fixed workers + durable request reservations
                  ↓
Evidence → analyst decision → report → independent retest
```

Use `--observe` only for separately authorized bounded HTTP checks. Every active checkpoint needs explicit approval. See [runtime contracts and examples](docs/WORKFLOW_RUNNER.md).

For the separate engagement commands, follow `engagement-plan` → `engagement-preflight` → `engagement-run`. These commands retain their own exact-plan approvals, budgets and credential restrictions.

### ③ Review evidence

- Import existing Nuclei/ZAP files with `external-import`; neither scanner is launched.
- Record evidence-linked analyst decisions with `workflow-review`.
- Compare independently executed runs with `workflow-compare`.
- Keep raw scanner inputs, scope profiles, account secrets and SQLite outside the public repository.

## Dashboard and reporting

```bash
# In your prepared private workspace session:
export HUNTERQA_WORKFLOW_RUN="/absolute/path/to/your/run-001"
python run.py
```

Open **http://127.0.0.1:5000**. The app enforces loopback peer/Host checks and ignores forwarded headers for access decisions.

| View | Purpose |
| --- | --- |
| `/workflows` | Recorded run state, charged reservations, execution steps, selected coverage and triage |
| `/assessments` | Saved engagement observations and optional same-plan baseline |
| `/playbooks` | Original review checklists |
| Existing research, triage and agent views | Local source/evidence research and analyst workflows |

The new workflow view is read-only. Start, stop, reconcile and review from the CLI. Set `HUNTERQA_ENGAGEMENT_REPORT` and optional `HUNTERQA_ENGAGEMENT_BASELINE` for saved engagement views.

Every run writes `summary.json`, `report.html` and `report.sarif`. Export again after review to include new decisions. HTML supports browser Print → Save as PDF.

## Command reference

Use `hunterqa COMMAND --help` for required inputs. The modes below describe the command's behavior, not permission granted by its name.

<details>
<summary><strong>Open the complete command catalog</strong></summary>

| Group | Commands | Mode |
| --- | --- | --- |
| Diagnostics | `capabilities`, `doctor`, `--version` | Read-only diagnostics; optional doctor Ollama probe is loopback |
| Protocol design | `workflow-tools`, `workflow-preflight`, `workflow-setup`, `workflow-run-plan` | Offline planning |
| Workflow execution | `workflow-run`, `workflow-status`, `workflow-stop`, `workflow-abandon` | Fixed approved execution, inspection, cancellation and no-replay reconciliation |
| Workflow results | `workflow-review`, `workflow-compare`, `workflow-export`, `workflow-benchmark` | Private review/reports and synthetic fixtures |
| Source research | `scan`, `audit`, `campaign`, `trust-graph`, `hypothesize`, `propose-fix`, `cve-check` | Local source/advisory review; optional loopback AI |
| Evidence formats | `import-sarif`, `parse-sanitizer`, `research-report`, `report-sarif`, `external-import` | Offline parsing/export |
| Research context | `research-playbooks`, `research-init`, `research-note`, `research-resume` | Non-executing checklists and private journals |
| Scope and observations | `bounty-preflight`, `bounty-assess`, `bounty-campaign`, `bounty-report`, `bounty-import-har` | Preflight/import/report offline; selected bounded observation commands send traffic |
| API/agent review | `bounty-api-inventory`, `bounty-agent-plan`, `bounty-ai-review`, `bounty-correlate` | Offline evidence/role planning; optional loopback AI |
| Browser/replay | `bounty-browser-lab`, `bounty-replay-head`, `bounty-repeatability` | Owned browser lab or approved HEAD replay; comparison offline |
| Analyst dossiers | `bounty-review-init`, `bounty-review-decide`, `bounty-review-export`, `bounty-reproduction-note`, `bounty-benchmark` | Human attestations, private drafts and synthetic review-cue checks |
| Engagements | `engagement-plan`, `engagement-preflight`, `engagement-run`, `engagement-compare`, `engagement-package` | Offline design/reporting around separately approved live checks |
| Executable lab | `verify-crashes` | Execute bounded replay only in an isolated authorized local lab |

</details>

## Controls and limits

- **Authorization:** explicit `--authorized`, exact profile/protocol bindings and method-specific approvals. Local attestations do not verify company identity or establish multi-user RBAC.
- **Scope:** exact hosts, ports and paths; unlisted targets remain excluded even when optional exclusion lists are empty.
- **Execution:** fixed worker code, no shell-command configuration, no automatic retry/replay, proxy or redirect following in the observation transport.
- **Stop:** per-run quotas and deadlines, emergency stop, worker parent-death checks; a sent request cannot be recalled.
- **Isolation:** worker processes are not an OS sandbox. Linux workers add resource limits; Windows relies on inherited directory ACLs for confidentiality.
- **Evidence:** source severity is not verified impact. Hash links detect inconsistency, not forgery by a directory owner.
- **Browser:** Playwright interception is not a network firewall. Remote form mode is narrow; the original browser lab stays on owned loopback.
- **Claims:** No guaranteed zero-days, no automatic official CVE assignment or disclosure submission, credential guessing, stealth/WAF bypass, or unrestricted exploit chaining.

See [security](SECURITY.md), [workflow boundaries](docs/WORKFLOW_RUNNER.md), [engagement boundaries](docs/APPROVED_ASSESSMENTS.md), and the [framework comparison](docs/FRAMEWORK_COMPARISON_2026_10.md).

## Updates and releases

Preserve local changes and private evidence before updating. Use a clean checkout, `git pull --ff-only`, reinstall the editable package and repeat diagnostics/tests. Never use a destructive reset to update a research workspace.

```bash
python tools/build_release.py --repo . --out ../HunterQA-AI-1.3.0-source.zip
python tools/verify_release_archive.py ../HunterQA-AI-1.3.0-source.zip
```

The builder creates a new archive, includes the public guides/artwork, excludes private runtime data, normalizes shell-script line endings for Linux, and records packaged-file SHA-256 hashes. It refuses an existing output filename.

| Document | Use |
| --- | --- |
| [Zero to Start](<zero to start.md>) | Installation, complete offline demo, approved checks, reporting and troubleshooting |
| [Authorized Assessment — Beginner’s Guide](docs/AUTHORIZED_ASSESSMENT_BEGINNER_GUIDE.md) | First organization-approved assessment: scope, reviewed HEAD observation, evidence and reporting |
| [Assessment templates](templates/README.md) | Original scope/target templates, matching instructions and private worksheets for every step |
| [1.3.0 release notes](docs/RELEASE_1_3_0.md) | Exact release inventory and known limitations |
| [Versioning policy](docs/VERSIONING.md) | Canonical version, immutable historical tags and publication procedure |
| [Operational workflows](docs/WORKFLOW_RUNNER.md) | Adapter bindings, controls, audit and retest semantics |
| [Protocol schema](docs/TESTING_PROTOCOL.md) | Strict planning schema and review fingerprints |
| [Research interoperability](docs/RESEARCH_WORKFLOWS.md) | Journals, imports, SARIF and source Action |
| [Earlier architecture](docs/ARCHITECTURE.md) | Historical architecture; current behavior is documented above |

**Use HunterQA only on systems and source you own or are explicitly authorized to assess.**
