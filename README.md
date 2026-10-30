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

**Containers & Kubernetes review pack:** [coverage and instructions](docs/CONTAINER_KUBERNETES_REVIEW.md).
`utility-review-catalog` lists two offline triage/reporting contracts.
`utility-review` reads owner observations; `utility-report-review` checks selected
saved finding metadata and writes JSON or a sanitized Markdown quality summary.
`utility-cvss31` calculates CVSS 3.1 Base arithmetic from a complete caller-chosen
vector. See the [Utility guide](docs/UTILITY_REVIEW.md),
[assurance template](templates/HunterQA-utility-review-template.json),
[report input template](templates/HunterQA-report-quality-template.json) and
[private worksheet](templates/27-utility-review.md). The
[category index](docs/CATEGORY_REVIEW_INDEX.md) lists all review packs and their
bounded modes; it is not a claim of complete automated pentesting coverage.

`ai-security-review-catalog` lists one offline AI application assurance contract.
`ai-security-review` reads owner observations; `ai-security-evidence-review` checks
owned saved canary/tool/retrieval constraints or imports numeric garak summaries.
See the [AI Security guide](docs/AI_SECURITY_REVIEW.md),
[assurance template](templates/HunterQA-ai-security-review-template.json),
[owned-case template](templates/HunterQA-ai-owned-cases-template.json) and
[private worksheet](templates/26-ai-security-review.md). No model or tools are called;
runtime authorization, model behavior and robustness remain unverified.

`network-review-catalog` lists one offline Layer 2/3 assurance contract with eight
control observations. `network-review` reads owner observations;
`network-config-review` reads selected saved Linux sysctl or systemd-resolved
settings. See the [Network guide](docs/NETWORK_SECURITY_REVIEW.md),
[JSON template](templates/HunterQA-network-review-template.json) and
[private worksheet](templates/25-network-review.md). Host/router roles, effective
interface/resolver policy and exploitability remain unverified; no packets are
injected and no host settings are changed.

`social-review-catalog` lists two offline approved-simulation and participant-
protection contracts. `social-review` reads owner observations; `social-evidence-review`
reads selected saved DMARC text or aggregate GoPhish result/config metadata.
See the [Social Engineering guide](docs/SOCIAL_ENGINEERING_REVIEW.md),
[JSON template](templates/HunterQA-social-review-template.json) and
[private worksheet](templates/24-social-engineering-review.md). No messages are sent
or credentials collected; live mail controls and participant behavior remain unverified.

`supply-chain-review-catalog` lists two offline artifact/build trust and
dependency-confusion contracts. `supply-chain-review` reads owner observations;
`supply-chain-config-review` reads selected npm lock v2/v3 JSON, `.npmrc` or pip
INI declarations. See the [Supply Chain guide](docs/SUPPLY_CHAIN_REVIEW.md),
[JSON template](templates/HunterQA-supply-chain-review-template.json) and
[private worksheet](templates/23-supply-chain-review.md). Hash syntax and saved
source settings do not establish artifact authenticity or effective resolution;
no packages are installed and no registries are contacted.

`forensics-review-catalog` lists two offline evidence-preservation/C2 governance
contracts. `forensics-review` reads owner observations; `forensics-log-review`
reads selected saved Windows event XML or Zeek DNS JSONL. See the
[Forensics & C2 guide](docs/FORENSICS_C2_REVIEW.md),
[JSON template](templates/HunterQA-forensics-review-template.json) and
[private worksheet](templates/22-forensics-c2-review.md). Evidence integrity,
malicious activity and C2 attribution remain unverified; no logs are altered or
agents deployed.

`post-exploitation-review-catalog` lists three offline assurance contracts for
lateral movement, persistence and data exfiltration. `post-exploitation-review`
reads owner observations; `post-exploitation-inventory-review` reads selected
saved Windows task XML or default VPC flow text. See the
[post-exploitation guide](docs/POST_EXPLOITATION_REVIEW.md),
[JSON template](templates/HunterQA-post-exploitation-review-template.json) and
[private worksheet](templates/21-post-exploitation-review.md). No remote actions,
task execution or data transfers are performed; compromise remains unverified.

`privilege-review-catalog` lists two offline Linux/Windows assurance contracts.
`privilege-review` reads owner observations; `privilege-inventory-review` reads
selected saved `getcap` text or Windows service JSON. See the
[privilege guide](docs/PRIVILEGE_ESCALATION_REVIEW.md),
[JSON template](templates/HunterQA-privilege-review-template.json) and
[private worksheet](templates/20-privilege-escalation-review.md). No host enumeration,
command execution or privilege escalation is performed; effective access remains unverified.

`crypto-review-catalog` lists two offline Cryptography contracts. `crypto-review`
reads owner observations; `crypto-source-review` inspects selected Python AST
hash/random/AES ECB/TLS patterns without executing source. See the
[Cryptography guide](docs/CRYPTOGRAPHY_REVIEW.md),
[JSON template](templates/HunterQA-crypto-review-template.json) and
[private worksheet](templates/19-cryptography-review.md). Cryptographic correctness,
live TLS, key/nonce handling and exploitability remain unverified.

`cicd-review-catalog` lists two offline CI/CD contracts. `cicd-review` reads
owner observations; `cicd-workflow-review` reviews selected saved GitHub Actions
**JSON** declarations without executing workflows. See the [CI/CD guide](docs/CICD_PIPELINES_REVIEW.md),
[JSON template](templates/HunterQA-cicd-review-template.json) and
[private worksheet](templates/18-cicd-pipelines-review.md). YAML and native
Jenkins/GitLab/Azure parsing are not implemented; secret protection and effective
permissions remain unverified.

`container-review-catalog` lists two offline contracts; `container-review` checks
owner observations. `container-config-review` reads selected Docker inspect or
Kubernetes workload/RBAC JSON without daemon/cluster connections. Use the
[JSON template](templates/HunterQA-container-review-template.json) and
[private worksheet](templates/17-container-kubernetes-review.md). Reports withhold
native identities and contents; actual isolation, permissions and escape paths remain unverified.

**API Security review pack:** [coverage and instructions](docs/API_SECURITY_REVIEW.md).
`api-review-catalog` lists two offline API/business-logic contracts; `api-review`
checks owner observations. `api-openapi-review` reads selected OpenAPI 3.0/3.1 JSON
security inheritance/alternatives, server and inline request-bound declarations.
Use the [JSON template](templates/HunterQA-api-review-template.json) and
[private worksheet](templates/16-api-security-review.md). No references or endpoints
are requested; contract cues do not prove server authorization or business-logic enforcement.

**Reconnaissance review pack:** [coverage and instructions](docs/RECONNAISSANCE_REVIEW.md).
`recon-review-catalog` lists two offline OSINT contracts; `recon-review` checks
owner observations. `recon-inventory` filters/deduplicates saved DNS names or
CT-style name JSON using an explicit private domain scope. Names are withheld by
default; `--include-names` exports admitted names in the private report. Use the
[review template](templates/HunterQA-recon-review-template.json),
[name-scope template](templates/HunterQA-recon-scope-template.json) and
[worksheet](templates/15-reconnaissance-review.md). No DNS, collection or active
target enrollment occurs; ownership and current exposure remain unverified.

**Fuzzing & Vulnerability Research review pack:** [coverage and instructions](docs/FUZZING_RESEARCH_REVIEW.md).
`fuzzing-review-catalog` lists four offline contracts; `fuzzing-review` checks owner
observations. `fuzzing-artifact-review` reads selected AFL++ stats or libFuzzer
progress/error markers without running a harness. Use the
[JSON template](templates/HunterQA-fuzzing-review-template.json) and
[private worksheet](templates/14-fuzzing-research-review.md). Metrics are unverified;
saved crashes are not confirmed vulnerabilities and bitmap occupancy is not source coverage.

**Exploit Development assurance pack:** [coverage and instructions](docs/EXPLOIT_DEVELOPMENT_REVIEW.md).
`exploit-dev-review-catalog` lists six offline contracts; `exploit-dev-review`
checks owner observations. `exploit-dev-artifact-review` reads selected ASan/TSan
log markers or ELF header declarations without running artifacts or symbolizers.
Use the [JSON template](templates/HunterQA-exploit-dev-review-template.json) and
[private worksheet](templates/13-exploit-development-review.md). Crashes, runtime
mitigations, exploitability and real-world effectiveness remain unverified.

**Infrastructure & Red Team defensive review pack:** [coverage and instructions](docs/INFRASTRUCTURE_REVIEW.md).
`infrastructure-review-catalog` lists seven contracts; `infrastructure-review`
checks selected owner observations. `infrastructure-pe-review` reads selected
x86/x64/ARM64 PE header flags and section characteristics without loading binaries.
Use the [JSON template](templates/HunterQA-infrastructure-review-template.json)
and [private worksheet](templates/12-infrastructure-review.md). No evasion, payload
or input capture is executed; actual process enforcement remains unverified.

**IoT & Embedded review pack:** [coverage and instructions](docs/IOT_EMBEDDED_REVIEW.md).
`iot-review-catalog` lists nine offline evidence areas; `iot-review` checks owner
declarations. `iot-config-review` reads selected Mosquitto ACL syntax or four
resolved U-Boot build flags. Use the [JSON template](templates/HunterQA-iot-review-template.json)
and [private worksheet](templates/11-iot-embedded-review.md). Reports retain
unknowns and receipt hashes without native users/topics or unselected build values.
No hardware, firmware binary or industrial service is operated; effective ACLs,
boot-chain enforcement and real-world effectiveness remain unverified.

**Mobile review pack:** [Android/iOS coverage and instructions](docs/MOBILE_REVIEW.md).
`mobile-review-catalog` lists the offline fields; `mobile-review` checks selected
owner declarations. `mobile-config-review` reads decoded Android Manifest/Network
Security Config and XML iOS Info.plist/entitlements using a hardened XML parser.
Reports withhold source identifiers and preserve uncertainty and SARIF context.
Use the [JSON template](templates/HunterQA-mobile-review-template.json) and
[private worksheet](templates/10-mobile-review.md). No apps/devices are executed;
actual signing and runtime enforcement remain unverified. Refresh dependencies
with `python -m pip install -e .` after updating this checkout.

**Cloud review pack:** [AWS/Azure/GCP coverage and instructions](docs/CLOUD_REVIEW.md).
`cloud-review-catalog` lists the offline evidence fields; `cloud-review` checks
selected owner-normalized posture declarations. `cloud-policy-review` reads
selected native AWS IAM, GCP IAM or Azure NSG JSON without provider connections.
Reports withhold source identifiers and retain explicit uncertainty, input hashes
and SARIF context. Use the [JSON template](templates/HunterQA-cloud-review-template.json)
and [private worksheet](templates/09-cloud-review.md). Effective permissions and
actual reachability remain unverified; the existing bounded AWS account adapter
is separate and unchanged.

**Wireless review pack:** [14-skill coverage and instructions](docs/WIRELESS_REVIEW.md).
`wireless-review-catalog` lists all contracts and typed fields; `wireless-review`
checks selected local policy declarations. `wireless-hostapd-review` reads seven
explicit single-BSS configuration directives without executing them. Reports
omit network identities and credentials, preserve unknown evidence and export
through the existing SARIF command. Use the
[JSON template](templates/HunterQA-wireless-review-template.json) and
[private worksheet](templates/08-wireless-review.md). No radio activity, packet
capture, device authentication or active vulnerability validation is performed.

**Active Directory review pack:** [coverage and instructions](docs/ACTIVE_DIRECTORY_REVIEW.md).
`ad-review-catalog` describes both AD and NetExec category contracts; `ad-review`
checks selected owner-normalized account, SMB/LDAP, ACL, certificate, trust and
hybrid declarations offline. Unknown fields remain unassessed; no directory query,
authentication or external tool is run. Use the
[JSON template](templates/HunterQA-ad-review-template.json) and
[private worksheet](templates/07-active-directory-review.md). Effective rights,
live attack paths and complete AD CS coverage remain unverified/incomplete.

**Auth & Identity review pack:** [JWT and OAuth/OIDC guide](docs/AUTH_IDENTITY_REVIEW.md).
`identity-review-catalog` lists both review contracts; `identity-review` compares
private JWT samples and declared web-client settings offline. It retains redacted
cues, remediation and an input hash. It does not verify signatures, authenticate
to providers or test actual server acceptance. Use the
[JSON template](templates/HunterQA-identity-review-template.json) and
[private reviewer worksheet](templates/06-auth-identity-review.md).

**Web Application review pack:** [16-skill coverage and instructions](docs/WEB_APPLICATION_REVIEW.md).
`web-review-catalog` lists every contract; `web-source-review` inspects authorized
local Python without executing it. Ten narrow source checks also run through the
existing local scan engine; six skills provide guided review only. Reports retain
source hashes, locations, remediation and explicit limits. This does not add
comprehensive active exploitation or establish real-world detection accuracy.
Use the [private category worksheet](templates/05-web-application-review.md).

**Optional local operator access:** [setup and limits](docs/OPERATOR_ACCESS.md).
`operator-init`, `operator-add`, `operator-update`, `operator-status`,
`operator-audit` and `operator-secret` manage named local dashboard accounts,
viewer/analyst/admin roles, private session keys and revocable sessions. The
control root must be separate from assessment roots. This is a shared local
organization workspace; hosted multi-user/tenant isolation, SSO and independently
verified owner grants remain incomplete.

**Check what is ready:** [marked feature checklist](docs/FEATURE_READINESS_CHECKLIST.md)
and [owned-lab setup/readiness guide](docs/READINESS.md). `assessment-readiness`
checks local installation and recomputes optional retained lab evidence without
launching tools or contacting targets. `coverage-audit --format markdown` prints
implemented `[x]` and unfinished `[ ]` features. All seven broad categories remain
partial, and real-world effectiveness remains unverified.

**Further development:** [assessment adapters and quotas](docs/ASSESSMENT_ADAPTERS.md)
add `assessment-setup` for fixed `web-canary-check`, `authorization-matrix`,
`service-enumeration` and optional `aws-account-audit` workflows. These provide
inert markup/SQL-error comparisons, dedicated-role GET contracts, exact TCP
reachability and two read-only AWS account APIs. All need reviewed scope and
explicit checkpoints; findings remain unverified.

Use `coverage-audit` for the seven-area status and `assessment-benchmark` for a
versioned owned application baseline. `quota-init`, `quota-status`, `quota-stop`
and `quota-reconcile` manage optional shared host-local quotas configured through
`HUNTERQA_QUOTA_LEDGER`. This is partial assessment coverage and cooperating local
quota enforcement, not a complete pentesting platform or production multi-user
service. These additions are absent from the immutable v1.3.0 archive.

**Development addition after v1.3.0:** `discovery-setup` plans approved, bounded
HTML discovery with link following, form inventory and private workflow reports.
It follows only admitted seed origins and profile paths, requires explicit
approval, and does not execute JavaScript or submit forms. See the
[discovery guide](docs/SCOPED_WEB_DISCOVERY.md) and the
[seven-area expansion roadmap](docs/ASSESSMENT_EXPANSION_ROADMAP.md).
This code is absent from the original v1.3.0 archive. The table below describes
the published release; the broader assessment gaps remain partially implemented
or planned, as recorded in the roadmap.

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
