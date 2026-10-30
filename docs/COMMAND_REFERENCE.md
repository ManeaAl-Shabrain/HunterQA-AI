# HunterQA command reference

Use `hunterqa --help` to list commands and `hunterqa COMMAND --help` for required
inputs and limits. `hunterqa --version` reports the package version; record the
Git commit too when using current source.

## Execution boundaries

Most review/import/report commands work on saved local files. Optional AI
commands contact local Ollama. `doctor --check-ollama` probes that local service.
`bounty-preflight` checks scope offline; `bounty-assess` and
`bounty-replay-head` send only separately approved bounded requests.
Workflow and engagement execution require their exact reviewed plans and
checkpoints. Read [workflow controls](WORKFLOW_RUNNER.md) and
[engagement controls](APPROVED_ASSESSMENTS.md) before using them.

`assessment-benchmark` starts its own synthetic loopback fixture and records
HTTP/TCP operations. Browser labs use owned loopback fixtures; separately
approved browser engagement modes have their own scope controls.
Playwright interception is not an OS firewall. Executable crash/fuzz research
needs a separately isolated owned lab.

No guaranteed zero-days, no automatic vulnerability confirmation, CVE assignment
or disclosure submission. Command names do not grant permission. Findings and AI
suggestions require human review. See [security policy](../SECURITY.md).

`browser-discovery` is a separately reviewed engagement mode for bounded
same-origin rendered links and ephemeral cookie login. See the [guide](SCOPED_RENDERED_DISCOVERY.md).

`sql-canary-check` and `xss-canary-check` are reviewed engagement modes with five
fixed owned-endpoint inputs. See [runtime controls](CONTROLLED_RUNTIME_VALIDATION.md).

## Commands

Descriptions below match CLI help. Category aliases are listed by `--help` and
are not additional implementations. See the [category index](CATEGORY_REVIEW_INDEX.md).

| Command | Purpose |
| --- | --- |
| `ad-review` | Review owner-normalized AD policy evidence offline without directory queries |
| `ad-review-catalog` | Show Active Directory and NetExec offline review contracts |
| `ai-security-evidence-review` | Offline observations, owned saved cases or garak summaries; no model or tool calls |
| `ai-security-review` | Offline observations, owned saved cases or garak summaries; no model or tool calls |
| `ai-security-review-catalog` | Show one offline AI application assurance contract |
| `api-openapi-review` | Offline API evidence/OpenAPI JSON review; no endpoint requests |
| `api-review` | Offline API evidence/OpenAPI JSON review; no endpoint requests |
| `api-review-catalog` | Show two offline API security and business-logic assurance contracts |
| `assessment-benchmark` | Run versioned owned-loopback application controls; never a real-world accuracy score |
| `assessment-readiness` | Read-only installation and retained owned-lab evidence checks; no assessment authorization |
| `assessment-setup` | Plan fixed access, service or read-only AWS checks without traffic |
| `audit` | Offline source/config/dependency/OpenAPI inspection |
| `bounty-agent-plan` | Build a safe, non-executing specialist-agent plan |
| `bounty-ai-review` | Local Ollama agent-role recommendations without tool execution |
| `bounty-api-inventory` | Offline OpenAPI 3.x authorization and object-access review |
| `bounty-assess` | Bounded authorized HEAD/GET web observations |
| `bounty-benchmark` | Score offline synthetic OpenAPI review cues against independent positive/negative labels |
| `bounty-browser-lab` | Owned 127.0.0.1 Playwright lab review with optional scoped login |
| `bounty-campaign` | Unify local SAST/AI, optional OSV/HAR and approved HTTP research |
| `bounty-correlate` | Deduplicate policy-matched local evidence with manual review |
| `bounty-import-har` | Offline read-only HAR evidence analysis |
| `bounty-preflight` | Offline scope preflight; makes no network requests |
| `bounty-repeatability` | Compare two same-scope HEAD replay reports offline |
| `bounty-replay-head` | Safe HEAD-only replay of approved sanitized HAR evidence |
| `bounty-report` | Draft a human-reviewed Markdown bug bounty report |
| `bounty-reproduction-note` | Create a private analyst-attested local reproduction note |
| `bounty-review-decide` | Record one human decision to a NEW private dossier version |
| `bounty-review-export` | Create a private disclosure draft for human-validated cases only |
| `bounty-review-init` | Create an offline, scope-matched review dossier from correlated findings |
| `campaign` | Run one bounded authorized local research campaign |
| `capabilities` | Show research category coverage and limitations |
| `cicd-review` | Offline CI/CD observations or saved GitHub Actions JSON; no workflow execution |
| `cicd-review-catalog` | Show two offline CI/CD assurance contracts |
| `cicd-workflow-review` | Offline CI/CD observations or saved GitHub Actions JSON; no workflow execution |
| `cloud-policy-review` | Offline cloud policy review; no provider connection or credentials |
| `cloud-review` | Offline cloud policy review; no provider connection or credentials |
| `cloud-review-catalog` | Show offline AWS/Azure/GCP evidence fields and selected native policy modes |
| `container-config-review` | Offline container evidence/JSON review; no daemon or cluster connection |
| `container-review` | Offline container evidence/JSON review; no daemon or cluster connection |
| `container-review-catalog` | Show two offline Container/Kubernetes review contracts |
| `coverage-audit` | Show honest delivery and missing coverage across seven assessment areas |
| `crypto-review` | Offline cryptography observations or selected Python AST; no execution or connections |
| `crypto-review-catalog` | Show two offline Cryptography assurance contracts |
| `crypto-source-review` | Offline cryptography observations or selected Python AST; no execution or connections |
| `cve-check` | Match offline OSV advisories to declared exact PyPI versions |
| `discovery-setup` | Plan bounded same-origin HTML discovery; sends no requests |
| `doctor` | Read-only local release diagnostics |
| `engagement-compare` | Offline comparison of two saved same-plan assessment reports |
| `engagement-package` | Offline reviewed disclosure/CVE request handoff; does not send |
| `engagement-discovery-coverage` | Offline discovery recall against a supplied hashed URL reference |
| `engagement-plan` | Create an offline assessment plan for review |
| `engagement-preflight` | Offline review of an expiring exact assessment plan |
| `engagement-run` | Execute fingerprint-approved bounded assessment steps |
| `exploit-dev-artifact-review` | Offline assurance/log/ELF review; no exploit or binary execution |
| `exploit-dev-review` | Offline assurance/log/ELF review; no exploit or binary execution |
| `exploit-dev-review-catalog` | Show six offline exploit-development assurance contracts |
| `external-import` | Offline scoped import of existing Nuclei JSONL or ZAP traditional JSON |
| `forensics-log-review` | Offline observations or saved event/DNS logs; no alteration, agents or connections |
| `forensics-review` | Offline observations or saved event/DNS logs; no alteration, agents or connections |
| `forensics-review-catalog` | Show two offline evidence-integrity/C2 assurance contracts |
| `fuzzing-artifact-review` | Offline campaign evidence/metrics review; no fuzzer or harness execution |
| `fuzzing-review` | Offline campaign evidence/metrics review; no fuzzer or harness execution |
| `fuzzing-review-catalog` | Show four offline fuzzing/research review contracts |
| `hypothesize` | Local Ollama-assisted source hypotheses (never auto-confirmed) |
| `identity-review` | Review private JWT samples and OAuth/OIDC configuration offline |
| `identity-review-catalog` | Show JWT and OAuth/OIDC offline review contracts |
| `import-sarif` | Normalize local CodeQL / SARIF output |
| `infrastructure-pe-review` | Offline defensive evidence/PE header review; no payload or evasion execution |
| `infrastructure-review` | Offline defensive evidence/PE header review; no payload or evasion execution |
| `infrastructure-review-catalog` | Show seven offline defensive Infrastructure review contracts |
| `iot-config-review` | Offline IoT evidence/source review; no hardware or network access |
| `iot-review` | Offline IoT evidence/source review; no hardware or network access |
| `iot-review-catalog` | Show selected offline IoT evidence, MQTT ACL and U-Boot review contracts |
| `lab-sql-validation` | Demonstrate fixed SQL impact on original in-memory toy data only |
| `lab-sql-verify` | Verify evidence and replay fixed in-memory SQL cases; no target traffic |
| `mobile-config-review` | Offline mobile evidence/XML review; no app or device execution |
| `mobile-review` | Offline mobile evidence/XML review; no app or device execution |
| `mobile-review-catalog` | Show selected offline Android/iOS review fields and XML modes |
| `network-config-review` | Offline observations or saved network/resolver config; no packets or host changes |
| `network-review` | Offline observations or saved network/resolver config; no packets or host changes |
| `network-review-catalog` | Show one offline Layer 2/3 network assurance contract |
| `operator-add` | Manage opt-in local dashboard operators; not target assessment permission |
| `operator-audit` | Manage opt-in local dashboard operators; not target assessment permission |
| `operator-init` | Manage opt-in local dashboard operators; not target assessment permission |
| `operator-secret` | Create a private persistent session-key file without displaying its value |
| `operator-status` | Manage opt-in local dashboard operators; not target assessment permission |
| `operator-update` | Manage opt-in local dashboard operators; not target assessment permission |
| `parse-sanitizer` | Parse a local ASan/UBSan log |
| `post-exploitation-inventory-review` | Offline observations or saved task/flow review; no execution or transfers |
| `post-exploitation-review` | Offline observations or saved task/flow review; no execution or transfers |
| `post-exploitation-review-catalog` | Show three offline post-exploitation assurance contracts |
| `privilege-inventory-review` | Offline privilege evidence or saved inventory; no host enumeration or execution |
| `privilege-review` | Offline privilege evidence or saved inventory; no host enumeration or execution |
| `privilege-review-catalog` | Show two offline Linux/Windows privilege assurance contracts |
| `propose-fix` | Generate a read-only local AI patch suggestion for one triage finding |
| `quota-init` | Initialize a host-local shared quota window |
| `quota-reconcile` | Inspect, stop or reconcile shared local quotas |
| `quota-status` | Inspect, stop or reconcile shared local quotas |
| `quota-stop` | Inspect, stop or reconcile shared local quotas |
| `recon-inventory` | Offline reconnaissance evidence or scoped name import; no DNS or external collection |
| `recon-review` | Offline reconnaissance evidence or scoped name import; no DNS or external collection |
| `recon-review-catalog` | Show two offline OSINT review contracts |
| `report-sarif` | Export normalized candidates as SARIF 2.1.0 without source snippets or uploading |
| `research-init` | Initialize a new private policy-bound research journal |
| `research-note` | Append an operator observation, hypothesis, negative result or next step |
| `research-playbooks` | List original non-executing research review checklists |
| `research-report` | Normalize validated local research JSON |
| `research-resume` | Read and verify private research context; executes no tests |
| `runtime-validation-benchmark` | Run six owned HTTP SQL/XSS controls with real Chromium |
| `runtime-validation-verify` | Offline consistency of retained HTTP runtime benchmark evidence |
| `scan` | Run unified offline Semgrep + config + API + dependency scan |
| `social-evidence-review` | Offline observations or saved DMARC/simulation metadata; no delivery or collection |
| `social-review` | Offline observations or saved DMARC/simulation metadata; no delivery or collection |
| `social-review-catalog` | Show two offline social-engineering assurance contracts |
| `supply-chain-config-review` | Offline observations or saved npm/pip declarations; no registry access or installation |
| `supply-chain-review` | Offline observations or saved npm/pip declarations; no registry access or installation |
| `supply-chain-review-catalog` | Show two offline supply-chain assurance contracts |
| `trust-graph` | Build a local Python call graph and trust-boundary review paths |
| `utility-cvss31` | Calculate CVSS 3.1 Base arithmetic from a complete caller-chosen vector |
| `utility-report-review` | Review saved finding metadata; no evidence references opened or verdict changes |
| `utility-review` | Review owner reporting/triage observations offline |
| `utility-review-catalog` | Show two offline triage/reporting assurance contracts |
| `verify-crashes` | Replay AFL++ inputs against a local approved executable |
| `web-review-catalog` | Show all 16 Web Application review contracts and execution limits |
| `web-source-review` | Offline Python web security source cues; never executes inspected code |
| `wireless-hostapd-review` | Offline wireless evidence/source review; no radio access or security-tool execution |
| `wireless-review` | Offline wireless evidence/source review; no radio access or security-tool execution |
| `wireless-review-catalog` | Show all 14 offline Wireless review contracts and field schemas |
| `workflow-abandon` | Reconcile a crashed coordinator without replaying work |
| `workflow-benchmark` | Exercise original offline positive/negative configuration fixtures |
| `workflow-compare` | Compare evidence from two independently approved runs |
| `workflow-export` | Create a private JSON, printable HTML or SARIF report |
| `workflow-preflight` | Offline testing-protocol and dependency review; no execution |
| `workflow-review` | Record an evidence-linked local analyst decision |
| `workflow-run` | Review or execute a fixed-adapter assessment workflow |
| `workflow-run-plan` | Review or execute a fixed-adapter assessment workflow |
| `workflow-setup` | Create a private starter protocol and bindings; executes nothing |
| `workflow-status` | Inspect a durable run or request emergency stop |
| `workflow-stop` | Inspect a durable run or request emergency stop |
| `workflow-tools` | List planning adapter declarations; launches no tools |
