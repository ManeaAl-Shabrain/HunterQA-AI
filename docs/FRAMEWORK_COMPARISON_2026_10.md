# HunterQA and seven AI security references — October 28, 2026

HunterQA baseline: merged `main` commit `ab4bc91`, including PRs #23 and #24.
This comparison inspected current primary documentation, license headers, and
Zen's action definition. It did not install or benchmark the other frameworks,
audit their entire implementations, or independently verify their performance,
isolation, accuracy, tool counts, and exploitation claims. Availability labels
below describe what the inspected files say. New HunterQA capabilities are
original implementations; no external skills, prompts, exploit modules or
framework source were copied or executed.

## These references occupy different layers

| Reference | Documented emphasis | HunterQA comparison and useful adaptation |
| --- | --- | --- |
| [Claude-Red](https://github.com/SnailSploit/Claude-Red) | A methodology skill library for Claude, spanning many security domains; MIT license header. It is not itself a scanner-runtime comparison. | HunterQA already has seven constrained analyst roles. Add ten original review playbooks with evidence/control questions, presented as data rather than downloaded instructions or automatic executors. Offensive evasion and post-exploitation skills are not incorporated. |
| [How to Build AI Hackbots](https://chndlrx.com/posts/how-to-build-ai-hackbots/) | An architecture article rather than a product: project-scoped workspaces, staged notes, skeptical review, proxy history, and reusable knowledge. The author also describes benchmark shortcuts and rule failures. | Existing dossiers/HAR review address part of this. Add policy-bound private notes and negative results, with an integrity-checked context-resume command. Resuming notes must not resume live operations. A second opinion or a hash still does not prove a finding. |
| [Zen AI Pentest](https://github.com/marketplace/actions/zen-ai-pentest), [inspected action](https://github.com/SHAdd0WTAka/Zen-Ai-Pentest/blob/main/action.yml) | A broad framework plus a GitHub Action. The action definition includes SARIF/report outputs and conditional upload, PR-comment and check-run steps. License is documented as MIT. | HunterQA had SARIF import and project QA, but lacked SARIF export and a reusable consumer action. Add a source-only action that requires acknowledgment, treats input paths as data, returns private SARIF, and leaves uploads/comments to explicit caller configuration. |
| [NeuroSploit](https://github.com/JoasASantos/NeuroSploit) | Current README describes a Rust harness, source/live modes, specialist selection, replay evidence, model adjudication, graphs, resume and multiple report formats; MIT header. Its older Python distribution is separate. | HunterQA's source graph, scoped observations and human dossiers are narrower. Add normalized external evidence import and CI-friendly output. Do not claim parity with wire validation, cross-model adjudication or autonomous exploit chains. |
| [PentAGI](https://github.com/vxcontrol/pentagi) | A self-hosted agent platform documenting Docker execution, persistent memory, optional graph services, provider options, monitoring, and tool-call supervision; MIT header. | HunterQA already enforces small request budgets and loopback AI. Add durable research context without requiring its distributed service stack. This journal is a local consistency mechanism, not semantic memory, a container sandbox, or a supervisor for autonomous tools. |
| [Pentest-Swarm-AI](https://github.com/Armur-Ai/Pentest-Swarm-AI) | Its feature-status table distinguishes a stable sequential runner/tool adapters from an alpha swarm scheduler and live dashboard, with verification oracles/Action/playbooks labeled beta. License header is AGPL-3.0. | Retain HunterQA's explicit deterministic workflow. Adopt the general ideas of focused review recipes, visible uncertainty, and interoperable evidence. No swarm scheduler or attack-chain executor is added, and no AGPL source is incorporated. |
| [Xalgorix](https://github.com/xalgorix/xalgorix) | A Go/TypeScript platform documenting live telemetry, source/live scan modes, browser workflows, findings, report management and external integrations; Apache-2.0 header. | HunterQA already has source review, historical evidence and a limited browser mode. Improve its local research continuity and report interoperability. This work does not add its hosted service, broad authenticated browser automation, email flows, remote notifications or dynamic tool installation. |

None of these descriptions establishes a “best tool” ranking. A prompt library,
an article, an action and a distributed execution platform need different
evaluation criteria. A bigger tool list is not evidence of better detection.

## Capability gap analysis

| Capability | HunterQA before this change | Result of this change |
| --- | --- | --- |
| Methodology catalog | Seven analyst roles; manual research categories | Ten original playbooks and a read-only `/playbooks` view; no skill execution |
| Target-scoped research notes | Campaign artifacts, SQLite review history, dossiers | New private policy-bound workspace with observations/hypotheses/negative results/next steps |
| Resume after an interruption | Saved campaign and assessment artifacts | Verify journal hash links and return recent context; zero execution resumed |
| Proxy evidence | Offline HAR import and bounded credential-free HEAD replay | Unchanged; a live Burp/Caido MCP bridge is not implemented |
| Other scanner evidence | SARIF and sanitizer imports | Add offline Nuclei HTTP JSONL and ZAP traditional JSON imports with endpoint-scope filtering |
| Standard CI output | SARIF input only | Add conservative SARIF 2.1.0 output with safe relative locations and generic unverified messages |
| Reusable GitHub Action | Internal QA workflow only | Add source-only composite action; no target URL input, target project execution, uploads or comments |
| Validation | Analyst dossiers, source grounding, synthetic fixtures | New notes/imports remain unverified; existing disclosure validation is not bypassed |
| Agent supervision | Fixed offline roles; bounded operator-started HTTP/browser runs | Preserved; no arbitrary model-selected tools, autonomous retries or exploit chaining |
| Memory and graphs | Source trust graph, conservative correlation, campaign comparisons | Journal/context added; semantic retrieval and graph-directed exploitation are not claimed |
| Provider diversity | Local Ollama/Qwen | Preserved; private evidence is not silently sent to remote providers |
| Runtime platforms | Single-operator workstation and loopback dashboard | Preserved; no distributed or hosted multi-user deployment is introduced |

## Additional tool interoperability

Two useful scanner ecosystems were identified beyond HunterQA's existing
Semgrep, SARIF, OpenAPI, advisory, HAR and sanitizer workflows:

- **Nuclei**: read its existing HTTP JSONL output using the upstream
  [result-event field definitions](https://github.com/projectdiscovery/nuclei/blob/dev/pkg/output/output.go).
  No templates or scanner executables are installed or run by the adapter.
- **ZAP**: read its existing
  [traditional JSON site/alert/instance format](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/).
  This does not operate a proxy, invoke its API, replay traffic or launch scans.

Both adapters bound input size/record counts, reject duplicate JSON keys,
scope-check endpoint hosts/paths/ports without DNS, deduplicate exact sanitized
candidate identities, retain source severity only as an assertion, and omit raw
requests/responses/payloads/extracted values and arbitrary template prose. They
do not automatically admit new scanner rules into the existing dossier engine.
Unknown/unsupported formats and encoded paths have explicit conservative limits.

SARIF output follows the
[OASIS 2.1.0 structure](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html).
Outputting a format is distinct from uploading it or independently validating
the findings represented in it.

## Implementation choices and deferred capabilities

The implemented changes target research continuity and tool interoperability
while preserving the existing approval boundary. They are not a merger of all
seven systems. Remote-provider backends, live proxy/MCP control, semantic/vector
memory, production multi-user hosting, CVSS/EPSS ingestion, distributed agent
scheduling and broad browser workflows need separate designs and validation.
They are not represented as implemented features here.

Unrestricted exploit execution, stealth/evasion, credential guessing, automatic
report submission, official CVE allocation and guaranteed discovery remain outside
this implementation. Existing approved observations, one designated-account login,
benign WAF canaries and restricted browser checks retain their documented limits.

## Reference snapshots and attribution

README blob identifiers observed during this review (blob IDs, not release or
commit IDs):

| Repository | README blob SHA |
| --- | --- |
| SnailSploit/Claude-Red | `0858a54b75c0a29021e4ca7b7d69fbbee40c3bce` |
| JoasASantos/NeuroSploit | `ccc366aee1e3d182403829f5f4186348b41009bf` |
| vxcontrol/pentagi | `fc90f6e11e5de1b3bbbcff34b5bd548e53c68cf7` |
| Armur-Ai/Pentest-Swarm-AI | `e1f9516b110873b0e412c3923009952d3180c6cd` |
| xalgorix/xalgorix | `a09b5b289343c8a70499c0e260ea03ec2d9d5593` |
| SHAdd0WTAka/Zen-Ai-Pentest | `81229ff951efed330539718e5851b68363de38ff` |

Zen action blob: `b2e623a137aa58c4b34f8797d7dcd28ba71d9820`.
The article was retrievable in this review; the earlier v1.2 inspiration note's
retrieval limitation no longer applies to this comparison. Documentation and
licenses can change; the links above identify the inspected primary projects.
HunterQA retains its own original implementation and does not claim endorsement
or runtime compatibility with the seven referenced projects.

See [research workflow usage](RESEARCH_WORKFLOWS.md) for implemented commands,
formats, local Action setup and remaining limits.
