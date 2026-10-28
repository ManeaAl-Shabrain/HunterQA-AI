# HunterQA AI — Architecture and Evidence Lifecycle

**Release documented:** v1.2.0 Stable. One Python/Flask codebase with separate
local research, optional network assessment, and human-review trust boundaries.

## Main components

- **Flask UI (`hunterqa/__init__.py`, `hunterqa/routes.py`):**
  - Listens on `127.0.0.1:5000` by default from `run.py`; this is a local
    development server, **not** an internet-facing multi-user service.
  - Uses CSRF checks and explicit authorization for project scan actions.
  - `/bounty` and `/agent-lab` display selected existing local evidence;
    viewing these dashboards never starts a remote test or browser session.
- **Unified CLI (`hunterqa/cli.py`):**
  - Provides local research campaigns, scope-gated bounty observations,
    offline OpenAPI research, AI review planning, isolated owned-browser
    assessment, evidence correlation, analyst verification and benchmark QA.
  - Most v1.2 bounty outputs are restricted to approved local directories
    and created as **new** private files (mode `0600`).
- **Local source research (`hunterqa/orchestrator.py` and `hunterqa/engines/`):**
  - Runs configured local Semgrep rules and config/dependency/OpenAPI checks
    from explicitly approved project roots.
  - Creates unverified findings, trust graphs, optional AI research
    hypotheses and separately processed sanitizer/fuzzer evidence.
  - Code execution from fuzzing/crash tools is **not sandboxed by approved
    filesystem roots**; use an isolated disposable VM/network.
- **Program scope and HTTP (`hunterqa/bounty.py`, `hunterqa/replay_v12.py`):**
  - Requires acknowledged written authorization, exact-host/path/port
    scope, traffic budgets and conservative transport settings.
  - Preflights all targets; limits live bounty observations to HEAD/GET
    and stops on denials, rate limits or server errors.
  - Prior-HAR replay is **HEAD only**, without forwarding original
    credentials/cookies, following redirects or retrying automatically.
  - Offline HAR import does not replay the original requests.
- **Offline API and analyst planning (`hunterqa/api_surface_v12.py`,
  `hunterqa/agent_workflow_v12.py`, `hunterqa/agent_ai_v12.py`):**
  - Analyzes local OpenAPI 3.0/3.1 JSON and produces **review prompts**,
    not proof of authorization defects.
  - Provides seven fixed analyst roles; optional Qwen/Ollama receives
    bounded aggregate metadata over loopback.
  - LLM output cannot create commands or grant itself scope.
  - Correlates only approved known evidence types with matching
    program/policy hashes, using hashed target references.
- **Owned Chromium lab (`hunterqa/browser_lab_v12.py`):**
  - Requires owned `127.0.0.1`, one exact approved port, an ephemeral
    context and optionally one explicitly approved login POST.
  - Blocks unapproved browser requests/redirect hops, service workers,
    WebSockets and downloads. Sensitive browser values are not exported.
  - **Playwright interception is not a firewall**: use host/network
    isolation for untrusted content.
- **Human verification (`hunterqa/verification_v12.py`,
  `hunterqa/repeatability_v12.py`):**
  - Converts scoped correlation candidates into local dossiers.
  - Uses explicit reviewer decision statuses and matching human
    reproduction attestations; creates SHA-256-linked local file versions.
  - Hash linking detects edits but **is not a cryptographic signature**
    or independent proof that a vulnerability exists.
  - Exports human-only private disclosure drafts for analyst-validated
    records. No automatic bug bounty submission.
- **QA benchmark (`hunterqa/benchmark_v12.py`):**
  - Scores synthetic positive/negative API **review cues**.
  - Its precision/recall values do not indicate actual vulnerability
    detection accuracy and cannot substantiate a zero-day claim.

## Evidence lifecycle

```text
Explicit owner/program permission + approved local files
       |
       +-- Source/Semgrep, dependency, offline OSV/CVE, fuzz/sanitizer
       +-- Local OpenAPI review ---------------------------+
       +-- Pre-captured HAR (offline) --------------------+
       +-- Optional permitted bounded HEAD/GET ------------+
       +-- Owned-loopback browser lab (optional)           |
       |                                                   v
       +-- Fixed reviewer plan (+ optional private Qwen) --> scope-matched correlation
                                                               |
                                                               v
                                                        private review dossier
                                                               |
                                    authorized human reproduction + manual attestation
                                                               |
                                                               v
                                              human-validated PRIVATE draft
```

## What is and isn't verified

- **Semgrep finding:** local rule pattern, not automatically CVSS critical.
- **OpenAPI security declaration:** schema metadata, not runtime access
  control behavior.
- **OSV/CVE alias:** an advisory match, not confirmed installed exploitability.
- **ASan/UBSan/crash evidence:** a runtime observation tied to a build/input,
  not proof of externally exploitable security impact or novelty.
- **HEAD status difference:** an HTTP observation, not authentication
  bypass or exploit evidence.
- **AI hypothesis:** untrusted analyst suggestion; never automatically
  approved as a security finding.
- **Analyst-validated case:** a human's documented local reproduction,
  not an independently verified third-party finding.
- **Unknown zero-day:** requires independent reproduction, impact and
  coordinated disclosure; this software cannot guarantee discovery
  or issue a CVE.

## Optional external research tools

- **Semgrep:** installed separately for source scanning.
- **Ollama:** local Qwen inference; entirely optional for core offline QA.
- **Playwright/Chromium:** optional browser dependencies; only owned
  loopback browser laboratory is implemented.
- **Clang, AFL++ and sanitizers:** optional, isolated local executable
  research tools.
- **CodeQL/Ghidra:** not automatically executed; import supported local
  evidence formats where applicable.

## Performance / deployment

- Prefer a local small model, one scan worker, and isolated sequential
  fuzzing/browser runs on memory-constrained Kali VMs.
- Never expose the Flask development server on `0.0.0.0` or the public
  internet.
- Keep projects, session keys, SQLite databases and private evidence
  outside the public repository.

For supported commands, setup, release integrity and safety boundaries,
see [README](../README.md), [v1.2 workflow](V1_2_DEV.md),
[browser lab](BROWSER_LAB_V1_2.md), [review workflow](REVIEW_V1_2.md),
and [versioning](VERSIONING.md).
