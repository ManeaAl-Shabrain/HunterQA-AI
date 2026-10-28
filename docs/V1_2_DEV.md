# HunterQA AI 1.2 — Scoped AI Research Orchestration

**Status:** Development milestone on `feature/v1-2-ai-research-orchestration`.
The published `v1.1.0` remains the stable release.

## What v1.2 already does

- **API Contract Reviewer:** reads an approved local OpenAPI 3.0/3.1 JSON
  spec and constructs a bounded inventory of endpoints, auth declarations,
  resource identifiers and business-logic review opportunities.
  Nothing is fetched from contract `servers`, and no API call occurs.
- **Seven specialist research roles:** scope-guard, API reviewer, local source
  reviewer, advisory reviewer, capture reviewer, evidence reviewer, report
  reviewer. Roles have strict task types, no arbitrary execution and human gates.
- **Local Qwen review (optional):** sends only sanitized aggregate plan
  metadata to a loopback Ollama instance. Suggestions are parsed into known
  role IDs and cannot run commands or change the authorization policy.
- **Evidence correlation:** accepts only whitelisted, bounded local HunterQA
  reports for the exact same program and policy hash. Deduplicates known
  review categories using hashed target identifiers. It does NOT prove
  exploitability or zero-day discovery.
- **Low-noise HTTP safeguard:** existing opt-in HEAD/GET engine sends no
  automatic retries and stops on 401, 403, 429 or 5xx responses.
  No traffic-obfuscation, VPN rotation, WAF evasion or hidden scanning.
- **Read-only `/agent-lab` dashboard:** displays local agent plans and evidence
  summary. Viewing it cannot launch a live assessment.

Existing source scanning, Semgrep, Qwen local campaigns, AFL++/sanitizer lab
research, OSV/CVE aliases, HAR triage, bug bounty scope control and v1.1
reports are preserved.

## Kali checkout

```bash
cd ~/Desktop/HunterQA-AI
git status --short
git fetch origin
git switch --track origin/feature/v1-2-ai-research-orchestration
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q
```

If this feature branch already exists locally, use
`git switch feature/v1-2-ai-research-orchestration && git pull --ff-only`.

## First offline research session

All sample files should reside in an approved local folder, not your
public GitHub repo. The example domain is fake and **must not be scanned**.

```bash
mkdir -p "$HOME/ZeroScope-AI/research-lab/v12"

cp examples/bounty_profile.example.json \
  "$HOME/ZeroScope-AI/research-lab/v12/profile.json"
cp examples/bounty_targets.example.txt \
  "$HOME/ZeroScope-AI/research-lab/v12/targets.txt"
cp examples/v12_owned_api_openapi.json \
  "$HOME/ZeroScope-AI/research-lab/v12/openapi.json"

export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"

python -m hunterqa bounty-api-inventory \
  --profile "$HOME/ZeroScope-AI/research-lab/v12/profile.json" \
  --spec "$HOME/ZeroScope-AI/research-lab/v12/openapi.json" \
  --out "$HOME/ZeroScope-AI/research-lab/v12/inventory.json" \
  --authorized

python -m hunterqa bounty-agent-plan \
  --profile "$HOME/ZeroScope-AI/research-lab/v12/profile.json" \
  --spec "$HOME/ZeroScope-AI/research-lab/v12/openapi.json" \
  --targets "$HOME/ZeroScope-AI/research-lab/v12/targets.txt" \
  --out "$HOME/ZeroScope-AI/research-lab/v12/agent-plan.json" \
  --authorized

python -m hunterqa bounty-correlate \
  --profile "$HOME/ZeroScope-AI/research-lab/v12/profile.json" \
  --file "$HOME/ZeroScope-AI/research-lab/v12/inventory.json" \
  --out "$HOME/ZeroScope-AI/research-lab/v12/correlation.json" \
  --authorized
```

All three commands run **without network requests**. Outputs use private
create-only files (`0600`). Choose new filenames on subsequent runs.
No model output or downloaded document may change approved scope.

## Optional private Ollama specialist suggestions

```bash
ollama list

python -m hunterqa bounty-ai-review \
  --plan "$HOME/ZeroScope-AI/research-lab/v12/agent-plan.json" \
  --model qwen2.5-coder:3b \
  --out "$HOME/ZeroScope-AI/research-lab/v12/ai-review.json" \
  --authorized
```

If Ollama is unavailable or produces invalid JSON, the output says
`unavailable_or_invalid_output` with no suggested actions. Do not interpret
these suggestions as evidence of a security defect.

## Dashboard

```bash
export HUNTERQA_AGENT_PLAN="$HOME/ZeroScope-AI/research-lab/v12/agent-plan.json"
export HUNTERQA_API_SURFACE_REPORT="$HOME/ZeroScope-AI/research-lab/v12/inventory.json"
export HUNTERQA_AGENT_CORRELATION_REPORT="$HOME/ZeroScope-AI/research-lab/v12/correlation.json"
export HUNTERQA_SECRET_KEY="$(cat "$HOME/.config/hunterqa/session-key")"
python run.py
```

Open `http://127.0.0.1:5000/agent-lab` in the Kali VM.
The page only reads configured local evidence. It has no form that can trigger
remote traffic or model execution.

## Scope and disclosure

Never treat contract security declarations as actual deployed access controls.
IDOR/BOLA, injection, business logic and authentication require manual tests
on the exact assets and test accounts authorized by each current program.
A synthesized candidate is not automatically bounty-eligible.

If you do opt into v1.1's bounded live HTTP observation engine, check the
program's automation and traffic rules first. It has no credential/attack
payload execution, WAF bypass, proxy rotation, brute force or stealth mode.

**Zero-day research:** the project can help formulate and correlate hypotheses
from source and isolated fuzz evidence. New vulnerability status, impact and
CVE assignment require independent reproducibility and coordinated disclosure.
There is no guarantee of finding unknown flaws.

## v1.2 owned-browser and controlled replay milestone

A second implementation milestone now lives on this same development branch:

- `bounty-browser-lab`: isolated, non-persistent headless Playwright
  against an **owned local loopback application only**, with optional
  explicitly authorized single-form login, strict response handling, and
  no saved credentials, cookies, HTML, HAR or screenshots.
- `bounty-replay-head`: credential-free HEAD comparison of sanitized,
  in-scope HAR observations using the original pinned-IP authorization gate.
- Read-only browser and replay summary cards on `/agent-lab`.

See `docs/BROWSER_LAB_V1_2.md` for exact Kali installation, private
policy examples, optional Chromium acceptance, and important network-isolation
limits. Playwright routes are not an OS firewall; use a disposable lab VM.
No browser automation against public HackerOne/Bugcrowd assets is available.

## Human verification dossiers and offline reproducibility

This v1.2 branch also includes a new create-only local analyst review
workflow. Correlation suggestions are always unverified. A reviewer may
record a `not_reproducible`, `false_positive`, `out_of_scope`,
`needs_more_evidence`, or `analyst_validated` decision. Validated
decisions require a separate, matching manual reproduction note and
sanitized impact/reproduction statements. All decisions are SHA-256
linked, but not cryptographically signed.

`bounty-repeatability` compares two HEAD replay reports from the same
program and sanitized HAR source **without sending network requests**.
Stable HTTP response codes are not proof of vulnerability.

See `docs/REVIEW_V1_2.md` for exact CLI examples, report export,
approved-root restrictions, privacy limitations and disclosure rules.

## Offline review-cue accuracy benchmarking

The v1.2 development branch includes an independently labeled, completely
synthetic OpenAPI regression pack. Run `bounty-benchmark --strict` against the
private profile and local pack to score review prompts, not live security
vulnerabilities. It measures false positives, missed review prompts and
unlabeled suggestions, and exports privacy-safe aggregate metrics for the
`/agent-lab` calibration card. No scans, exploitation or external requests.

See `docs/BENCHMARK_V1_2.md` for complete Kali commands and label caveats.

## Next v1.2 milestones (not yet implemented)

- Independent host-level browser network isolation for trusted future
  expansions beyond the currently owned-loopback-only browser lab.
- Fine-grained HTTP interception and safe replay approvals with strict limits.
- Independent verification against owned benchmarks, without mistaking
  human attestations for automatically proven exploitability.
- Program profile import validation and richer reporting templates.
- Benchmarks using OWASP Juice Shop, WebGoat and crAPI in isolated labs.

Do not merge or tag a v1.2 stable release until all CI and Kali tests and
manual dashboard acceptance pass.
