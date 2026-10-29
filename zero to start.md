# Zero to Start · HunterQA 1.3.0

![HunterQA cybersecurity assessment flow](docs/assets/hunterqa-cybersecurity-infographic.png)

**From a clean Kali environment to a reviewed, traceable assessment.**

[Overview](README.md) · [Release inventory](docs/RELEASE_1_3_0.md) · [Runtime contracts](docs/WORKFLOW_RUNNER.md) · [Security](SECURITY.md)

> This guide covers source version **1.3.0**. Confirm the published tag on [GitHub Releases](https://github.com/ManeaAl-Shabrain/HunterQA-AI/releases). A prepared release branch is not a published release. The first walkthrough below is entirely offline and uses files you create yourself.

## Your route

For a marked implementation inventory and a reproducible setup check, use the
[feature checklist](docs/FEATURE_READINESS_CHECKLIST.md) and
[owned-lab readiness guide](docs/READINESS.md). `assessment-readiness` performs
read-only checks; `assessment-benchmark` runs only its owned loopback fixtures.
Neither certifies comprehensive coverage or authorizes a customer test.

For post-release development features, use the [assessment adapters and shared
quota guide](docs/ASSESSMENT_ADAPTERS.md). `coverage-audit` reports the seven-area
implementation status; `assessment-benchmark` runs the versioned owned application
baseline. Neither command certifies complete pentest coverage. These additions
are absent from the original v1.3.0 archive; the walkthrough below remains the
offline release baseline.

| Step | Outcome |
| --- | --- |
| 1. Prepare | Python environment and current source |
| 2. Verify | Correct installed version and passing checks |
| 3. Create a case | Private source, policy, configuration and output |
| 4. Review and run | An offline workflow with an explicit execution fingerprint |
| 5. Assess evidence | Analyst review, reports and a conservative retest |
| 6. Extend carefully | Optional approved HTTP, browser and local-AI workflows |
| 7. Maintain | Updates, backups, diagnostics and release verification |

## 1. Prepare Kali and install

Use a Kali/Linux environment you control. Keep assessment data separate from the public repository. A disposable VM is useful for executable lab research; a VM alone does not enforce target scope.

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip

git clone https://github.com/ManeaAl-Shabrain/HunterQA-AI.git
cd HunterQA-AI
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev,quality]'
hunterqa --version
```

Expected for this source: **HunterQA AI 1.3.0**. Before its PR is merged or release published, use the reviewed release branch/archive rather than assuming `main` already contains it. After publication, use `git switch --detach v1.3.0` for the immutable release, or stay on `main` for development.

| Component | Required? | Purpose |
| --- | --- | --- |
| Python 3.11+, Git and virtual environment | Yes | CLI, local app and fixed workers |
| Semgrep executable | Optional | SAST scan/campaign commands |
| Ollama plus supported local Qwen model | Optional | Local AI suggestions |
| Playwright extra and Chromium | Optional | Browser workflows/tests |
| Instrumented compiler/AFL++ | Optional | Isolated executable lab research |

Install Semgrep only for source scanning: `python -m pip install semgrep`. Optional local model/browser dependencies are not required for the offline lesson.

## 2. Verify the installation

```bash
hunterqa doctor --json
python -m ruff check hunterqa zeroscope tools --select F
python -m bandit -r hunterqa zeroscope tools -ll
python -m pytest -q
python tools/verify_release_1_3.py
```

The release verifier creates its own temporary synthetic case, exercises the actual workflow CLI, verifies reports/retesting and makes no target requests. Optional browser/platform tests may be skipped in the default suite.

For browser acceptance:

```bash
python -m pip install -e '.[dev,quality,browser]'
python -m playwright install --with-deps chromium
HUNTERQA_REAL_BROWSER_CI=1 HUNTERQA_ENGAGEMENT_BROWSER_CI=1 python -m pytest -q
```

These tests use owned loopback services or synthetic intercepted responses. They do not assess a public website. Re-run optional bundled-rule checks after installing Semgrep:

```bash
python tools/verify_semgrep_rules.py
```

## 3. Create your first private offline case

Keep this terminal in the repository with the virtual environment active. Choose a fresh case name if the example directory already exists.

```bash
umask 077
mkdir ../hunterqa-demo-v130
export HUNTERQA_CASEDIR="$(realpath ../hunterqa-demo-v130)"
export HUNTERQA_APPROVED_ROOTS="$HUNTERQA_CASEDIR"
mkdir "$HUNTERQA_CASEDIR/source"

printf 'FROM example:latest\nUSER root\n' > "$HUNTERQA_CASEDIR/source/Dockerfile"

python - <<'PY'
import json, os
from pathlib import Path
root = Path(os.environ["HUNTERQA_CASEDIR"])
profile = {
    "program": "Owned offline teaching fixture",
    "platform": "local-lab",
    "authorization_reference": "Owned synthetic local files; this lesson authorizes no external traffic",
    "acknowledged_authorization": True,
    "allowed_hosts": ["app.example.test"],
    "excluded_hosts": [],
    "allowed_paths": ["/"],
    "excluded_paths": [],
    "methods": ["HEAD"],
    "allowed_ports": [443],
    "max_requests": 1,
    "interval_seconds": 1,
    "lab_mode": False,
    "allow_private_network": False,
    "allow_http": False
}
with (root / "profile.json").open("x", encoding="utf-8") as stream:
    json.dump(profile, stream, indent=2)
PY
```

The fictional URL below supplies a scope label; the default workflow sends no traffic and performs no DNS lookup. **Do not add `--observe` to this teaching case.** Any real target needs a separate profile backed by actual written authorization.

Your case will contain:

```text
hunterqa-demo-v130/
├── source/             owned source/configuration
├── profile.json        permission reference and exact scope
├── plan-001/           reviewed protocol, bindings and execution plan
├── run-001/            private SQLite state, evidence and reports
└── run-002/            independent retest
```

## 4. Plan, inspect and run offline

Create the starter:

```bash
hunterqa workflow-setup \
  --profile "$HUNTERQA_CASEDIR/profile.json" \
  --project "$HUNTERQA_CASEDIR/source" \
  --target "https://app.example.test/" \
  --out-dir "$HUNTERQA_CASEDIR/plan-001" --authorized

python -m json.tool "$HUNTERQA_CASEDIR/plan-001/execution-plan.json"
```

Read the scope, bindings, selected adapters, limits and fingerprints. This starter selects declared assets → local configuration/API review → evidence index → reporting. Service enumeration and active validation are unselected, not silently completed.

After reviewing this wholly offline fixture, obtain its execution fingerprint:

```bash
export HUNTERQA_EXECUTION_SHA="$(python -c 'import json,os; from pathlib import Path; print(json.loads((Path(os.environ["HUNTERQA_CASEDIR"])/"plan-001"/"execution-plan.json").read_text())["execution_sha256"])')"

hunterqa workflow-run \
  --profile "$HUNTERQA_CASEDIR/profile.json" \
  --protocol "$HUNTERQA_CASEDIR/plan-001/protocol.json" \
  --bindings "$HUNTERQA_CASEDIR/plan-001/bindings.json" \
  --approve-execution "$HUNTERQA_EXECUTION_SHA" \
  --out-dir "$HUNTERQA_CASEDIR/run-001" \
  --operator "Local teaching operator" --authorized
```

Expected: a completed offline run with two configuration candidates, zero charged requests and new report files. The Dockerfile is inspected as text; no container is built or executed.

| Artifact | Meaning |
| --- | --- |
| `run.sqlite3` | Durable state, quota, reviews and event chain |
| `*.result.json` | Fixed-worker result artifacts |
| `summary.json` | Initial run summary |
| `report.html` | Printable report |
| `report.sarif` | Conservative candidate export |
| `*.network.jsonl` | Only present for applicable live workers; durable intent/outcome records |

An existing output directory is rejected. Never delete a prior case to bypass this; choose a new run name. If a plan expires, create and review a fresh plan.

## 5. Open the dashboard and review evidence

```bash
export HUNTERQA_WORKFLOW_RUN="$HUNTERQA_CASEDIR/run-001"
python run.py
```

Open **http://127.0.0.1:5000/workflows**. Keep the server on loopback. Stop it with Ctrl+C before continuing CLI examples in the same terminal.

The page shows recorded state, charged reservations, selected/completed stages, candidates and audit references. Refresh for current records. It cannot start a workflow or accept arbitrary file paths.

Review the generated HTML directly in your browser, or export a fresh report:

```bash
hunterqa workflow-status --run "$HUNTERQA_CASEDIR/run-001"
hunterqa workflow-export --run "$HUNTERQA_CASEDIR/run-001" \
  --format html --out "$HUNTERQA_CASEDIR/report-after-review.html"
```

Use browser Print → Save as PDF for a PDF copy. Keep detailed evidence private. An initial generated report does not automatically change after later analyst decisions; export again under a new filename.

### Record a responsible analyst decision

Get a candidate ID from `workflow-status`. Create an evidence note based on your own inspection, then record `needs-review` while deployment impact remains unknown:

```bash
printf 'Inspected the owned Dockerfile declaration; runtime deployment impact is unverified.\n' \
  > "$HUNTERQA_CASEDIR/analyst-note.txt"

hunterqa workflow-review --run "$HUNTERQA_CASEDIR/run-001" \
  --finding EXACT_CANDIDATE_ID --decision needs-review \
  --reviewer "Local analyst" --note "Deployment impact needs independent verification" \
  --evidence "$HUNTERQA_CASEDIR/analyst-note.txt" --authorized
```

Replace `EXACT_CANDIDATE_ID` with the full ID. `confirmed` and `false-positive` are also analyst attestations; they are not independently verified owner identities or proofs of exploitability. SARIF remains conservative and labels exported candidates unverified.

## 6. Make a change and retest

Change only the synthetic Dockerfile you created:

```bash
printf 'FROM example:1\nUSER 10001\n' > "$HUNTERQA_CASEDIR/source/Dockerfile"

hunterqa workflow-run \
  --profile "$HUNTERQA_CASEDIR/profile.json" \
  --protocol "$HUNTERQA_CASEDIR/plan-001/protocol.json" \
  --bindings "$HUNTERQA_CASEDIR/plan-001/bindings.json" \
  --approve-execution "$HUNTERQA_EXECUTION_SHA" \
  --out-dir "$HUNTERQA_CASEDIR/run-002" \
  --operator "Local retest operator" --authorized

hunterqa workflow-compare --first "$HUNTERQA_CASEDIR/run-001" \
  --second "$HUNTERQA_CASEDIR/run-002" --out "$HUNTERQA_CASEDIR/retest.json"

hunterqa workflow-benchmark --out "$HUNTERQA_CASEDIR/fixture-benchmark.json"
```

Within the still-valid plan window, the retest should report two candidates not observed. This demonstrates configuration-rule behavior, not proof that a deployed vulnerability was repaired. A project binding approves a mutable directory; it is not an immutable source snapshot. Each new invocation is an explicit local attestation, and budgets are per run.

The benchmark covers three synthetic Docker fixtures. Its score does not measure overall vulnerability discovery accuracy.

## 7. Move to explicitly authorized live checks

Use a separate real assessment case. Obtain the owner's written permission and define exact targets, ports, methods, paths, testing window, traffic limits and permitted actions. Empty exclusions never expand an allowlist.

1. Create a private real scope profile using `examples/bounty_profile.example.json`.
2. Use `bounty-preflight` for an existing target list, or review a new workflow protocol.
3. Use `workflow-setup --observe` only when HEAD/GET observations are permitted.
4. Inspect `workflow-run-plan` output. Approve its exact execution hash.
5. For every required checkpoint, also pass `--approve-protocol EXACT_PROTOCOL_SHA256 --approve-step STEP_ID`.
6. Start with the smallest necessary request budget and retain an emergency-stop terminal.

The observation adapter prefers HEAD when the profile permits it, otherwise GET. It uses pinned DNS/TLS transport, no proxies/retries/redirects, sequential calls and conservative stop conditions. HTTP status matches do not prove successful authentication or a vulnerability.

```bash
hunterqa workflow-stop --run /absolute/path/to/your/run
hunterqa workflow-abandon --run /absolute/path/to/crashed-run --authorized
```

Stop is supervised outside the worker; workers also watch expiry, deadlines and parent death. An already sent request cannot be recalled. Abandon refuses a held coordinator lock, reconciles unfinished records and never replays traffic.

For separate account/browser checks, follow [approved engagements](docs/APPROVED_ASSESSMENTS.md). The dedicated-account HTTPS check and narrow remote form browser remain separate from workflow workers. The original `bounty-browser-lab` supports only an owned loopback application. Playwright interception is not an OS firewall.

## 8. Add evidence and optional research tools

| Need | Command or guide |
| --- | --- |
| Offline Nuclei/ZAP evidence | `external-import`; [formats and limits](docs/RESEARCH_WORKFLOWS.md) |
| Source SAST | `scan` or `campaign` after installing Semgrep |
| Configuration/API/dependencies | `audit`, `bounty-api-inventory`, `cve-check` with a local advisory snapshot |
| Original methodology | `research-playbooks`, `research-init`, `research-note`, `research-resume` |
| Local AI | `hypothesize`, `bounty-ai-review`, `propose-fix`; model advice is unverified |
| Private disclosure dossier | `bounty-review-init` → `bounty-review-decide` → `bounty-review-export` |
| Reviewed package | `engagement-package`; private unsent disclosure/CVE-request draft |
| Executable crash research | `verify-crashes` only in a separately isolated owned lab |

Install Ollama from its official distribution and run it locally. Supported model examples in the constrained agent review are `qwen2.5-coder:3b` and `qwen2.5-coder:7b`. Downloading a model requires network access; subsequent supported model calls use the fixed loopback service.

```bash
ollama pull qwen2.5-coder:3b
hunterqa doctor --check-ollama --json
```

Ollama must be running for the probe/model commands. No external model provider is required. Imported reports and AI output never become executable instructions.

## 9. Update, back up and verify archives

Before updating, preserve local edits and back up the complete private case directory, including SQLite and evidence artifacts. Avoid replacing guides/source while a worker run is active.

```bash
git status --short --untracked-files=all
git fetch origin --tags
git switch main
git pull --ff-only origin main
source .venv/bin/activate
python -m pip install -e '.[dev,quality]'
hunterqa --version
python tools/verify_release_1_3.py
```

Resolve local edits deliberately if Git refuses the switch/pull. Do not use `reset --hard`, `git clean` or force-push as an update procedure. Updating source/runtime code invalidates old execution fingerprints; generate and review a new plan.

Build a new archive from a clean, reviewed checkout:

```bash
python tools/build_release.py --repo . --out ../HunterQA-AI-1.3.0-source.zip
python tools/verify_release_archive.py ../HunterQA-AI-1.3.0-source.zip
```

For downloaded published assets, run `sha256sum -c HunterQA-AI-1.3.0-source.zip.sha256` beside the archive, then verify its internal manifest. Only trust checksums from the authenticated release source. Immutable historical releases remain separate.

## 10. Troubleshooting

| Symptom | Check and next step |
| --- | --- |
| Wrong version after pulling | Activate the intended environment; reinstall with `python -m pip install -e '.[dev,quality]'`; inspect `python -m pip show hunterqa-ai` |
| Directory outside approved roots | Use canonical absolute paths and explicitly set `HUNTERQA_APPROVED_ROOTS`; keep source/config/run as siblings |
| Execution fingerprint mismatch | Recreate `workflow-run-plan` after code, profile, protocol or binding changes; read it before approving |
| Plan expired or window closed | Obtain a valid testing window and generate a new reviewed plan |
| Output already exists | Choose a fresh output filename/run directory; preserve previous evidence |
| Missing approval checkpoint | Review and explicitly name every pending checkpoint against the exact protocol fingerprint |
| Worker failed/timed out | Inspect recorded step state and selected limits; distinguish missing/invalid input from a security finding |
| Recorded running after a crash | Confirm the coordinator is gone; use `workflow-abandon`; no automatic replay |
| Integrity check failed | Preserve the complete case, investigate changed/missing artifacts, and do not treat it as verified evidence |
| Browser unavailable | Install the browser extra, Chromium and required Linux libraries |
| Semgrep/Ollama warning | Install/start only the optional engine you need; offline configuration review still works |
| Dashboard unavailable | Use 127.0.0.1:5000 and inspect port use; do not expose the server publicly |
| Missing findings on retest | Compare matching scope/assessment coverage; absence alone does not prove repair |

## Readiness before a real assessment

- Written authorization and exact scope are current.
- The local environment and selected adapters passed relevant checks.
- The execution plan and all required checkpoints were personally reviewed.
- Traffic, concurrency, deadline and emergency-stop behavior are understood.
- Private evidence storage and retention are established.
- Findings, severity labels and AI suggestions will receive human review.

**Release-ready means the documented local capability set passes its checks. It does not mean unrestricted testing, zero false positives, guaranteed discovery, a verified company grant service or safe public multi-user deployment.**
