# HunterQA AI

**One local, authorization-gated AI-assisted vulnerability research platform for Kali Linux.**

HunterQA combines offline static/code analysis, local Qwen hypotheses, trust graphs, bounded lab crash replay, sanitizer evidence, advisory/CVE intelligence and analyst review in one Python/Flask repository. HunterQA AI 1.1 additionally introduces strictly scoped, explicitly authorized HEAD/GET observations and offline HAR review, while retaining all existing research engines.

**HunterQA AI v1.1.0 is the stable, tested local-authorized Bug Bounty Edition.** Prior v1.0.1 and v1.0.0 releases remain available. This is not a production multi-user service or autonomous exploitation framework. Human review of research findings remains required. No tool can guarantee finding every vulnerability, zero false positives, or independent CVE issuance. A research record, advisory match or ASan diagnostic is not automatically a confirmed exploitable vulnerability.

## HunterQA AI v1.2 — Research Orchestration (Development Branch)

**v1.2 is under active development on `feature/v1-2-ai-research-orchestration`;
v1.1.0 remains the latest published stable release.** This branch adds offline
OpenAPI route authorization review, seven constrained AI research roles,
private Ollama/Qwen role prioritization, source-linked evidence deduplication,
a read-only AI Agent Lab dashboard and conservative low-noise HTTP stop
conditions. This is not unrestricted autonomous exploitation or stealth mode.

See [v1.2 Kali instructions](docs/V1_2_DEV.md) for
`bounty-api-inventory`, `bounty-agent-plan`, `bounty-ai-review`,
`bounty-correlate`, and the `/agent-lab` dashboard.
Read [reference review and license notes](docs/INSPIRATION_V1_2.md).
For local acceptance after installing this feature branch:

```bash
bash tools/verify_agent_1_2.sh
```

No third-party-target network scanning is part of the v1.2 offline acceptance.

**New owned-browser milestone:** `bounty-browser-lab` optionally performs a
single approved login on a locally owned `127.0.0.1` test application using
ephemeral Playwright Chromium. `bounty-replay-head` rechecks only exact,
previously sanitized HAR endpoints with a credential-free HEAD request.
Neither mode provides WAF evasion, remote authenticated exploitation, brute
force, or live browser access to third-party bounty programs. Both modes keep
private user data and credentials out of the public repository and report.
See [the browser lab and safe replay guide](docs/BROWSER_LAB_V1_2.md).

**New analyst verification milestone:** `bounty-review-init` builds a
scope-bound finding dossier from existing correlation evidence.
`bounty-reproduction-note` requires an explicit human attestation tied
to the exact finding, `bounty-review-decide` creates a new hash-linked
dossier revision, and `bounty-review-export` creates a private Markdown
draft only for analyst-validated cases. `bounty-repeatability` compares
two approved HEAD reports **offline** without new network requests.
No automated CVE or zero-day confirmation is provided. See
[the private analyst review guide](docs/REVIEW_V1_2.md).

**Offline Review Cue Benchmark:** `bounty-benchmark` evaluates labeled,
fully synthetic OpenAPI schemas for useful versus unnecessary API review
prompts. The CI gate checks for missed suggestions, unexpected suggestions,
and unlabeled predictions. Review-cue precision is NOT real security
vulnerability accuracy. No targets are contacted. See
[the synthetic benchmark guide](docs/BENCHMARK_V1_2.md) and the
read-only Agent Lab calibration card.


Install optional browser support with `python -m pip install -e '.[dev,browser]'`.


## Bug Bounty Edition v1.1 — stable local release

See `docs/BUG_BOUNTY_V1_1.md` for the exact scope profile, `bounty-preflight`, `bounty-assess`, `bounty-import-har`, `bounty-report` and read-only dashboard workflow. This is bounded authorization-gated reconnaissance, offline proxy evidence review, and local source/vulnerability research—not unrestricted penetration-test automation or proof of a zero-day.

## Current local install / update (existing Kali checkout)

```bash
cd ~/Desktop/HunterQA-AI
git status --short
git fetch origin
git switch main
git pull --ff-only origin main
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

If your current branch has uncommitted changes, preserve them before switching. Stop before switching if `git status` shows uncommitted work; preserve it separately. Keep your existing `instance/` SQLite data and `~/ZeroScope-AI/research-lab/` evidence intact.

For a brand-new local checkout, install Python >= 3.11, Git, and a Python virtual environment first. Semgrep and Ollama are optional external local tools for relevant engines. See `docs/` for detailed workflows.

## Single-command acceptance check

```bash
export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"
export HUNTERQA_SECRET_KEY="$(cat "$HOME/.config/hunterqa/session-key")"
bash tools/verify_bounty_1_1.sh
```

This verifies Python compilation, the full regression suite, scope rejection, privacy-safe HAR review, ten Flask routes against **disposable SQLite data**, and a bounded SHA-256 source release ZIP. Review all failures and warnings. It does not certify real-world vulnerability-detection coverage. CI runs source QA on pull requests, without credentials or web-app deployment.

## Run the dashboard (Kali VM only)

```bash
export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"
export HUNTERQA_CAMPAIGN_HISTORY_ROOT="$HOME/ZeroScope-AI/research-lab"
export HUNTERQA_CVE_REPORT="$HOME/ZeroScope-AI/research-lab/verification/cve_validation_8_6.json"
export HUNTERQA_TRIAGE_REPORT="$HOME/ZeroScope-AI/research-lab/verification/hunterqa_unified_triage.json"
export HUNTERQA_SECRET_KEY="$(cat "$HOME/.config/hunterqa/session-key")"
python run.py
```

Open `http://127.0.0.1:5000` **inside Kali**. Check `ss -ltnp | grep ':5000'` for loopback-only binding. If the local secret file is missing, create it with `bash tools/setup_verify_kali.sh`, or follow `docs/RELEASE_DOCTOR_8_1.md`; never commit it.

Pages include Overview, Projects, Research Lab, Unified Triage, AI Hypotheses, Research Analytics, Campaign History, Research Trends, CVE Intelligence, Coverage & Engines, Audit History, and **Bug Bounty Lab** at `http://127.0.0.1:5000/bounty`. Opening a dashboard page never runs a remote scan.

## Research capabilities and limits

| Engine | Current functionality | What it does not prove |
|---|---|---|
| Semgrep + local source checks | Selected offline rules and config checks | Complete CWE detection or exploitability |
| Trust graph | AST-based local functions/routes/call edges | General accurate taint analysis in every language |
| Local Ollama/Qwen | Bounded hypotheses and remediation proposals | Verified weaknesses or safe code changes |
| Patch guard | Rejects known unsafe replacement patterns | Semantic correctness of all patches |
| AFL++ lab / sanitizer | Crash replay and ASan/UBSan evidence parsing | Every crash is security-relevant |
| Unified triage and analyst review | Evidence-linked candidate and review history | An AI-only confirmed zero-day |
| Offline CVE engine | User-supplied OSV snapshot, exact and selected range matches | Current verified installed packages |
| Dependency inventory | Pinned requirements and supported npm, Poetry, uv, Composer lockfiles | That every dependency is installed/reachable |
| History / trends / analytics | Compare local evidence over time | That record differences are actual regressions |
| Release Doctor / QA | Local readiness, regression, bounded archive checks | Production-grade deployment certification |

Unrecognized lockfile entries, advisory ranges, missing snapshots, absent source files and uncertain scope remain **unassessed**; they do not mean “secure.” CVE aliases come from external advisories and are not created by the model. Source revisions, advisory age and incomplete test coverage can change results.

## Example authorized local campaign

```bash
python -m hunterqa campaign \
  --project "$HOME/ZeroScope-AI/targets" \
  --out-dir "$HOME/ZeroScope-AI/research-lab/authorized-campaign" \
  --with-ai --ai-chunks 4 --authorized
```

Use a fresh output directory. Crash replay and sanitizer execution are **separate explicit opt-in lab actions**; run untrusted binaries only in an isolated VM. No stealth, evasion or unsolicited remote scanning is included.

## Example offline CVE check

An OSV-format snapshot must already be present **inside** approved local roots. This command does not download any vulnerability intelligence or execute project code.

```bash
python -m hunterqa cve-check \
  --project "$HOME/ZeroScope-AI/research-lab/cve-validation-demo" \
  --snapshot "$HOME/ZeroScope-AI/research-lab/osv_validation_demo.json" \
  --out "$HOME/ZeroScope-AI/research-lab/verification/cve_review_new.json" \
  --authorized
```

For the user's historical Jinja2 3.1.3 test input, eight saved GHSA/PYSEC advisory records represented four distinct CVE aliases. That fixture is **not** proof of four exploitable installed vulnerabilities, and the OSV snapshot may go stale. See `docs/ADVISORY_QUALITY_8_6.md` and `docs/RESOLVED_DEPENDENCIES_8_5.md`.

## Generate a complete, self-contained source ZIP

```bash
python tools/build_release.py --repo . --out "$HOME/Desktop/HunterQA-AI-1.1.0-source.zip"
python tools/verify_release_archive.py "$HOME/Desktop/HunterQA-AI-1.1.0-source.zip"
```

The builder packages tracked project code, templates, docs and tests; it excludes common local SQLite databases, secrets, logs and fuzz outputs. Review the ZIP before public distribution. SHA-256 archive manifest verification proves consistency with the included manifest, not independent publisher authenticity.

## Security model

- Flask app listens on loopback in single-user Kali lab; not a public production service.
- Browser form writes use CSRF protections and require explicit project authorization.
- Local evidence is bounded and should be kept outside the published repository.
- Model output is not executed automatically and cannot independently mark a finding a zero-day.
- Signature/manifest integrity is not equivalent to trusted provenance.
- Approved roots, offline-only research, audit logs, sanitized evidence display and review gates are design controls, not a sandbox around arbitrary project code.
- Back up `instance/hunterqa.sqlite3` before migration or switching to a new release. Never overwrite analyst history as a testing shortcut.

## License and release

HunterQA-owned source is licensed under the **MIT License**; see `LICENSE`. See `SECURITY.md` for vulnerability reporting and local authorized research boundaries. External dependencies, models and advisory datasets retain their own licenses and terms.

## Release and contributors

For full release validation, rollback and security limitations, see `docs/RELEASE_1_0_CHECKLIST.md`. Earlier stacked phase PRs are intermediate historical development changes. For official v1.1.0 release notes, see `docs/RELEASE_1_1_0.md`. The version tag points to the reviewed `main` release commit.

This is a research project. Findings should be validated and reported responsibly to affected maintainers.
