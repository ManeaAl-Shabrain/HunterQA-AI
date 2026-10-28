# HunterQA AI

**One local, authorization-gated AI-assisted vulnerability research platform for Kali Linux.**

HunterQA combines offline static/code analysis, local Qwen hypotheses, trust graphs, bounded lab crash replay, sanitizer evidence, advisory/CVE intelligence and analyst review in one Python/Flask repository.

**The 1.0 branch is a release review candidate, not yet a published stable release.** Human review and Kali acceptance are required. No tool can guarantee finding every vulnerability, zero false positives, or independent CVE issuance. A research record, advisory match or ASan diagnostic is not automatically a confirmed exploitable vulnerability.

## Current local install / update (existing Kali checkout)

\`\`\`bash
cd ~/Desktop/HunterQA-AI
git status --short
git fetch origin
git switch --track origin/release/hunterqa-ai-1-0-review
source .venv/bin/activate
python -m pip install -e '.[dev]'
\`\`\`

If this branch is already checked out locally, use \`git switch release/hunterqa-ai-1-0-review\` instead. Stop before switching if \`git status\` shows uncommitted work; preserve it separately. Keep your existing \`instance/\` SQLite data and \`~/ZeroScope-AI/research-lab/\` evidence intact.

For a brand-new local checkout, install Python >= 3.11, Git, and a Python virtual environment first. Semgrep and Ollama are optional external local tools for relevant engines. See \`docs/\` for detailed workflows.

## Single-command acceptance check

\`\`\`bash
export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"
export HUNTERQA_SECRET_KEY="$(cat "$HOME/.config/hunterqa/session-key")"
bash tools/verify_release_8_6.sh
\`\`\`

This verifies Python compilation, the full regression suite, Release Doctor, nine Flask routes against **disposable SQLite data**, and a bounded SHA-256 source release ZIP. Review all failures and warnings. It does not certify real-world vulnerability-detection coverage. CI runs source QA on pull requests, without credentials or web-app deployment.

## Run the dashboard (Kali VM only)

\`\`\`bash
export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"
export HUNTERQA_CAMPAIGN_HISTORY_ROOT="$HOME/ZeroScope-AI/research-lab"
export HUNTERQA_CVE_REPORT="$HOME/ZeroScope-AI/research-lab/verification/cve_validation_8_6.json"
export HUNTERQA_TRIAGE_REPORT="$HOME/ZeroScope-AI/research-lab/verification/hunterqa_unified_triage.json"
export HUNTERQA_SECRET_KEY="$(cat "$HOME/.config/hunterqa/session-key")"
python run.py
\`\`\`

Open \`http://127.0.0.1:5000\` **inside Kali**. Check \`ss -ltnp | grep ':5000'\` for loopback-only binding. If the local secret file is missing, create it with \`bash tools/setup_verify_kali.sh\`, or follow \`docs/RELEASE_DOCTOR_8_1.md\`; never commit it.

Pages include Overview, Projects, Research Lab, Unified Triage, AI Hypotheses, Research Analytics, Campaign History, Research Trends, CVE Intelligence, Coverage & Engines, and Audit History.

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

\`\`\`bash
python -m hunterqa campaign \
  --project "$HOME/ZeroScope-AI/targets" \
  --out-dir "$HOME/ZeroScope-AI/research-lab/authorized-campaign" \
  --with-ai --ai-chunks 4 --authorized
\`\`\`

Use a fresh output directory. Crash replay and sanitizer execution are **separate explicit opt-in lab actions**; run untrusted binaries only in an isolated VM. No stealth, evasion or unsolicited remote scanning is included.

## Example offline CVE check

An OSV-format snapshot must already be present **inside** approved local roots. This command does not download any vulnerability intelligence or execute project code.

\`\`\`bash
python -m hunterqa cve-check \
  --project "$HOME/ZeroScope-AI/research-lab/cve-validation-demo" \
  --snapshot "$HOME/ZeroScope-AI/research-lab/osv_validation_demo.json" \
  --out "$HOME/ZeroScope-AI/research-lab/verification/cve_review_new.json" \
  --authorized
\`\`\`

For the user's historical Jinja2 3.1.3 test input, eight saved GHSA/PYSEC advisory records represented four distinct CVE aliases. That fixture is **not** proof of four exploitable installed vulnerabilities, and the OSV snapshot may go stale. See \`docs/ADVISORY_QUALITY_8_6.md\` and \`docs/RESOLVED_DEPENDENCIES_8_5.md\`.

## Generate a complete, self-contained source ZIP

\`\`\`bash
python tools/build_release.py --repo . --out "$HOME/Desktop/HunterQA-AI-1.0.0-source.zip"
python tools/verify_release_archive.py "$HOME/Desktop/HunterQA-AI-1.0.0-source.zip"
\`\`\`

The builder packages tracked project code, templates, docs and tests; it excludes common local SQLite databases, secrets, logs and fuzz outputs. Review the ZIP before public distribution. SHA-256 archive manifest verification proves consistency with the included manifest, not independent publisher authenticity.

## Security model

- Flask app listens on loopback in single-user Kali lab; not a public production service.
- Browser form writes use CSRF protections and require explicit project authorization.
- Local evidence is bounded and should be kept outside the published repository.
- Model output is not executed automatically and cannot independently mark a finding a zero-day.
- Signature/manifest integrity is not equivalent to trusted provenance.
- Approved roots, offline-only research, audit logs, sanitized evidence display and review gates are design controls, not a sandbox around arbitrary project code.
- Back up \`instance/hunterqa.sqlite3\` before migration or switching to a new release. Never overwrite analyst history as a testing shortcut.

## Release and contributors

Review the single aggregate PR to \`main\` and the detailed \`docs/RELEASE_1_0_CHECKLIST.md\`. Earlier stacked phase PRs represent intermediate changes and should not be merged again on top of the cumulative release without branch-ancestry review. Do not publish a GitHub tag or stable release until approved acceptance and a license/security review are complete.

This is a research project. Findings should be validated and reported responsibly to affected maintainers.
