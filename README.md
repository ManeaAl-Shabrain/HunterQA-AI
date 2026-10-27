# HunterQA AI

**One local vulnerability research platform for Kali Linux.** A unified Flask dashboard, fixed local Semgrep rules, configuration and API policy checks, dependency inventory, AFL++ crash replay, ASan/UBSan evidence parsing, optional CodeQL SARIF import, and Ollama-assisted review. No cloud account, remote scanning, stealth/evasion mechanism, or automatic exploit execution.

> **Scope/accuracy:** This repository is a serious **research foundation**, not a machine that proves every vulnerability or discovers every zero-day. Rules only flag candidates; dedicated lab tests and human review determine actual impact. The platform never automatically marks a zero-day or assigns an unsupported CVSS score.

## Install on the existing Kali VM

Test environment: 2 vCPUs and ~5 GiB RAM. Run Ollama and CPU-heavy fuzzing **separately** to avoid resource exhaustion.

1. Stop your currently running ZeroScope/HunterQA Flask server (`Ctrl+C`). Keep your old folder as a backup.
2. Extract **one** packaged repository:

```bash
cd ~/Desktop
tar -xzf HunterQA-AI.tar.gz
cd HunterQA-AI
```

3. Preserve old scan history (if available). For an in-place/renamed previous dashboard the legacy database may be under `~/Desktop/hunterqa-dashboard/instance/zeroscope.sqlite3`:

```bash
mkdir -p instance
cp -n ~/Desktop/hunterqa-dashboard/instance/zeroscope.sqlite3 instance/zeroscope.sqlite3 2>/dev/null || true
./scripts-migrate.sh
```

This does not overwrite the old database and migrates `instance/zeroscope.sqlite3` to `instance/hunterqa.sqlite3`. If the previous database uses SQLite WAL, stop the old server before copying.

4. Create the Python environment. Flask and pytest require internet access **once for installation**; runtime checks do not require a cloud connection.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
semgrep --version
ollama list
```

Existing installations of Semgrep and Ollama may be reused. If Semgrep is missing, install it with `pipx install semgrep`; install Ollama from its official Linux installer (review before executing). Pull the model if not present: `ollama pull qwen2.5-coder:3b`.

5. **Authorize local directories** and point at your existing research evidence. Do not include remote domains or an arbitrary user's directory.

```bash
export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"
export HUNTERQA_RESEARCH_REPORT="$HOME/ZeroScope-AI/research-lab/verification/integrated_report.json"
export HUNTERQA_OLLAMA_MODEL="qwen2.5-coder:3b"
export HUNTERQA_FUZZ_STATS="$HOME/ZeroScope-AI/research-lab/fuzz-output-v3/default/fuzzer_stats"
export HUNTERQA_HYPOTHESES_REPORT="$HOME/ZeroScope-AI/research-lab/hypotheses.json"
export HUNTERQA_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python run.py
```

6. Open **http://127.0.0.1:5000** in Firefox **inside Kali**. The server never binds to `0.0.0.0`. The app uses the existing Flask authorization confirmation before each web scan.

> Set the secret key consistently across restarts if you want existing sessions to remain valid. Consider saving environment variables in a private local setup script (`chmod 600`) that is never added to Git.

## All components in one repository

```text
HunterQA-AI/
├── hunterqa/
│   ├── __init__.py               Flask app + migration / config
│   ├── routes.py                 Web routes, CSRF and authorized scan workflow
│   ├── db.py                     SQLite projects, findings, dependencies, audit
│   ├── orchestrator.py           Unified offline source scan coordinator
│   ├── scanner.py                One-worker asynchronous Flask scan service
│   ├── research.py               Old/new report normalization
│   ├── evidence.py               SHA256 + conservative provenance correlation
│   ├── evidence_refresh.py       Read-only atomic file snapshot
│   ├── security.py               Approved-roots and CSRF
│   ├── agent_adapter.py          Read-only legacy agent JSON normalization
│   ├── cli.py / __main__.py      CLI entry points
│   ├── engines/
│   │   ├── config_audit.py       Docker/K8s/Terraform hints
│   │   ├── dependencies.py       Local package inventory + offline advisory match
│   │   ├── openapi.py            Offline JSON OpenAPI policy hints
│   │   ├── sarif.py              CodeQL/SARIF import adapter
│   │   ├── sanitizers.py         ASan and UBSan evidence parsing
│   │   ├── fuzzing.py            Limited crash replay in approved local lab
│   │   ├── ai_research.py        Ollama local code hypotheses (not executed)
│   │   └── hypotheses.py         Manual research taxonomy/checklist
│   ├── rules/semgrep.yml        Bundled offline Semgrep source rules
│   ├── templates/              Dashboard and research views
│   └── static/                 Local CSS/JS
├── zeroscope/                  Tiny legacy Python import compatibility shims
├── examples/local_lab/        Deliberately vulnerable isolated C test programs
├── tests/                     Regression, correlation, routes and engine tests
├── docs/                      Architecture, security model and limitations
├── run.py                     Loopback-only Flask entrypoint
└── scripts-migrate.sh         Non-destructive legacy database rename
```

## Daily workflow

**Browser:** the Research Lab can also display AFL++ `fuzzer_stats` (set `HUNTERQA_FUZZ_STATS`) and a separate AI Hypotheses page from `HUNTERQA_HYPOTHESES_REPORT`. Register your own source directory in `Projects`, type the exact authorization statement, start a scan, review unverified findings and dependency inventory, then use `Research Lab` to inspect crash/sanitizer evidence from your local lab. `Coverage & Engines` shows current functionality and research-only categories. JSON export includes the input report SHA-256.

**CLI:** use the *same repository* for offline research jobs. All source/lab commands require an approved root and/or explicit authorization.

```bash
# One unified source scan: Semgrep + local configuration + OpenAPI + inventory
python -m hunterqa scan --project "$HOME/ZeroScope-AI/targets" --out "$HOME/ZeroScope-AI/research-lab/source_scan.json" --authorized

# Fast deterministic audit even if Semgrep is unavailable
python -m hunterqa audit --project "$HOME/ZeroScope-AI/targets" --out "$HOME/ZeroScope-AI/research-lab/local_audit.json"

# Local Qwen research hypotheses; no generated code is executed
python -m hunterqa hypothesize --project "$HOME/ZeroScope-AI/targets" --out "$HOME/ZeroScope-AI/research-lab/hypotheses.json" --authorized

# Parse existing ASan log into normalized JSON
python -m hunterqa parse-sanitizer --file "$HOME/ZeroScope-AI/research-lab/uaf_sanitizer.log" --out "$HOME/ZeroScope-AI/research-lab/sanitizer.json"

# Import a manually produced local CodeQL SARIF report
python -m hunterqa import-sarif --file /path/to/result.sarif --out /path/to/sarif-findings.json

# Normalize old and integrated research evidence
python -m hunterqa research-report --file "$HUNTERQA_RESEARCH_REPORT" --out "$HOME/ZeroScope-AI/research-lab/normalized_report.json"
```

### Crash verification (isolated VM only)

The browser **never executes binaries or fuzzers**. Research binaries can run arbitrary code, so use an isolated Kali VM without access to sensitive networks. The CLI checks approved paths and explicit authorization, limits duration and output, and never accepts hostnames or remote URLs. These controls are **not** a secure sandbox on their own.

```bash
export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/research-lab"
python -m hunterqa verify-crashes \
  --lab "$HOME/ZeroScope-AI/research-lab" \
  --binary "$HOME/ZeroScope-AI/research-lab/fuzz_target_san" \
  --crashes "$HOME/ZeroScope-AI/research-lab/fuzz-output-v3/default/crashes" \
  --out "$HOME/ZeroScope-AI/research-lab/verification/integrated_report.json" \
  --authorized
```

**Important:** replay only with the **same corresponding build** if possible. A sanitizer report is linked to an input only if *both* input and executable SHA-256 match. Your old `FUZZTEST2026` intentional abort and `uaf_test.c` UAF remain **separate evidence**.

## Coverage and detection claims

| Research area | Actual implementation | Limits |
|---|---|---|
| Injection, XSS, insecure deserialization | Selected bundled Semgrep rules | Candidate patterns, not verified vulnerabilities |
| Memory safety | ASan/UBSan parser and controlled crash replay | Requires instrumented local executable / test harness |
| Config/cloud/container | Selected Docker, Terraform, K8s file checks | Not a complete cloud posture assessment |
| APIs/auth | Offline OpenAPI JSON contract policy hints | Cannot prove backend authorization without tailored tests |
| Dependency / supply chain | Local inventory; optional user-provided advisory snapshot | No live CVE feed, constraint resolution or automatic patching |
| Binary analysis | Import analyzer SARIF when available | Does not automatically reverse engineer arbitrary binaries |
| Logic and privilege boundaries | Structured manual checklist + local Qwen hypotheses | Needs domain-specific invariants, test accounts, code context |
| Fuzzing | AFL++ local lab fixtures, bounded replay | Fuzz campaigns prepared/executed separately in VM |
| CWE/CVSS | CWE candidates from explicit evidence; CVSS human review | Pattern severity is not CVSS; no automatic zero-day designation |

## Security model / guardrails

- Loopback-only Flask server, CSRF tokens, signed sessions, safe HTML escaping, no frontend-supplied CLI arguments, and approved local directory constraints with path resolution.
- Scans require explicit authorization and run one worker at a time (fits small Kali VM).
- Semgrep uses local rules and `--metrics=off`; it does not retrieve registry rules in this configuration.
- Local Ollama is fixed to `127.0.0.1:11434`. Its generated text is not trusted evidence or executable code.
- Read-only research report loader: maximum 1 MiB, symlink rejection, older and newer JSON schemas, bounded fields.
- Sanitizer evidence is tracked separately from AFL++ crashes unless cryptographic provenance matches. Even matched provenance requires review.
- `audit_events` records local project registration and scan authorization. The app is designed for single-user local use; it is not multi-user hardened or a production network service.
- No stealth, evasion, password attacks, unsolicited scanning, remote probes, or exploit payload delivery.

## Automated tests

```bash
source .venv/bin/activate
python -m compileall -q hunterqa zeroscope
python -m pytest -q
```

The package is supplied as source; install and run the full Flask/Semgrep/Ollama integration tests on Kali. Individual tests do not by themselves prove detection accuracy in real repositories.

## References

- [Semgrep CLI and local rules](https://semgrep.dev/docs/)
- [AFL++ comparison instrumentation](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.laf-intel.md)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [MITRE CWE](https://cwe.mitre.org/)
