# HunterQA AI 1.1 — Authorized Bug Bounty Edition (Development Branch)

**Branch:** `feature/v1-1-authorized-bug-bounty`  
**Status:** feature integration / regression testing; v1.0.1 remains the published stable release.

This increment introduces real, bounded remote HTTP observations under explicit
HackerOne, Bugcrowd, private-program or local-lab profiles. It adds controlled
web/API security reconnaissance on top of existing HunterQA source assessment,
Semgrep, local Qwen research, AFL++/ASan/UBSan validation, OSV/CVE intelligence
and the unified dashboard. It is NOT an unconstrained autonomous exploitation
framework.

## Initial Kali setup

```bash
cd ~/Desktop/HunterQA-AI
git status --short
git fetch origin
git switch --track origin/feature/v1-1-authorized-bug-bounty
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q
```

Copy `examples/bounty_profile.example.json` and
`examples/bounty_targets.example.txt` to an approved private research folder,
then edit for an explicitly authorized asset and exact program limits. The
example domain is fictitious; it cannot be scanned as written.

```bash
mkdir -p "$HOME/ZeroScope-AI/research-lab/bounty"
cp examples/bounty_profile.example.json "$HOME/ZeroScope-AI/research-lab/bounty/profile.json"
cp examples/bounty_targets.example.txt "$HOME/ZeroScope-AI/research-lab/bounty/targets.txt"

export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"

python -m hunterqa bounty-preflight \\
  --profile "$HOME/ZeroScope-AI/research-lab/bounty/profile.json" \\
  --targets "$HOME/ZeroScope-AI/research-lab/bounty/targets.txt"
```

Once the program's rules allow HEAD requests, change the example to real
approved assets and run:

```bash
python -m hunterqa bounty-assess \\
  --profile "$HOME/ZeroScope-AI/research-lab/bounty/profile.json" \\
  --targets "$HOME/ZeroScope-AI/research-lab/bounty/targets.txt" \\
  --method HEAD --authorized \\
  --out "$HOME/ZeroScope-AI/research-lab/bounty/assessment-001.json"
```

To view the report:

```bash
export HUNTERQA_BOUNTY_REPORT="$HOME/ZeroScope-AI/research-lab/bounty/assessment-001.json"
export HUNTERQA_SECRET_KEY="$(cat "$HOME/.config/hunterqa/session-key")"
python run.py
```

Open `http://127.0.0.1:5000/bounty` in Kali Firefox. No HTTP test
runs simply by viewing the dashboard.

## Security controls

- Exact-host allowlist, explicit excluded hosts and path prefixes, checked
  before requests. No wildcard scope or subdomain discovery.
- HTTPS only by default, approved ports, optional HTTP **only** if explicitly
  permitted; lab-only private address access.
- Resolve all DNS answers, reject unsafe public DNS results, then connect to
  **pinned vetted IP**, retaining host-based TLS certificate validation.
- No redirects, proxies, authentication handling, query strings, cookies
  in outbound requests, exploit payloads, hidden active scans or crawling.
- Single-process request budgets (1–40), fixed minimum intervals, 5-second
  per-request timeout, response size limits, and stop-on-429.
- Response-cookie **values and body contents are not stored**; only a hash
  of bounded body bytes for GET. Header and cookie observations are hypotheses,
  not confirmed or bounty-eligible vulnerabilities.
- Reports are kept locally inside approved project roots; no automatic
  HackerOne/Bugcrowd submissions or external CVE requests.

A profile with `acknowledged_authorization: true` is the operator's declaration,
not independent proof that the program permits the scan. Always check the
current Bounty Brief / Security Page and program policy, rate limits, forbidden
techniques, asset exclusions and disclosure rules before sending any request.



## Offline penetration-testing proxy evidence (Burp / ZAP / browser HAR)

Export a HAR after manually testing an authorized app. Place the HAR in the
approved private research folder and **never commit** its raw contents: it may
contain authentication headers, personal data or response bodies.

```bash
python -m hunterqa bounty-import-har \
  --profile "$HOME/ZeroScope-AI/research-lab/bounty/profile.json" \
  --har "$HOME/ZeroScope-AI/research-lab/bounty/capture.har" \
  --out "$HOME/ZeroScope-AI/research-lab/bounty/har-reviewed.json" \
  --authorized

python -m hunterqa bounty-report \
  --file "$HOME/ZeroScope-AI/research-lab/bounty/har-reviewed.json" \
  --out "$HOME/ZeroScope-AI/research-lab/bounty/report-draft.md"
```

HAR input is never replayed. Out-of-scope entries are skipped. Query strings,
cookies, authorization headers, response bodies and any request bodies are
excluded from the resulting JSON. All observations remain unverified until
independently reproduced with demonstrable impact; do not submit merely
missing-security-header observations as confirmed vulnerabilities.

The Markdown output is a **draft** for analyst correction and subsequent
HackerOne/Bugcrowd submission; there is no automatic API submission or ticket
filing. Build your own minimal safe reproduction and check the program's
policy, severity matrix, known issues and exclusions.

## Broader penetration testing and zero-day research

Use the existing local source tools for authorized repositories:

```bash
python -m hunterqa scan --project "$HOME/ZeroScope-AI/targets" \\
  --out "$HOME/ZeroScope-AI/research-lab/local-sast.json" --authorized

python -m hunterqa campaign --project "$HOME/ZeroScope-AI/targets" \\
  --out-dir "$HOME/ZeroScope-AI/research-lab/bounty-local-campaign" \\
  --with-ai --ai-chunks 4 --authorized
```

Run the existing `cve-check` with a real offline OSV snapshot for published
CVE aliases. The AFL++ and sanitizer engines can help investigate potentially
unknown defects on isolated binaries. An AI hypothesis, missing header or
crash is not proof of a new vulnerability, let alone a confirmed zero-day.
No software can guarantee finding all vulnerabilities or zero false positives.

## Next v1.1 phases

A truly useful bug bounty agent also needs authenticated Playwright replay,
HTTP interception integration, isolated agent execution, granular test
permissions, OWASP API checks with consenting test accounts, proof validation,
issue deduplication, and HackerOne/Bugcrowd markdown report templates.
Those are **planned**, not implemented by this first network-safe increment.

Do not merge or publish a stable 1.1.0 release until full Kali regression,
scope-negative testing, and manual review succeed.
