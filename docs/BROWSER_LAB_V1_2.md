# HunterQA AI v1.2 — Playwright Browser Lab & Controlled HEAD Replay

**Status:** v1.2 development on `feature/v1-2-ai-research-orchestration`.
The published v1.1.0 stable release is not modified.

## Implemented in this milestone

### Playwright local browser laboratory

`bounty-browser-lab` offers a disposable, headless Chromium browser context
against exactly one **owned 127.0.0.1 application**. The entire program profile
must declare `platform: local-lab`, `lab_mode: true`,
`allow_private_network: true`, exactly one `allowed_hosts: ["127.0.0.1"]`,
one approved port, and `GET` in its allowed methods. Browser policy rejects
every other host or port.

The browser:
- Registers context-wide request interception **before** creating a page.
- Blocks other origins, unexpected methods, ambiguous paths and query strings.
- Requires a single explicitly approved login POST endpoint and refuses all
  other modifying requests.
- Stops on HTTP 401/403/429/5xx, enforces the smaller of 20 or the program
  request budget, and uses a minimum interval of 0.5 seconds.
- Disables service workers, downloads, stored HAR/screenshots, saved browser
  profiles, location permissions, and WebSocket access.
- Accepts credentials *only* from `HUNTERQA_LAB_USERNAME` and
  `HUNTERQA_LAB_PASSWORD` environment variables (never CLI flags or Git).
- Saves only SHA-256 fingerprints and aggregate page/network counts: never
  passwords, cookies, tokens, response content or screenshots.
- Labels login status **attempted_unverified**; the browser does not prove
  security impact or successful authentication.

**Network isolation warning:** Playwright request interception is an
application-level guard, not a firewall. Browser-internal traffic and network
implementation bugs require an isolated VM/container or network namespace
with host-level egress restrictions. Never use this build against remote
HackerOne/Bugcrowd programs.

### Safe prior-HAR HEAD replay

`bounty-replay-head` accepts only a **sanitized HunterQA offline HAR import**
produced with exactly the same program policy hash. It requires HEAD testing
to be authorized. It preflights *every* target before sending anything, uses
the existing pinned-IP/TLS-validated `read_only_probe`, deduplicates URLs,
and makes at most 20 HEAD requests within the configured program budget.

The replay uses no authentication, browser state, cookies, request bodies, or
query strings; it never retries or follows redirects. It compares response
status codes and safe header **names**, not content. A difference is only an
unverified observation, never evidence of exploitability.

**Important:** HEAD replay of a saved authenticated GET response is *not*
authenticated replay; response differences can be normal.

## Optional Playwright installation on Kali

```bash
cd ~/Desktop/HunterQA-AI
source .venv/bin/activate
python -m pip install -e '.[dev,browser]'
python -m playwright install chromium
```

This installs an optional browser dependency. It does not change v1.1 Stable.
If Kali reports missing system libraries, review Playwright's Linux dependency
instructions before installing system packages.

## Real Chromium acceptance on an owned ephemeral local server

```bash
HUNTERQA_REAL_BROWSER_CI=1 \
  python -m pytest -q tests/test_browser_lab_playwright_v12.py
```

The test starts its own temporary `127.0.0.1` server, performs one
nonpersistent login attempt with disposable fixture credentials, asserts
blocked cross-port redirection, and closes the browser and server afterward.
It contacts no external website.

## Browser lab command: your own application

Run your **own** test server on `127.0.0.1:8765` (or change this example
port to its actual bind port). Save a private policy JSON in an approved root:

```json
{
  "program": "My owned disposable browser lab",
  "platform": "local-lab",
  "authorization_reference": "Owned local application test authorization",
  "acknowledged_authorization": true,
  "allowed_hosts": ["127.0.0.1"],
  "allowed_ports": [8765],
  "allowed_paths": ["/"],
  "excluded_paths": ["/admin"],
  "methods": ["GET", "HEAD"],
  "max_requests": 12,
  "interval_seconds": 1.0,
  "lab_mode": true,
  "allow_private_network": true,
  "allow_http": true
}
```

For a simple anonymous browser review (no login), with that server running:

```bash
export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"

python -m hunterqa bounty-browser-lab \
  --profile "$HOME/ZeroScope-AI/research-lab/v12/browser-scope.json" \
  --url "http://127.0.0.1:8765/" \
  --out "$HOME/ZeroScope-AI/research-lab/v12/browser-observation-001.json" \
  --authorized
```

To exercise the **optional single login submission** on your own lab app,
set `HUNTERQA_LAB_USERNAME` and `HUNTERQA_LAB_PASSWORD` in the local shell
without echoing them into the terminal, and add
`--login --login-post-path /login` with an initial URL ending `/login`.
The default selectors are `#username`, `#password`, and
`button[type=submit]`; only simple CSS selectors are accepted. Remove
credentials from the environment after the run. Use disposable test users,
not real customer credentials.

## Controlled HEAD evidence replay

After capturing your **authorized** HAR with a local intercepting proxy
and saving it only in your private approved folder:

```bash
python -m hunterqa bounty-import-har \
  --profile "$HOME/ZeroScope-AI/research-lab/bounty/profile.json" \
  --har "$HOME/ZeroScope-AI/research-lab/bounty/owned-capture.har" \
  --out "$HOME/ZeroScope-AI/research-lab/bounty/imported-001.json" \
  --authorized

python -m hunterqa bounty-replay-head \
  --profile "$HOME/ZeroScope-AI/research-lab/bounty/profile.json" \
  --har-report "$HOME/ZeroScope-AI/research-lab/bounty/imported-001.json" \
  --out "$HOME/ZeroScope-AI/research-lab/bounty/replayed-head-001.json" \
  --authorized
```

Only run HEAD replay where the program's policy explicitly permits that
automated traffic. Neither `bounty-import-har` nor the offline API agent
review sends network traffic. Do not upload original HAR evidence, browser
credentials or private reports to public GitHub.

## Quality gates and release status

The standard v1.2 CI suite tests the browser request gate without Chromium.
A separate real Chromium test uses an ephemeral owned loopback server.
Run `bash tools/verify_agent_1_2.sh` for existing API and agent acceptance,
then the optional Chromium test above.

The new code remains **development-only** until Kali acceptance, security
review and approval to merge. A passed browser login fixture does not prove
security vulnerability detection, zero-day discovery, WAF bypass, or
fitness for public production targets.
