# HunterQA AI v1.2 — Playwright Browser Lab & Controlled HEAD Replay

**Status:** Original v1.2 browser baseline, extended in current development source.
The rendered-link crawl below is not included in the immutable v1.3.0 release.

## Rendered-link discovery (development source)

Add `--crawl` to `bounty-browser-lab` to inspect links created by JavaScript,
then visit admitted anchors breadth-first in the same ephemeral context. An
optional explicitly approved local login can precede discovery; its in-memory
session is reused without exporting cookies. Login remains **attempted_unverified**.
Only your owned, isolated `127.0.0.1` lab is supported by this browser mode.

```bash
hunterqa bounty-browser-lab \
  --profile /absolute/private/lab-profile.json \
  --url http://127.0.0.1:49151/app \
  --crawl --max-pages 3 --max-depth 1 --settle-ms 250 \
  --out /absolute/private/rendered-discovery.json --authorized
```

Use the actual port and scope of your already running owned lab. This command
does not start a fixture server. Copy the profile fields described below into
your private scope file, with your permission reference and allowed/excluded
paths. For local login, use the existing credential environment variables and
`--login --login-post-path /login`; no credentials belong in command arguments.

| Bound | Behavior |
| --- | --- |
| Pages | 1–10; default 3, counting the page after optional login as depth zero |
| Depth | 0–3; default 1 |
| Rendering window | 0–2000 ms per page; default 250, not a guarantee that all JavaScript finished |
| Link sample | First 200 rendered anchors per page; at most 200 admitted URLs retained internally |
| Requests | Shared existing browser budget: minimum of policy budget and 20, including login, scripts, fetches and subresources |
| Navigation | Same exact scheme, IP and port; admitted paths only; queries and unapproved redirects denied |

`discovery.pages` contains URL hashes, depths, and capped form/link counts, not
URLs, page content, input values, form actions, cookies or credentials.
`limit_reached` indicates a page/depth/frontier/link-sample bound; even when
false, `coverage_complete` remains false. Oversized or out-of-scope links are
skipped. Repeated URLs and fragments do not cause repeated crawler visits.
Only anchors are followed; forms and application buttons are not operated by
the crawler. Page JavaScript still runs and can initiate admitted GET requests.
GET endpoints in this lab must be designed to avoid state changes.

Denial/rate-limit/server-error responses, request-budget exhaustion or unexpected
page navigation stop the run. Navigation and request timeouts remain in force;
this is not a hard wall-clock limit or a browser-process resource sandbox.
Keep the OS/network isolation described below. Failed runs do not produce a
successful crawl report; inspect the failure and use a fresh output file.

Real Chromium tests cover delayed JavaScript links, reuse of an owned login
cookie, page/depth/request limits, exclusions, query rejection, cross-port
blocking and report privacy. Run them only in your isolated owned lab:

```bash
HUNTERQA_REAL_BROWSER_CI=1 python -m pytest -q tests/test_browser_lab_playwright_v12.py
```

This increment does not provide remote authenticated crawling, SSO negotiation,
automatic SPA interaction, API endpoint enumeration or vulnerability validation.
The separate `assessment-benchmark` continues to measure its original fixed
HTML/SQL-error/access/TCP fixtures, not this optional browser capability.

## Remaining development sequence

1. Extend owned-lab browser evidence and session contracts before adding more interactions.
2. Add labeled owned-app validation cases per vulnerability class; distinguish cues from demonstrated impact.
3. Model SSO and business workflows with explicit roles and expected outcomes.
4. Add offline directory/attack-path and cloud permission analysis with reviewed evidence sources.
5. Design and independently test tenant isolation and worker enforcement before hosted deployment.

These are pending stages, not capabilities enabled by `--authorized`. All seven
broad readiness areas remain partial and real-world effectiveness is unverified.

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

The browser functionality is included in stable v1.2.0 after reproducible CI
checks; verify it in an isolated owned Kali lab before relying on it.
A passed browser login fixture does not prove
security vulnerability detection, zero-day discovery, WAF bypass, or
fitness for public production targets.
