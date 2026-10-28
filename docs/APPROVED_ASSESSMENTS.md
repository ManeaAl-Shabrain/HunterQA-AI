# Approved assessment plans (1.3.0)

These CLI features extend the v1.2 research workflow. They are not part of the
immutable v1.2.0 release archive. The dashboard does not launch assessments.

## What is implemented

| Need | Implemented mode | Boundary |
| --- | --- | --- |
| Automated validation | `observe` | Execute a fixed reviewed list of exact HEAD/GET requests. No model-selected tools, exploit payloads or crawling. |
| WAF testing | `waf-canary` | GET with fixed `X-HunterQA-Test: approved-benign-canary`. Configure a temporary rule on your own WAF to recognize it. A matching response only checks that canary's expected behavior; it does not measure attack coverage. No evasion. |
| Account testing | `auth-check` | One HTTPS form POST to the exact approved endpoint using one designated disposable test account. Fixed `username` and `password` fields. No candidate lists, guessing, spraying, or lockout stress testing. |
| Remote authenticated browser | `browser` | One exact HTTPS page, optionally one approved same-origin login POST. Fresh Chromium context, JavaScript disabled, fixed conventional form selectors, no external assets, redirects, SSO, SPA workflows or saved sessions. Counts forms/links after an uninterrupted observation. |
| Reporting | `engagement-package --kind disclosure` | A reviewed private handoff from an existing analyst-validated dossier. No external submission. |
| CVE coordination | `engagement-package --kind cve-request` | Prepare a private request and optionally record an externally assigned identifier as unverified. HunterQA does not allocate IDs or verify CNA assignment. |
| Unknown vulnerability research | Existing isolated fuzz/crash and source workflows | Continue collecting candidates and reproducibility evidence; no guaranteed discovery or proof of novelty. |

Every new live mode needs a reviewed plan and an explicit invocation. There is
no unrestricted autonomous exploitation, stealth, WAF bypass, password attack,
automatic platform submission, automatic official CVE allocation, or guaranteed
zero-day discovery hidden behind an approval switch.

## Permission and controls

Use the current owner's written authorization and method-specific program terms.
Create a private existing [scope profile](BUG_BOUNTY_V1_1.md) with exact hosts,
ports, allowed/excluded paths, and GET enabled for form/browser checks. POST is
a separate plan exception for one login endpoint; it does not expand profile
methods globally. Existing bounty commands keep their old behavior.

Plans bind to the exact profile bytes and permission reference, expire within
24 hours, and have 1–20 steps within the profile budget. All steps are checked
offline before traffic. Browser mode must be the only step. The operator must
pass the plan's exact canonical SHA-256 fingerprint and `--authorized` at run
time; editing the plan or profile requires another review. JSON duplicate keys
and unknown plan/step fields are rejected.

Each invocation permits at most 20 requests or the smaller profile budget,
with the profile interval (minimum 0.5 seconds). Browser requests share that
budget. There is at most one credential POST per invocation. Budgets and
approvals are **per invocation**, not a persistent cross-run quota or one-use
permission token. A single operator can rerun a plan with a new output file
until it expires. The local hash and booleans are operator attestations, not
signatures or independently verified owner authorization.

HTTP transport checks the full DNS answer set and pins a permitted IP while
retaining hostname-based TLS verification. No environmental proxies, automatic
redirects or retries are used. Stop on redirects, 401/403, 429, server errors,
transport errors, expiry or the stop file. Consequently a normal login redirect
is reported as stopped/inconclusive, rather than successful authentication.

The stop file is checked before each request and while waiting between requests.
It does not interrupt an in-flight request, DNS resolution, browser operation or
an already launched browser process. Response bodies are limited to 1 MiB and
HTTP sockets use a five-second timeout. Playwright operations have bounded
timeouts. Use OS-level process/network controls when immediate termination is
required. Browser isolation is an operator attestation: run in a disposable VM
with network egress controls. Browser interception is not a firewall.

## Example: plan, review, execute

These are Kali commands. Replace paths and the fictional hostname with an
actually authorized service; do not send requests to the example hostname.
Keep profiles, plans and reports outside the public checkout. Plan generation
and preflight are offline; `engagement-run` sends real requests.

```bash
export HUNTERQA_APPROVED_ROOTS="$HOME/private-hunterqa"
folder="$HOME/private-hunterqa"

hunterqa engagement-plan --profile "$folder/profile.json" \
  --url https://app.example.test/health --mode observe --method GET \
  --expected-status 200 --ttl-minutes 60 --out "$folder/plan.json"

hunterqa engagement-preflight --profile "$folder/profile.json" --plan "$folder/plan.json"
# Read the displayed plan and current written permission. Copy approval_sha256.

hunterqa engagement-run --profile "$folder/profile.json" --plan "$folder/plan.json" \
  --approve-plan COPY_REVIEWED_SHA256_HERE --authorized \
  --stop-file "$folder/STOP" --out "$folder/result-001.json"
```

Create the stop file from another terminal with `touch "$folder/STOP"`.
Use a new output name for every run; the CLI reserves a create-only private
output before traffic. A preflight failure leaves an error-type-only file;
inspect the error, review changes and choose another name for a later run.
Do not delete a stop file until the assessment owner has resolved the reason.

For a WAF canary plan, use `--mode waf-canary --method GET` with the status
your temporary approved WAF rule should return. Expected 403/429 responses
still stop the assessment. They do not trigger bypasses or retries.

For a single account check use `--mode auth-check --method POST
--dedicated-test-account`. The URL must be the exact HTTPS form endpoint.
Provide `HUNTERQA_TEST_USERNAME` and `HUNTERQA_TEST_PASSWORD` through your local
secret mechanism, then clear them after the run. The tool accepts only one
pair, whether you are checking an expected successful or expected failed login.
It does not infer successful authentication or account lockout from a status.

For browser review, install `pip install -e '.[browser]'` and
`python -m playwright install chromium`. Generate a plan with `--mode browser
--method GET --browser-isolated`, plus `--login-url https://app.example.test/login
--dedicated-test-account` for a login. Only `input[name="username"]`,
`input[name="password"]`, and `button[type="submit"]` are supported. The
approved start URL and optional login URL are the only routed endpoints;
other assets/actions are blocked. This intentionally narrow mode cannot audit
an authenticated application broadly or follow a login redirect. Provide the
same two credential environment variables. Before launching the Playwright
driver or Chromium, the browser mode removes test/legacy lab credential variables
from its own process environment; the invoking shell is unaffected. No cookies,
DOM, screenshots or credentials are exported.

## Evidence and reviewed handoff

### Offline comparisons and dashboard

```bash
hunterqa engagement-compare --first "$folder/result-001.json" \
  --second "$folder/result-002.json" --out "$folder/comparison-001.json"

export HUNTERQA_ENGAGEMENT_REPORT="$folder/result-002.json"
export HUNTERQA_ENGAGEMENT_BASELINE="$folder/result-001.json"
python run.py
# Open http://127.0.0.1:5000/assessments
```

The comparison and dashboard do not send assessment traffic. Reports must be
within approved roots and reference the same exact plan/profile fingerprints
and step identities/order. Different expiry values create different plans and
are deliberately incompatible. Stopped runs may have unequal coverage; missing
status/body observations remain unknown rather than being called unchanged.
Comparisons describe response status and bounded body fingerprints, not a
vulnerability verdict, remediation proof, or authentication result. Canonical
report content fingerprints check consistency, not signatures or author identity.
Only allowlisted metadata reaches the dashboard; arbitrary report text and raw
request/response material are not forwarded. Expired historical reports remain
readable offline; viewing them does not renew approval or rerun their plans.

### Validation and handoff

Assessment reports contain plan/profile fingerprints, hashed target references,
request counts, status observations, optional expected-status comparisons, and
browser structure counts. They export no response bodies or cookie values.
Raw exception messages are omitted because browsers and servers may include
private contents in them. A report is an observation, not vulnerability proof.
It is not automatically imported into the v1.2 known-rule correlation engine.
Independently reproduce an actual candidate, then follow the existing
[analyst dossier workflow](REVIEW_V1_2.md). No status match alone qualifies it.

```bash
hunterqa engagement-package --profile "$folder/profile.json" \
  --dossier "$folder/validated-dossier.json" --kind disclosure \
  --reviewed --authorized --out "$folder/disclosure-package.json"

hunterqa engagement-package --profile "$folder/profile.json" \
  --dossier "$folder/validated-dossier.json" --kind cve-request \
  --reviewed --authorized --out "$folder/cve-request-package.json"
```

Both commands call the existing dossier validation gate and refuse packages
with no analyst-validated case. The package records a draft digest and
`submitted: false`. Review private data, duplicates, exact affected asset,
reproduction and recipient rules, then submit through the authorized channel.
Optional `--assigned-cve CVE-2026-12345` records a real externally assigned ID;
its syntax is checked, but its authenticity remains unverified. Request
preparation does not make HunterQA a CVE Numbering Authority.

## Verification

```bash
python -m pytest -q tests/test_engagement.py
HUNTERQA_ENGAGEMENT_BROWSER_CI=1 python -m pytest -q tests/test_engagement.py
```

The opt-in tests use real Chromium and entirely synthetic, intercepted HTTPS
responses, including successful responses, redirects, denials and rate limits.
They do not assess a remote service or prove OS-level browser containment.
Linux CI also runs the existing full regression and owned-loopback acceptance.
