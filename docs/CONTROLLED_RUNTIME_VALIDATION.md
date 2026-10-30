# Controlled SQL and reflected-XSS runtime checks

This post-v1.3.0 source addition builds on scoped rendered discovery. Before
merge, use the `feature/owned-runtime-validation` branch; historical releases
do not contain these commands.

These engagement modes exercise one explicitly reviewed, owner-prepared test
endpoint using five fixed GET inputs. They accept no caller-supplied payload,
SQL query, script or target list. Use only dedicated read-only endpoints backed
by public synthetic canary data; ownership and read-only behavior are operator
attestations, not independently verified grants or backend enforcement.

## What the evidence means

| Mode | Observation | Limit |
| --- | --- | --- |
| `sql-canary-check` | A public owner-installed marker appears on both fixed true-condition probes, and stays absent on baseline/negative/repeated-baseline controls | Controlled SQL-like behavioral difference, not proof of an arbitrary database mechanism or customer exploitability |
| `xss-canary-check` | A fixed benign SVG event sets a fresh random window marker in Chromium on both probes, but not on baseline, HTML-escaped input or repeated baseline | Runtime execution witness for this reflected HTML event context only; not DOM/stored XSS or arbitrary context coverage |

Results are `matched`, `not_observed` or `inconclusive`. A stopped, incomplete,
unstable or control-failing run cannot become `matched`. `not_observed` is not a
claim that the application has no vulnerability. Customer vulnerabilities remain
unconfirmed and require analyst review and owner-side evidence.

Each invocation sends at most five fixed requests under the existing scope,
exact-plan fingerprint, expiry, rate interval, request budget and stop controls.
One validation step must be the entire plan. Redirects, non-200 responses,
transport errors, budget/expiry or a stop file end the check without retries.
The endpoint is HTTPS, except an explicitly configured owned `127.0.0.1` lab.
There is no login, credential forwarding, cookie reuse or data extraction mode.

## Plan a check

Prepare a private scope profile and an existing case directory under
`HUNTERQA_APPROVED_ROOTS`. The profile must permit GET and at least five requests.
`CASE` below names that directory. The hostname is fictional; substitute only an
actually authorized, dedicated canary endpoint.

SQL mode requires a public synthetic marker matching
`HUNTERQA_CANARY_` followed by 16–32 alphanumeric characters. Install it in the
synthetic test data so ordinary missing-value queries do not return it. The
marker is not placed in the probe, preventing literal reflection from satisfying
the positive witness.

```bash
hunterqa engagement-plan --profile "$CASE/profile.json" \
  --url https://app.example.test/canary --mode sql-canary-check \
  --parameter q --owned-test-endpoint \
  --canary-marker HUNTERQA_CANARY_0123456789ABCDEF \
  --ttl-minutes 30 --out "$CASE/sql-plan.json"
```

For reflected-XSS execution, install the browser extra and Chromium and use an
isolated disposable environment with OS egress controls:

```bash
hunterqa engagement-plan --profile "$CASE/profile.json" \
  --url https://app.example.test/reflection-canary --mode xss-canary-check \
  --parameter q --owned-test-endpoint --browser-isolated \
  --ttl-minutes 30 --out "$CASE/xss-plan.json"
```

Review the complete plan and written permission, then approve its exact hash:

```bash
hunterqa engagement-preflight --profile "$CASE/profile.json" --plan "$CASE/sql-plan.json"
hunterqa engagement-run --profile "$CASE/profile.json" --plan "$CASE/sql-plan.json" \
  --approve-plan REVIEWED_SHA256 --stop-file "$CASE/STOP" \
  --out "$CASE/sql-result-001.json" --authorized
```

Use the corresponding XSS plan for the other mode. Changed endpoints, parameters,
marker or options require a fresh plan approval. Existing output files are not
overwritten. Budgets are per invocation, not organization-wide or single-use grants.

## Browser and evidence boundaries

The browser receives each response through the existing pinned DNS/TLS transport
and never fetches it directly. Only the exact virtual page navigation is routed.
All other resource/redirect requests, frames, popups, workers and WebSockets are
blocked. Owner CSP policies and content type are preserved; an additional policy
allows only the inline canary execution, with no connections, forms or external
resources. No CSP bypass is attempted. Use a fresh context for every control so
a marker cannot survive from a previous probe.

The GET parameter is inserted by the controlled transport. It is intentionally
absent from the browser location, so this mode does not test location-driven DOM
XSS. The fixed witness changes only a synthetic window property. It does not read
cookies, application data, storage or files, and does not contact a callback.
DOM reads have a three-second wait; context/browser cleanup waits are five seconds
each. Browser interception is not an OS firewall. A stop cannot recall in-flight
requests or provide an OS-level kill guarantee.

Receipts retain case names, input/body hashes, body lengths, response status and
boolean witnesses. They omit response bodies, row values, raw probe strings,
browser storage, screenshots and credentials. The public SQL marker remains in
the private plan. A saved result's state is recomputed from its receipts during
benchmark verification; hashes provide consistency, not independent authenticity.

The local saved-assessment view shows a sanitized validation state and can
compare decisive state changes for the same approved plan. It does not display
probe strings or response bodies, and a changed state is not automatic remediation.

## Owned HTTP/Chromium benchmark

Install `.[browser]` and Playwright Chromium first. This command starts its own
ephemeral loopback HTTP service, exercises six fixed endpoints, retains evidence
and shuts the service down. It accepts no external target.

```bash
hunterqa runtime-validation-benchmark --out-dir "$CASE/runtime-001" --authorized
hunterqa runtime-validation-verify --run "$CASE/runtime-001"
```

The versioned labels in `hunterqa/fixtures/runtime-validation-v1.json` are separate
from the classifier. SQL cases use a literal-query positive, parameterized
negative and literal-reflection negative. XSS cases use a raw-HTML positive,
escaped negative and CSP-blocked negative. Five requests per case produce 30
fixture HTTP operations. The positive SQL fixture can return only its original
two-row in-memory data; SQLite permits reads only after initialization.

Reports include TP/FP/FN/TN per class, precision, recall, false-positive and
false-negative rates for decisive samples. Inconclusive positives/negatives are
separate; `positive_miss_rate` includes inconclusive positives so abstention cannot
hide missed positive cases. Zero denominators are `null`, not a perfect score.
Six synthetic endpoints are a regression baseline, not representative field rates.

Keep the whole private directory: ground truth, per-case plans/results and
`benchmark.json`. Verification checks current source/package identity, receipt
consistency and recomputed metrics **offline**; it does not launch Chromium,
replay HTTP or establish fresh vulnerability validity. Run a new benchmark into
a new directory for an independent retest. An evidence-directory owner can forge
local artifacts; this is not a signed audit or third-party evaluation.

## Standards reference and remaining coverage

The mapping below is a bounded implementation reference, not a claim that an
entire OWASP test is automated or that the tool meets a certification.

| OWASP WSTG 4.2 reference | Implemented slice | Missing breadth |
| --- | --- | --- |
| [WSTG-v42-INPV-05: SQL injection](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection/) | Fixed string-condition differential with a public synthetic marker and negative/repeat controls | Other database dialects/contexts, numeric/JSON/header inputs, timing/OOB and application-specific validation |
| [WSTG-v42-INPV-01: Reflected XSS](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting/) | Actual benign event-marker execution in a bounded reflected HTML response | Stored/DOM XSS, other parsing contexts, external resources, authentication and broad browser/application coverage |

Full active validation, independent representative evaluation and complete
standards coverage remain unfinished. See [expansion progress](EXPANSION_PROGRESS.md).
