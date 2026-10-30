# Scoped rendered discovery

`browser-discovery` is an opt-in engagement mode for an explicitly authorized
HTTPS application. It executes same-origin JavaScript, inventories rendered
anchors and follows admitted links in a bounded breadth-first traversal. An
optional dedicated-account form login supplies an ephemeral cookie session.
It does not establish successful authentication or complete endpoint coverage.

This mode is separate from the owned-loopback lab and the existing
JavaScript-disabled `browser` mode. It is a post-v1.3.0 source addition.

## Controls and supported inputs

- The reviewed plan contains the mode, start URL, optional exact login URL,
  page/depth/settling bounds, profile hash, expiry and isolation attestation.
  Editing any of these requires a new fingerprint approval.
- Every routed request uses the existing pinned DNS/TLS transport, scope
  allowlist and exclusions. Only the original HTTPS origin is eligible, even
  when the profile admits other hosts. URLs with query strings stay unsupported.
- GET documents, scripts, stylesheets, fetch and XHR resources share the
  engagement budget: at most 20 requests or the smaller profile limit. HEAD is
  restricted to the start URL. Other methods are blocked, except the one
  optional approved login POST using the supplied dedicated account.
- Credentials use `HUNTERQA_TEST_USERNAME` and `HUNTERQA_TEST_PASSWORD`.
  Only conventional username/password fields and a submit button are supported.
  Bounded extra form fields such as CSRF fields are permitted; duplicate fields
  or a different username/password stop the run. Credential environment variables
  are removed before spawning the browser driver.
- The login response must complete without a redirect. The driver then makes
  a new scoped GET to the start URL using the same ephemeral cookie context.
  No session files, browser profile or external SSO providers are imported.
- Service workers, WebSockets, child frames and popup requests are blocked.
  An extra CSP restricts scripts/connections to the same origin and disables
  images, workers, objects and frames. All owner CSP policies are retained.
- The crawler reads anchors and counts forms; it does not click application
  controls or submit forms. Executed page JavaScript can initiate GETs, which
  remain subject to the same request guard. Only use paths the owner has
  authorized for this behavior; GET alone does not guarantee absence of side effects.
- Bounds: 1–10 pages, depth 0–3, 0–2000 ms settling per page, at most 200
  retained URL hashes and 200 examined anchors per page. Scripts/assets consume
  the request budget without counting as visited pages.
- Redirects, denials, rate limits, server errors, transport errors, exhausted
  budgets, expiry and the stop file stop execution without retries.
- DOM inventory evaluation and final structure reads have three-second waits;
  context/browser cleanup waits are five seconds each. This bounds an
  unresponsive renderer read without treating it as an empty route inventory.

Run in an isolated disposable browser environment with OS egress controls.
Browser interception and CSP are not an OS firewall or process sandbox. The
isolation flag records the operator's attestation, not independently verified
isolation. The engagement budget is per invocation, not a shared organization quota.

## Plan and review

Install the browser extra and Chromium. Prepare a private scope profile as in
[approved assessments](APPROVED_ASSESSMENTS.md). These example names are
fictional; use only an actually authorized application.

```bash
hunterqa engagement-plan --profile "$CASE/profile.json" \
  --url https://app.example.test/app --mode browser-discovery \
  --browser-isolated --max-pages 3 --max-depth 1 --settle-ms 250 \
  --ttl-minutes 30 --out "$CASE/rendered-plan.json"

hunterqa engagement-preflight --profile "$CASE/profile.json" \
  --plan "$CASE/rendered-plan.json"
```

For the optional conventional login, add
`--login-url https://app.example.test/app/login --dedicated-test-account`
when creating the plan. Supply the dedicated credentials through the local
secret mechanism. Never put them in the plan, command arguments or repository.

Read the complete plan and current permission, then run with its displayed hash:

```bash
hunterqa engagement-run --profile "$CASE/profile.json" \
  --plan "$CASE/rendered-plan.json" --approve-plan REVIEWED_SHA256 \
  --stop-file "$CASE/STOP" --out "$CASE/rendered-result-001.json" --authorized
```

`CASE` must name an existing private directory under `HUNTERQA_APPROVED_ROOTS`.
Use a new output file for each invocation. Create the stop file from another
terminal to prevent subsequent requests. In-flight operations have bounded
timeouts and cannot be recalled.

## Evidence and reference coverage

The observation's `discovery` object contains visited URL hashes, depth, form
counts, admitted discovered URL hashes, bounds and truncation indicators. A
discovered URL may remain unvisited because of depth/page limits. No DOM,
screenshots, native URLs, cookies or credentials are exported. `coverage_complete`
and `authentication_verified` remain false.

To measure recall on a known application, prepare an independent reference JSON:

```json
{"schema_version": 1, "expected_url_sha256": ["REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS"]}
```

Hash each full expected URL with SHA-256, UTF-8 encoding, without a fragment.
Use the application's independently maintained route list rather than copying
the discovered output. Then compare offline:

```bash
hunterqa engagement-discovery-coverage --report "$CASE/rendered-result-001.json" \
  --reference "$CASE/expected-routes.json" --out "$CASE/discovery-coverage.json"
```

The result shows reference matches/missing routes, unlabelled discovered routes
and `reference_discovery_recall`. Unlabelled routes are not automatically false
positives. A supplied or incomplete reference is not independent field evidence.
This is endpoint inventory recall, not vulnerability detection accuracy.

## Remaining limits

No SSO negotiation, cross-origin providers/CDNs, imported sessions, bearer-token
configuration, general action-driven SPA exploration, eval-dependent scripts,
query-bearing URLs or complete route discovery is implemented. An arbitrary
framework may require resources this mode blocks. Report an incomplete or
stopped observation rather than interpreting missing links as absent endpoints.

The Chromium regression fixture uses intercepted synthetic HTTPS responses; it
tests rendered links, cookie reuse, exclusions, foreign origins, credential
binding, CSP preservation, budgets, stops and fixed independent route labels.
It makes no request to a customer or public target. Live-field effectiveness
and broad application compatibility remain unverified.
