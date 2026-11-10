# Selected SPA hash-route discovery

The opt-in `browser-discovery` engagement mode can retain and visit explicit
slash hash routes such as `https://app.example.test/app#/overview`. Previously
all fragments were discarded as section anchors. Conventional rendered links
and existing three-field discovery plans keep their previous behavior unless
`hash_routes` is explicitly supplied.

This remains bounded anchor navigation, not arbitrary clicking or business-flow
automation. A hash route is an application state, not necessarily another HTTP
endpoint or a successfully authenticated page.

## Prepare and approve

Follow the [rendered discovery setup](SCOPED_RENDERED_DISCOVERY.md), including
written permission, the exact HTTPS origin/path, approved private directories,
an isolated browser and any dedicated conventional-login account. Select the
logical hash routes in the permission review too. Example planning command:

```bash
hunterqa engagement-plan --profile "$CASE/scope.json" \
  --url https://app.example.test/app --mode browser-discovery \
  --browser-isolated --max-pages 3 --max-depth 2 --settle-ms 250 \
  --hash-route /overview --hash-route /details \
  --out "$CASE/hash-plan.json"
```

Review the plan with `engagement-preflight`, then use its exact approval digest
with the usual `engagement-run` inputs. Adding, removing or changing a selected
route changes the plan fingerprint and requires a new review. The options stored
in that plan are:

```json
{
  "max_pages": 3,
  "max_depth": 2,
  "settle_ms": 250,
  "hash_routes": ["/overview", "/details"]
}
```

Choose 1–10 unique case-sensitive routes, each at most 256 ASCII characters.
Routes start with `/` and contain ordinary letter/digit/underscore/hyphen path
segments, with an optional final slash. `/` itself is supported. Do not include
`#`. Queries, percent encoding, traversal/dot segments, repeated slashes,
whitespace, Unicode and hashbang syntax (`#!/...`) are unsupported. No route
normalization, wildcard or prefix matching is performed.

## Navigation and limits

Selected fragments are accepted only on the original start document, on the
same HTTPS origin and exact path. Ordinary HTTP path exclusions and query
restrictions remain enforced. Hash route selection does not permit an excluded
HTTP request. Another document's `#/overview` link is not admitted by this list.

The list is an admission list, not a set of guessed navigation seeds. The
crawler follows selected hash routes exposed by anchors in observed states;
the application's scripts can reveal further anchors after navigation. A route
that is selected but never exposed is not automatically probed.

Hash states consume the existing `max_pages` (1–10) and depth (0–3) bounds even
when changing the fragment sends no document request. The existing per-invocation
HTTP budget still counts each resource/fetch request separately. Gate checks
also run around states and snapshots, so no-network hash changes do not bypass
expiry or a stop file. The existing settle wait is bounded to 0–2000 ms.

Same-document navigation may return no new HTTP response; this is accepted only
for an admitted fragment transition. A missing response for an ordinary document
navigation still stops the run. The URL is checked after settling and after the
DOM snapshot. An observed unexpected route change stops inventory collection.
See [Playwright navigation behavior](https://playwright.dev/python/docs/api/class-page#page-goto).

These checks constrain the crawler's chosen navigation and detect observed
changes. They are not a firewall around every transient client-side state: page
JavaScript still executes and can change state between checks. Existing
same-origin network interception, fixed methods, credential binding, CSP,
resource restrictions and ephemeral context cleanup remain in force. They do
not provide OS or tenant isolation.

## Evidence and coverage

The discovery report retains complete URL hashes including admitted fragments,
the number of selected/visited hash states, and each observation's
`navigation_kind`: initial document, new document, or same-document fragment.
Raw selected route names, DOM, cookie values and session storage are not exported.
The private reviewed plan still contains its selected route names. Hashes are
guessable for common routes and do not authenticate evidence provenance.

For `engagement-discovery-coverage`, hash the full expected URL, including `#`
and the exact selected fragment. Ordinary fragment-free route references keep
their existing meaning. Supply an independently maintained reference list:

- `reference_discovery_recall` counts reference URLs exposed in the admitted
  link inventory, including links not visited because of a limit.
- `reference_visit_recall` and visited match/missing counts use retained page/state
  observations. They are null for legacy inventories without page observations.

Duplicate, malformed or undiscovered visit hashes are rejected. A visit does not
prove a successful HTTP response, a correct rendered view, an authenticated
session or endpoint completeness. Unlabelled URLs are not false positives;
reference authenticity and field effectiveness remain unverified.

Owned Chromium controls cover two states revealed in sequence, optional
dedicated login, no extra document requests for same-document transitions,
unselected/foreign/document-mismatched anchors, autonomous route changes,
page/depth bounds, request budgets and stops. General SPA actions, external SSO,
complex sessions, query-based routers and representative compatibility testing
remain unfinished.

This engagement mode retains invocation-local limits; the optional shared ledger
for selected [native commands](NATIVE_SHARED_QUOTAS.md) does not automatically
meter it. Cross-host quota and multi-user enforcement remain unfinished.
