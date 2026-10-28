# Scoped HTML discovery

**Development addition after v1.3.0.** This adapter is absent from the immutable
published v1.3.0 archive. Use source containing `discovery-setup`.

HunterQA can inventory links and forms from explicitly approved seed pages and
follow admitted HTML links. This is the first website-discovery increment, not a
complete crawler or penetration test. See the [expansion roadmap](ASSESSMENT_EXPANSION_ROADMAP.md).

## Before starting

1. Obtain written authorization covering **GET discovery**, the seed origins,
   allowed paths, exclusions, testing window and request budget. GET requests can
   have application side effects; exclude logout, destructive and sensitive paths.
2. Fill a private copy of the [scope template](../templates/HunterQA-scope-template.json).
   Permit `GET`; retain only the approved hosts, ports and paths. Public remote
   targets require HTTPS. HTTP/private addresses require explicit owned-lab settings.
3. Keep the profile, configuration, run and evidence under a private approved local
   root. Never commit filled customer files to this repository.

## Plan → review → approve → run

The following Linux example uses a documentation-only hostname. Replace it with
your explicitly approved seed and private paths. Planning sends **zero requests**.

```bash
export HUNTERQA_APPROVED_ROOTS=/srv/assessments/customer

hunterqa discovery-setup \
  --profile /srv/assessments/customer/scope.json \
  --seed https://approved.example.test/app \
  --max-pages 5 --max-depth 1 \
  --out-dir /srv/assessments/customer/discovery-config --authorized
```

Review all three generated files: `protocol.json`, `bindings.json`, and
`execution-plan.json`. The profile bytes, protocol, depth binding and installed
Python/package sources are bound into the review fingerprint. The helper creates
a one-hour window; the protocol compiler permits at most 24 hours. Edits require
a new execution plan and fresh review:

```bash
hunterqa workflow-run-plan \
  --profile /srv/assessments/customer/scope.json \
  --protocol /srv/assessments/customer/discovery-config/protocol.json \
  --bindings /srv/assessments/customer/discovery-config/bindings.json \
  --out /srv/assessments/customer/review.json
```

Replace both placeholders below with the reviewed `execution_sha256` and
`preflight.protocol_sha256`. This approval permits dynamic link following within
the seed origins and profile; step targets are **seeds**, not an exhaustive URL list.
Repeat `--seed` during setup to approve additional seed origins; profile membership
alone does not authorize following links to an additional origin.

```bash
hunterqa workflow-run \
  --profile /srv/assessments/customer/scope.json \
  --protocol /srv/assessments/customer/discovery-config/protocol.json \
  --bindings /srv/assessments/customer/discovery-config/bindings.json \
  --out-dir /srv/assessments/customer/discovery-run \
  --approve-execution EXACT_EXECUTION_SHA256 \
  --approve-protocol EXACT_PROTOCOL_SHA256 --approve-step discover \
  --operator "Your assessment operator reference" --authorized

hunterqa workflow-status --run /srv/assessments/customer/discovery-run
hunterqa workflow-export --run /srv/assessments/customer/discovery-run \
  --format html --out /srv/assessments/customer/discovery-report.html
```

Request an emergency stop from another terminal with
`hunterqa workflow-stop --run /srv/assessments/customer/discovery-run`.
The supervisor terminates the worker on cancellation or timeout. A logged intent
can lack a response; it does not prove the server received the request. Never
automatically replay an interrupted run.

## Enforced bounds

| Control | Behavior |
| --- | --- |
| Traffic | GET only; no JavaScript, form submissions, session storage or credential forwarding |
| Scope | Exact seed origins plus profile host/port/path restrictions and exclusions; validated DNS answers are pinned by the existing transport |
| URL admission | No queries, embedded credentials, ambiguous encoded paths or redirects; fragments are removed from discovered links |
| Reservation | 1–20 total requests per discovery step, including seeds; constrained by profile and whole-run quota; unused reservations are not refunded |
| Pacing | Profile minimum interval, serialized network workers, existing concurrency and deadline controls |
| Crawl | Breadth first, depth 0–3; at most 200 link candidates per page and 200 queued URLs per step |
| Inventory | At most 200 endpoint hints, 100 forms and 200 informational findings per step; omitted inventory sets a limits flag |
| Response | Existing transport caps body reads at 1 MiB; only `text/html` is parsed as UTF-8 with replacement |
| Safety stop | Redirects, 401/403, 429, 5xx and transport failures stop follow-up work |

## Reading the evidence

- A visited URL means an HTTP response was observed. An unvisited endpoint is a
  link hint, not completed coverage or proof of an accessible service.
- Forms show an admitted action URL, method, field count and input types. They are
  never submitted. Field names, values, response bodies and script contents are
  not copied into inventory. Admitted URLs are retained in private journals and
  reports; path segments can still contain sensitive identifiers.
- HSTS, CSP, nosniff and cookie-flag observations remain **informational,
  unverified candidates**. Absence of a header does not establish exploitability.
- `limits_reached`, `queued_unvisited`, `skipped`, and the recorded depth identify
  incomplete discovery. No findings does not mean the site is secure.
- JSON/HTML reports and the local `/workflows` view include discovery inventory.
  SARIF contains candidates, not a complete endpoint/form inventory.
- Retest comparison binds the request reservation and depth. A smaller budget or
  depth is not treated as equivalent coverage.

JavaScript-heavy pages, authenticated roles, query-driven routes, API discovery,
subresource discovery, active vulnerability validation, network scanning and cloud
runtime checks remain outside this adapter. Audit hashes detect inconsistency;
they do not authenticate the owner or prevent forgery by the run-directory owner.

## Verification scope

`tests/test_web_discovery.py` exercises real supervised workers against an owned
loopback server, plus original offline positive/negative header/cookie controls.
These tests establish the tested behavior and boundaries only. They do not measure
real-world detection rates, exploitability, or full OWASP standards coverage.
