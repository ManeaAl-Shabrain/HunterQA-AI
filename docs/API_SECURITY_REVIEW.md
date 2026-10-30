# API Security review pack

**Post-v1.3.0 development capability.** Two offline assurance contracts review
owner observations. A separate bounded reader checks selected OpenAPI 3.0/3.1 JSON
declarations without calling endpoints, following references or testing accounts.
This is not a complete API pentest or a complete OpenAPI/JSON Schema validator.

Category vocabulary references [Claude-Red](https://github.com/SnailSploit/Claude-Red/tree/main/Skills/api).
HunterQA's implementation is original. Upstream payloads, operational instructions
and tool scripts are not imported, installed or executed.

## Coverage

| Contract | Selected owner observations |
| --- | --- |
| `offensive-api-security` | Object/function authorization, authentication, response minimization, resource limits and transport policy |
| `offensive-api-abuse` | Business invariants, workflow order, idempotency, batching and webhook destination/authenticity review |

These are declarations, not independent tests. INFO cues are unverified review
aids, not CVSS or confirmed vulnerabilities. All broader readiness areas remain
partial. Independent real-world effectiveness remains unverified.

No BOLA/BFLA, tenant isolation, mass assignment, business workflow, token, webhook,
rate-limit, gRPC or WebSocket runtime validation is added. There is no request,
account action, credential testing, batching attack or exploit chain execution.

## 1. Prepare private evidence

After merging and pulling, activate the development environment and refresh with
`python -m pip install -e .`. This pack adds no dependency or external tool.
Copy [the JSON template](../templates/HunterQA-api-review-template.json) and
[private worksheet](../templates/16-api-security-review.md) outside the checkout.
Keep agreements, role/account mappings, API specifications and reports private.

```bash
umask 077
mkdir -p "$HOME/hunterqa-cases/api"
cp templates/HunterQA-api-review-template.json "$HOME/hunterqa-cases/api/evidence.json"
export HUNTERQA_APPROVED_ROOTS="$HOME/hunterqa-cases/api"
# Edit only the private copy using applicable, independently reviewed evidence.
hunterqa api-review-catalog
hunterqa api-review \
  --input "$HOME/hunterqa-cases/api/evidence.json" \
  --out "$HOME/hunterqa-cases/api/review.json" \
  --authorized
```

The root has exactly `schema_version: 1` and `records`. Each record has exactly
`id`, `skill`, `observations`; catalog/template list the exact required fields.
Neutral IDs are unique and match `[a-z][a-z0-9-]{0,47}`. Every observation must be
boolean or null. False means a declared incomplete review; null means unknown.
An untouched template reports insufficient evidence, not a pass. Remove inapplicable
records. Maximum ten records per contract, 20 total.

## 2. Review an approved OpenAPI JSON file

Use a private owner-provided specification, without tokens or real examples of
sensitive data. This command does not download or generate the file.

```bash
hunterqa api-openapi-review \
  --input "$HOME/hunterqa-cases/api/openapi.json" \
  --out "$HOME/hunterqa-cases/api/contract-review.json" \
  --authorized
```

Only selected `3.0.x` and `3.1.x` JSON layouts are supported. Swagger 2, OpenAPI 3.2,
YAML, multi-document resolution, callbacks, webhooks and operations inside components
are outside this reader. If conversion is needed, use separately reviewed trusted
tools outside this command. This reader does not certify a document's validity.

### Security declarations

The reader selects an operation's `security` when present; otherwise it uses the
root declaration. It does not merge the two. Requirement objects inside the array
are alternatives; multiple named schemes inside one object are conjunctive.
Reports retain only alternative counts and unresolved-scheme counts, not names/scopes.

| Declaration | Report interpretation |
| --- | --- |
| Absent at operation/root | Not declared; actual server authentication remains unknown |
| Explicit `security: []` | No security requirement declared for that selected scope |
| An empty object in an alternative | Anonymous alternative declared |
| Named schemes | Mechanisms declared, without verification of enforcement |
| Undefined/referenced/unsupported scheme | Unresolved mechanism declaration |

Explicit anonymous alternatives remain visible even when another alternative is
unresolved. Public operations can be intentional. The reader cannot determine
object/function permissions, OAuth flow correctness, JWT validity or role semantics.
API-key-in-query and HTTP Basic definitions produce INFO cues even if unused by
operations. Review actual usage, TLS and credential policy separately. Security
scheme definitions are not completely validated.

### Servers and inline request bounds

Server arrays use operation, then path, then root precedence. Empty or relative
declarations do not produce an insecure-transport verdict. An explicit selected
`http://` declaration produces a review cue, without requesting or exporting URLs.
Absence of an HTTP URL does not prove TLS protection or correct deployment.

Inline parameters use operation-over-path precedence by name and location. Any
unresolved parameter reference makes the selected parameter review partial and
suppresses pagination-bound cues. For query parameters named `limit`, `page_size`,
`per_page`, `first` or `last`, a direct numeric schema without an explicit upper
bound produces an INFO documentation-review cue. OpenAPI 3.0 boolean and 3.1 numeric
`exclusiveMaximum` forms are distinguished. No maximum threshold or live quota is
enforced or inferred. Missing schema/type, unions and unsupported forms are not
general resource-limit detectors.

Only exact `application/json` request media with a direct inline schema are checked
for selected body cues: explicit array type without `maxItems`, or explicit object
type with `additionalProperties: true`. These do not prove batching abuse, resource
exhaustion or mass assignment. Flexible input can be intentional. Missing
`additionalProperties` is not assigned a security verdict. Boolean, referenced,
conditional and selected composed schemas are left unevaluated.

### References, limits and incomplete coverage

No `$ref`, `$dynamicRef` or `$recursiveRef` target is opened, including local paths,
file URLs and fragment references. Path items containing `$ref` are skipped in full,
including inline siblings, and skipped counts remain visible. Request-body/schema
references and compositions retain unresolved/not-evaluated status. Reference-marker
counts are syntax counts, not a resolved graph. Non-string reference-marker values
are rejected by this selected reader, even in otherwise unreviewed content.

Each input is at most 1 MiB, 20,000 JSON values and depth 40. Duplicate keys and
non-finite numbers are rejected with contents withheld. Native limits are 200 path
entries, 500 inline operations, 50 scheme definitions, 20 security alternatives,
20 schemes per alternative, 50 scope strings per scheme, 100 parameters per layer,
20 servers per layer and 20 request content entries. Selected `maxItems` values
must be integers in 0..1,000,000,000. Unsupported/invalid selected shapes fail
without exporting their values. Unselected content is not fully validated.

## Reports, authorization and tests

Inputs must be approved local regular files and require explicit authorization.
The flag is an operator attestation, not independently verified owner consent.
Outputs use the existing private/create-only writer; approved parents must exist,
and existing reports are never overwritten. On Windows use an access-controlled
private case directory. Secure input permissions yourself.

Reports retain UTC time, exact input SHA-256, receipt-derived case IDs, HTTP methods,
path hashes, selected declaration states, unresolved/skipped counts and remediation.
Paths, operation IDs, scheme/scope names, server URLs, parameter names and examples
are withheld. Hashes are correlatable and do not provide anonymity or prove
authenticity. Privately map operation indices/hashes to original source. Native
source-line coordinates are not claimed; SARIF uses external-evidence placeholders.
At most 500 findings are retained; truncation and dropped counts remain explicit.
Runtime, authorization and business-logic verification flags remain false.

```bash
hunterqa report-sarif \
  --file "$HOME/hunterqa-cases/api/contract-review.json" \
  --out "$HOME/hunterqa-cases/api/contract-review.sarif"
```

Tests use owned synthetic specifications and observations, including inheritance,
alternative/conjunctive requirements, overrides, unresolved references, privacy,
malformed shapes, bounds and positive/negative controls. They do not establish
real-world vulnerability detection rates or complete OWASP/API standards coverage.

## Primary references and next category

- [OpenAPI 3.0.4](https://spec.openapis.org/oas/v3.0.4.html)
- [OpenAPI 3.1.1](https://spec.openapis.org/oas/v3.1.1.html)

**Next requested category: Containers & Kubernetes.** It is not delivered here.
