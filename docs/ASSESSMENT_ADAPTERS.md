# Assessment adapters and shared quotas

**Unreleased development after v1.3.0.** These additions extend the local workflow
runner. They do not complete all seven assessment areas. Run `hunterqa coverage-audit`
for the explicit implementation inventory and [remaining gaps](ASSESSMENT_EXPANSION_ROADMAP.md).

All setup below is offline. Actual traffic requires a written agreement, a private
scope profile, the reviewed execution and protocol fingerprints, an explicit
`assess` checkpoint, and `--authorized`. Local attestations do not verify ownership.

## 1. Prepare a private case directory

Follow the [beginner guide](AUTHORIZED_ASSESSMENT_BEGINNER_GUIDE.md) and copy the
[scope template](../templates/HunterQA-scope-template.json). Set the exact hosts,
ports, paths, exclusions, permitted GET discovery/checks, budget and interval.
Use HTTPS remotely. HTTP/private addresses require explicit owned-lab settings.
GET requests can have side effects; exclude destructive application routes.

```bash
export HUNTERQA_APPROVED_ROOTS=/srv/assessments/customer
```

Keep filled manifests, credentials, ledger, approvals and evidence outside this
public repository. Examples use documentation-only hostnames. Do not paste secrets
into chat, command arguments, issue comments or reports.

## 2. Choose an adapter

| Adapter | What it does | Boundary |
| --- | --- | --- |
| `web-canary-check` | Baseline/probe GET pairs for inert HTML reflection and quote-related SQL error cues | No script execution, extraction, blind/OOB tests, SSRF, uploads or traversal; findings are unverified |
| `authorization-matrix` | Exact role/resource GET contracts with dedicated Bearer/Basic credentials or anonymous access | No SSO negotiation, cookies, automatic account discovery, session refresh or stateful business workflows |
| `service-enumeration` | One pinned TCP connect attempt for each exact profile-admitted URL host/port | No port ranges, subnet discovery, banners, TLS/OS fingerprinting, UDP or AD assessment |
| `aws-account-audit` | Fixed STS identity check followed by IAM account-summary counters | AWS commercial partition only; no resources, policy simulation, mutations, role assumption or other providers |

Each adapter uses the supervised runner, profile-bound approval, per-run quota,
request interval, deadline, private journals and emergency stop. Schema validation
rejects extra fields. Network steps remain serialized within one coordinator.

### Web canary manifest

Save this non-secret file as `canaries.json` in your private case directory:

```json
{
  "schema_version": 1,
  "checks": [
    {"id": "search-markup", "kind": "markup-reflection", "url": "https://approved.example.test/app/search", "parameter": "q"},
    {"id": "search-sql", "kind": "sql-error", "url": "https://approved.example.test/app/search", "parameter": "q"}
  ]
}
```

```bash
hunterqa assessment-setup --tool web-canary-check \
  --profile /srv/assessments/customer/scope.json \
  --input /srv/assessments/customer/canaries.json \
  --out-dir /srv/assessments/customer/canary-config --authorized
```

Select 1–10 checks, each with two requests and one reviewed query parameter. Setup
shows the generated baseline/probe query values in `review.request_contracts`;
they are bound into the approval. The fixed markup is an inert custom element;
the SQL probe adds a single quote to a canary marker. There is no user-supplied
payload engine. Legacy observation/discovery commands still reject query URLs.
Only this adapter adds its reviewed query parameter to an admitted base URL.

The journal binds the method, base URL and query fingerprint. Reports retain
status/body hashes and case IDs, not response bodies. A markup cue does not prove
XSS, and a new database error does not prove SQL injection. Baseline errors are
not counted as new SQL cues. Denials, redirects, 429 and 5xx stop further requests;
a SQL error cue can be retained before a 5xx safety stop. Inspect execution state
before interpreting coverage.

### Authorization matrix

Save `access-matrix.json`:

```json
{
  "schema_version": 1,
  "roles": {
    "owner": {"origin": "https://approved.example.test/app", "authenticated": true},
    "other-user": {"origin": "https://approved.example.test/app", "authenticated": true},
    "anonymous": {"origin": "https://approved.example.test/app", "authenticated": false}
  },
  "cases": [
    {"id":"owner-object","role":"owner","url":"https://approved.example.test/app/objects/OWNED_TEST_OBJECT","expect":"allow","statuses":[200],"body_sha256":null},
    {"id":"other-user-object","role":"other-user","url":"https://approved.example.test/app/objects/OWNED_TEST_OBJECT","expect":"deny","statuses":[403,404],"body_sha256":null},
    {"id":"anonymous-object","role":"anonymous","url":"https://approved.example.test/app/objects/OWNED_TEST_OBJECT","expect":"deny","statuses":[401,403,404],"body_sha256":null}
  ]
}
```

Create a separate private `test-credentials.json`. Its keys must be exactly the
authenticated roles; anonymous roles have no entry:

```json
{"owner":"Bearer REPLACE_WITH_DEDICATED_OWNER_TEST_TOKEN","other-user":"Bearer REPLACE_WITH_DEDICATED_OTHER_TEST_TOKEN"}
```

```bash
hunterqa assessment-setup --tool authorization-matrix \
  --profile /srv/assessments/customer/scope.json \
  --input /srv/assessments/customer/access-matrix.json \
  --credentials /srv/assessments/customer/test-credentials.json \
  --out-dir /srv/assessments/customer/access-config --authorized
```

Use 1–8 roles and 1–40 exact cases. Credentials are isolated per request and may
only go to the role's declared origin. An allow contract accepts selected 2xx
statuses; a deny contract accepts selected 401/403/404 statuses. An optional exact
body SHA-256 strengthens content comparison. A status-only match does not prove
correct authorization, account identity or tenant isolation.

Expected deny responses allow the remaining matrix cases to run. An unexpected
401/403 in an allow case, redirect, 429 or 5xx stops follow-up work. A deny case
returning 2xx becomes an unverified access-control candidate. Other mismatches
remain visible in case observations and need analyst review.

Credential bytes are hashed during planning and rechecked before each role
request; rotation requires fresh review. Credential files remain at their original
private location and are **not copied into run artifacts**. Reports retain case
labels and body hashes. No cookie jar or ambient credentials are used. Protect the
original credential file with OS permissions; the local filesystem owner remains
trusted. Use dedicated, short-lived test accounts and revoke them after assessment.

### Exact service enumeration

```bash
hunterqa assessment-setup --tool service-enumeration \
  --profile /srv/assessments/customer/scope.json \
  --target https://approved.example.test:443/app \
  --out-dir /srv/assessments/customer/service-config --authorized
```

Repeat `--target` only for explicitly approved host/ports. The profile must admit
each exact host and port using its URL scope model. The adapter makes a TCP connect,
not an HTTP request; URL paths are scope declarations, not TCP isolation boundaries.
Allowing a host/port permits a connection to that service irrespective of path.
There is no application request, credential use or banner read. Outcomes are
`connected`, `refused`, `timeout`, or `unreachable`, with a three-second socket
timeout plus the independent worker deadline. DNS answers are validated and one
address is pinned; this does not inventory every address behind a hostname.
An open TCP port is not a vulnerability. Journals distinguish connection outcomes
from HTTP responses. Scope/request limits still apply, up to the profile's 40-target
ceiling. OS, AD and internal attack paths remain untested.

### Read-only AWS account summary

Install the optional signer/parser dependencies:

```bash
python -m pip install -e '.[cloud]'
```

Create a dedicated scope profile allowing only `sts.amazonaws.com` and
`iam.amazonaws.com`, HTTPS port 443, path `/`, GET scope admission, two requests,
and the agreed interval. This adapter uses two **fixed read-only Query APIs over
POST**; it does not enable arbitrary POST requests or SDK operations.

The non-secret account manifest is:

```json
{"schema_version":1,"account_id":"REPLACE_WITH_AUTHORIZED_12_DIGIT_ACCOUNT"}
```

The separate private credential file contains `access_key_id`, `secret_access_key`,
`session_token`, and ISO-8601 UTC `expires_at`. Only explicit temporary ASIA session
credentials expiring within 24 hours are accepted; no environment/config discovery,
instance metadata or automatic role assumption occurs. The dedicated role needs
`iam:GetAccountSummary`. Obtain credentials through your organization's approved
process; do not use root credentials.

```bash
hunterqa assessment-setup --tool aws-account-audit \
  --profile /srv/assessments/customer/aws-scope.json \
  --input /srv/assessments/customer/aws-account.json \
  --credentials /srv/assessments/customer/aws-session.json \
  --out-dir /srv/assessments/customer/aws-config --authorized
```

The first call, [GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html),
must match the reviewed account ID before
[GetAccountSummary](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html)
is called. The SDK signs only; HunterQA's pinned, TLS-verified transport sends the
requests without redirects, retries or proxies. Only selected numeric counters
and hashed account/principal references enter reports. Root-key and root-MFA
conditions are review cues; no per-user or effective-permission conclusion is
inferred. A missing root password is not automatically classified as missing MFA.
Account matching verifies credential context, not target-owner authorization.
Tests use synthetic API contracts; no real AWS account has been used to validate
this implementation. Validate first in an explicitly authorized sandbox account.

## 3. Review, approve, run and stop

Read the input, scope, generated protocol/bindings and `execution-plan.json`.
Replace `CONFIG` and fingerprint placeholders with your actual reviewed values:

```bash
hunterqa workflow-run --profile /srv/assessments/customer/scope.json \
  --protocol /srv/assessments/customer/CONFIG/protocol.json \
  --bindings /srv/assessments/customer/CONFIG/bindings.json \
  --out-dir /srv/assessments/customer/run-001 \
  --approve-execution EXACT_EXECUTION_SHA256 \
  --approve-protocol EXACT_PROTOCOL_SHA256 --approve-step assess \
  --operator "Your assessment operator reference" --authorized

hunterqa workflow-status --run /srv/assessments/customer/run-001
hunterqa workflow-stop --run /srv/assessments/customer/run-001
```

For AWS use the matching AWS scope profile. Regenerate a plan using
`workflow-run-plan` and obtain fresh review after any scope, manifest, credential,
code, dependency or shared-quota configuration change. Retest comparison binds
the access/canary/account manifest; changing expectations is not equivalent coverage.
Interrupted runs are never automatically replayed.

## 4. Share quotas across cooperating local runs

```bash
hunterqa quota-init --ledger /srv/assessments/customer/quota.sqlite3 \
  --max-requests 100 --max-active-runs 2 \
  --expires-at REPLACE_WITH_UTC_TIMESTAMP_WITHIN_24_HOURS --authorized
export HUNTERQA_QUOTA_LEDGER=/srv/assessments/customer/quota.sqlite3
```

Set the variable **before both planning and execution** in every cooperating
coordinator. The path and quota-configuration hash are bound into approval.
Admission atomically reserves the entire run's network budget before creating its
run directory. Requests are not refunded after success, cancellation or failure.
The active-run slot is released after worker termination. SQLite transactions
prevent simultaneous coordinators from overspending this ledger.

```bash
hunterqa quota-status --ledger /srv/assessments/customer/quota.sqlite3
hunterqa quota-stop --ledger /srv/assessments/customer/quota.sqlite3 --authorized
```

Shared stop, expiry, configuration changes or release of an active lease cause
coordinators to stop and terminate workers. A crash leaves its reservation charged
and slot occupied. After independently confirming that its coordinator/workers are
dead, use `quota-reconcile --ledger PATH --run-id RECORDED_RUN_ID --authorized`.
Reconciliation releases the slot, never the charged requests. There is no automatic
replay, refund, renewal or reset; initialize a new ledger for a new approved window.

This is a **host-local, cooperating-coordinator control**, not authenticated
organization-wide enforcement. Processes omitting the setting, other ledgers or
hosts, and privileged filesystem owners are outside its trust boundary. Do not
place the SQLite ledger on an unsupported network filesystem. This adds neither
RBAC, signed owner grants, an OS sandbox nor distributed execution.

## 5. Measure the owned fixture baseline

```bash
hunterqa coverage-audit
hunterqa assessment-benchmark \
  --out-dir /srv/assessments/customer/owned-benchmark-001 --authorized
```

The benchmark starts only an owned `127.0.0.1` application and runs fixed tests.
Eight versioned cases cover raw/escaped/textarea/JSON reflection, an intentionally
concatenated versus parameterized in-memory SQLite SELECT, and broken versus denied
access contracts. It retains ground-truth labels, source/label hashes, private run
evidence, per-class true/false positives and false negatives, precision and recall.
The configured shared ledger also applies to benchmark workflows.

Fixture version `owned-assessment-1.1.0` also runs discovery/form/privacy and exact
open/refused TCP controls. Four retained workflows record 18 network operations.
Use `assessment-readiness --benchmark-dir PRIVATE_PATH --require-owned-lab` to
recompute their evidence without rerunning tests. See the
[readiness guide](READINESS.md) and [marked feature checklist](FEATURE_READINESS_CHECKLIST.md).

These are original, source-controlled labels, not an independently audited or
representative field dataset. Passing this benchmark does **not** establish real-world
detection rates, confirmed vulnerabilities, coverage of other classes, complete
OWASP compliance, or superiority over another tool.
