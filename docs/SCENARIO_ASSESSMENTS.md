# Local scenario assessments

This expansion adds reviewed application interactions, bounded canary checks,
service observations and normalized permission models. It preserves existing
scans and reports. Tests use owned loopback services and synthetic identities;
they do not require real cloud accounts or an enterprise directory.

## 1. Run the repeatable lab

Use the installed shared Linux runtime, or install the optional dependencies in
your development environment:

```bash
python -m pip install -e '.[identity,browser]'
python -m playwright install chromium
umask 077
mkdir -m 700 "$HOME/hunterqa-scenario-labs"
mkdir -m 700 "$HOME/.hunterqa-assessment-secrets"
export HUNTERQA_APPROVED_ROOTS="$HOME/hunterqa-scenario-labs"
export HUNTERQA_ASSESSMENT_SECRET_ROOT="$HOME/.hunterqa-assessment-secrets"
hunterqa expansion-benchmark \
  --out-dir "$HOME/hunterqa-scenario-labs/run-1" --browser --authorized
```

Use new directories or existing private directories you own; choose a new output
directory for each run. Browser installation needs connectivity once. Installed
fixtures run offline. On Windows use the same steps inside WSL2. For Compose or
systemd, run with the installed assessment identity and its approved paths; see
the [deployment guide](LINUX_DEPLOYMENT.md).

The full lab produces **20 checks**; omit `--browser` for 15. Inspect
`run-1/benchmark.json` and individual `*-report.json` files. `all_cases_matched`
must be true and `uploads_remaining` zero. Each check records its report filename
and SHA-256 of the saved file bytes. The lab starts temporary numeric loopback
servers and closes them on exit. Saved plans contain temporary ports
and expire: repeat the benchmark to generate fresh plans rather than replaying
old lab URLs. Encrypted synthetic session files remain in the private secret
directory; retain or remove that run's files according to your evidence policy.

| Check | What actually runs | What it does not establish |
| --- | --- | --- |
| SQL boolean contexts | HTTP against intentionally vulnerable in-memory SQLite, with a parameterized negative control | General SQLi coverage or production database impact |
| SQL timing | A synthetic one-second server delay measured over HTTP | SQL execution; the result is a timing signal only |
| XSS contexts | Chromium execution markers in HTML, quoted attributes and DOM fragments, with repeat/control requests | Stored XSS or all browser/framework contexts |
| SSRF callback | An owned backend makes an actual request to a separate owned collector | Arbitrary internal reachability or blind data extraction |
| Upload | Upload, fetch and deletion of an inert `.txt` canary | Executable upload or arbitrary file access |
| Workflow/session | Owner, other-user and anonymous contracts; named-actor cookie continuity | Automatically discovered business rules or all tenant boundaries |
| Browser journey | Reviewed fill/click/assert actions, imported cookies/local storage, a dynamically created link | General autonomous crawling or automatic SSO login |
| SMTP/FTP/Redis | Actual loopback TCP greetings or fixed PING | Verified product/version, OS or vulnerability |
| AD/AWS/Azure/GCP | Four synthetic normalized permission graphs evaluated offline | Live collection, native effective IAM/AD access or executed privilege paths |

Additional automated tests cover SSH/HTTP response observations, escaped XSS
and owner CSP controls, contract rejection, stop/quota/deadline enforcement,
vault expiry, evidence integrity and protected dashboard history. The benchmark
is a reproducible acceptance fixture, not an independent effectiveness study.

## 2. Scope and approval

`scenario-preflight` accepts an existing bounty scope profile and a scenario
plan. Both files must be under `HUNTERQA_APPROVED_ROOTS`. The profile's
`scenario_methods` defaults to `["GET"]`; adding POST requires explicit
`["GET", "POST"]`. The original bounty engine remains GET/HEAD only.

A plan has these exact top-level fields:

```json
{
  "schema_version": 1,
  "authorization_reference": "The exact reference from the scope profile",
  "expires_at": "REPLACE_WITH_A_FUTURE_UTC_TIMESTAMP_WITHIN_24_HOURS",
  "timeout_seconds": 120,
  "max_requests": 20,
  "browser_isolated": true,
  "cases": []
}
```

This is a schema illustration, not a runnable plan. Use the generated lab plans
to inspect complete cases. Supply 1–10 cases and a total reservation of at most
40 requests. Every case requires a unique ID and `owned_test_endpoint: true`.
Supported kinds: `workflow`, `browser-journey`, `sqli-boolean`, `sqli-timing`,
`xss-context`, `ssrf-callback` and `upload-canary`.

1. Review all URLs, methods, actions, actors, positive response hashes and limits.
2. Run `hunterqa scenario-preflight --profile /absolute/scope.json --plan /absolute/plan.json`.
3. Supply its exact `approval_sha256` to `scenario-run`, with the same inputs,
   `--approval SHA --out /absolute/new-report.json --authorized`.
4. Add `--session-file /private/vault.json --session-key /private/session.key`
   to **both** commands when named actors are used.
5. Create a file named `stop` beside the plan to stop before the next operation.
   `--stop-file` accepts another simple basename. A configured shared host-local
   [quota ledger](NATIVE_SHARED_QUOTAS.md) is also enforced.

Approval binds source files, encrypted session/key, runtime and quota settings.
Changes or expiry invalidate it. HTTP uses pinned destinations, no proxies,
redirects or retries, 1 MB response and 8 KB body limits, rate limits and a
combined I/O deadline. DNS resolution still depends on the operating system's
resolver timeout. Cancellation cannot retract an already sent request.

Workflow steps declare URL, GET/POST, actor, optional query/form, expected status
and optional response SHA-256. Positive 200/201 contracts require a body hash.
Browser journeys declare exact allowed URL/method/query-key rules and reviewed
CSS selectors for fill, select, check, click, text and count assertions. They
hash discovered links without automatically following unreviewed routes.

Browser execution requires an isolated test environment: ephemeral contexts,
blocked downloads/service workers, restricted requests, websockets/popups and
credential-stripped child environments supplement an OS network boundary.
`browser_isolated` is an operator declaration, not an installed firewall.
Preserve the target's CSP. Never interpret routing interception as complete
browser isolation.

SQL probes use public owner-installed markers and fixed controls; timing probes
require an explicitly owned single-row fixture. SSRF requires a separate scoped
collector with a fresh nonce. Uploads use inert text with cleanup verification.
On timeout or stop, no further cleanup request is sent; retain `canary_id` and
remove any remaining fixture manually. Reports never auto-confirm customer
vulnerabilities.

## 3. Private target sessions and SSO reuse

The target-session vault is separate from dashboard sign-in. An operator can
import a short-lived dedicated target test session after completing its login,
including SSO, manually. The tool does not negotiate arbitrary target federation,
export identity-provider state or bypass MFA.

`HUNTERQA_ASSESSMENT_SECRET_ROOT` must name a private existing absolute directory
outside Git, approved assessment/source roots and the operator control root.
Use 0700 directories and 0600 files on Linux. Create a vault using:

```bash
hunterqa assessment-session-create \
  --out "$HUNTERQA_ASSESSMENT_SECRET_ROOT/target.json" \
  --key-file "$HUNTERQA_ASSESSMENT_SECRET_ROOT/target.key" --authorized
```

Provide JSON through stdin using your private local secret-management workflow.
Do not paste real credentials into chat, shell history or shared reports. Input
schema: `schema_version: 1`, `expires_at` within 24 hours, and `actors`, keyed
by 1–10 short actor IDs. Each actor contains exactly `origin`, `headers`,
`cookies`, `local_storage`. Headers allow Authorization, Cookie and X-* only;
cookies declare name, value, httpOnly, secure and sameSite. See the public
synthetic example generated by `scenario_lab.sessions` in
[the lab source](../hunterqa/scenario_lab.py).

Actor state is encrypted with a separate private 256-bit key and checked again
before requests. Credentials stay bound to one exact application origin.
Native HTTP named actors keep bounded origin/path cookies; `anonymous` remains
stateless. A browser journey uses its own ephemeral cookie context. Evidence
contains actor labels, response/target hashes and bounded timing/status fields,
not raw credentials or response bodies. Lost vault keys require recreating the
session; expiry is checked at run time.

## 4. AD, cloud and service observations

`access-graph-review --input /absolute/model.json --out /absolute/report.json --authorized`
evaluates an explicit `active-directory`, `aws`, `azure` or `gcp` normalized model. Generated
`*-model.json` files show the exact schema. Principals/resources have tenant
labels; memberships and grants carry source hashes. Exact actions, explicit
allow/deny and satisfied/unsatisfied/unknown conditions produce model results.
Missing grants remain `not-granted-in-snapshot`; unknown conditions remain
unknown. Disabled identities are denied. Candidate control paths are bounded,
hashed and never executed.

This model is deliberately narrower than Windows ACE ordering, AD CS/trusts,
AWS SCP/resource policies, Azure inheritance or GCP conditional IAM. A source
hash links supplied evidence; it does not establish its authenticity. Real
read-only collection remains separately configured: existing
[AWS/cloud readers](CLOUD_REVIEW.md), [Azure inventory](SCOPED_AZURE_INVENTORY.md),
[GCP inventory](SCOPED_GCP_INVENTORY.md) and
[GCP permission queries](SCOPED_GCP_PERMISSIONS.md) retain their limits. No new
live LDAP collector or comprehensive multi-cloud effective-access engine is
claimed. Later real integrations require exact approved resources, minimum
read-only grants and private local credentials, followed by real-provider tests.

`service-fingerprint --input /absolute/contract.json --out /absolute/report.json --authorized`
uses one numeric endpoint, authorization reference, expiry and private-network
acknowledgment. Protocols: SSH, SMTP, FTP, Redis and HTTP. Only a greeting, fixed
PING or fixed HEAD is exchanged; no authentication or exploitation occurs.
Product and OS strings are advertised hints, not verified identification. The
existing exact TCP, TLS and UDP DNS tools remain available.

## 5. Dashboard history and evidence links

For `scenario-run`, `access-graph-review`, `service-fingerprint` and
`assessment-correlate`, add:

```text
--workspace-config /private/control/workspace.json --project-id 1
```

Choose an existing project in that workspace and a new output under its
`assessments` directory. Keep input profiles, plans and models under that root
as well; copy a reviewed lab model there before associating it with a project.
Session vaults and keys remain outside it and outside workspace backups; recreate
short-lived target sessions after recovery. Run as the trusted local assessment identity. Open
**Scenario results** in the signed-in dashboard to see completed CLI evidence
and project links. The view verifies saved report SHA-256 and shows allowlisted
summaries. A changed report becomes unavailable. Existing scans/reports are
preserved; this is completed-run history, not an asynchronous scenario queue or
a new HTTP endpoint for starting scans. Existing workspace/operator boundaries
and backup/recovery continue to apply.

`assessment-correlate --input /absolute/one.json --input /absolute/two.json --out /absolute/index.json --authorized`
links matching digests across 2–10 saved reports. A match means equal recorded
bytes, not proven provenance, effective permission or a confirmed vulnerability.

## 6. Troubleshooting and remaining acceptance

| Symptom | Check |
| --- | --- |
| Secret root rejected | Separate it from source/approved/control roots; check ownership, permissions and links |
| Approval rejected | Regenerate after any scope, session, runtime or quota change |
| No browser executable | Install Chromium for the same runtime identity or use the shared deployment runtime |
| Inconclusive/ stopped | Inspect error type, deadline, rate/HTTP response, stop file, expiry and quota ledger |
| No dashboard row | Run the CLI with workspace configuration/project association and a permitted output path |
| Old lab plan fails | Its temporary server has stopped or authorization expired; start a fresh benchmark |

The repository's tests and Linux deployment jobs exercise owned fixtures.
Real Google/Entra dashboard authentication and WSL2/Desktop acceptance remain
owner-run checks. General target SSO, representative business logic, live AD,
complete cloud inventory/effective access and independent detection-rate
evaluation remain unverified. See [expansion progress](EXPANSION_PROGRESS.md)
and [the local runtime handoff](LOCAL_RELEASE_HANDOFF.md).
