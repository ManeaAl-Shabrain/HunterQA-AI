# Controlled workflow runner: local platform baseline

The 1.3.0 source turns the protocol compiler into an operational local
workflow system. It provides a baseline for all ten platform priorities below.
It is not a distributed service, an independently authenticated authorization
system, a general exploit executor, or an operating-system sandbox.

## Delivered capabilities and boundaries

| Priority | Delivered | Boundary |
| --- | --- | --- |
| Persistent engine | SQLite run/step state, staged dependency scheduling, exclusive OS coordinator lock, create-only run IDs/directories | No automatic retry or replay; interrupted work requires a new separately reviewed run |
| Runtime controls | Per-run request reservations, concurrency ceiling, serialized network workers, minimum request spacing, supervised deadlines, stop file, expiry/change checks | Different run directories have independent quotas; no organization-wide quota service |
| Modular tools | Seven fixed code adapters with versioned worker output, strict bindings, isolated Python invocation, minimal environment | No arbitrary executable, command, downloaded plugin, or model-selected tool; external binaries need separately reviewed adapters and stronger isolation |
| Approval | Profile and protocol fingerprints, exact execution/bindings fingerprint, explicit checkpoint IDs and operator attestation | Filesystem owner is trusted; no verified customer identity, SSO, RBAC or signed owner grant |
| Assets/services | Exact declared URL/host/port inventory, scoped service-evidence import, bounded live HTTP status observations | Declaration/import is not discovery proof; no crawling, automatic port scanning or admission of discovered assets |
| Findings/evidence | Stable candidate IDs, deduplication, linked result hashes, request journals, manual review states, evidence fingerprints, generic CWE remediation | Scanner severity and analyst decisions remain assertions; no proof of novelty or automatic CVE assignment |
| Retesting | Comparison of two separately executed runs with identical scope/project bindings; missing findings become not-observed or unknown | Absence does not prove a fix; line changes can change IDs; historical reviews do not transfer |
| Reports | Automatic JSON summary, printable escaped HTML and conservative SARIF; explicit export after review | PDF uses browser Print; there is no native PDF backend or external upload |
| Management view | Local `/workflows` shows recorded state, charged quota, steps, selected coverage and triage | Read-only, administrator-selected run; start/stop/review remain CLI operations |
| Quality lab | Original positive/negative fixture benchmark and execution-boundary regression tests, including real supervised processes and owned-loopback HTTP | Three CLI benchmark fixtures do not establish real-world accuracy; Linux CI also exercises the mobile page in Chromium |

Evidence-linked `next_actions` provide review/remediation suggestions tied to
candidate IDs and result hashes. These are deterministic recommendations, not a
new autonomous AI agent. Existing optional local-AI research commands remain
separate. Coverage reports show selected versus completed stages; zero selected
means untested. They do not claim ASVS/WSTG compliance or comprehensive coverage.

## Adapter contracts

`workflow-tools` distinguishes runnable adapters from planning-only declarations.

| ID | Binding fields | Execution |
| --- | --- | --- |
| `declared-assets` | `{}` | Inventory explicitly declared targets; no network |
| `service-evidence` | `file` | Import bounded service assertions; no network |
| `source-review` | `project` | Existing local configuration and JSON OpenAPI checks plus declared dependency inventory; target source is never imported, built or run |
| `external-findings` | `file`, `tool` (`nuclei` or `zap`) | Existing offline importer, narrowed again to exact step targets; scanners are not installed/launched |
| `approved-observation` | `{}` | Fixed HEAD, or GET if HEAD is not permitted; exact step URLs only |
| `evidence-index` | `{}` | Link successful dependency-result fingerprints |
| `report-draft` | `{}` | Collect dependency-result references for final reporting |
| `approved-account-check` | unavailable | Planning-only; the runner rejects the entire workflow before starting. Existing dedicated-account `engagement-run` remains separate |

`source-review` does not run Semgrep inside a worker. Existing source Action,
campaign, Semgrep, browser, crash/fuzz and dedicated-account workflows retain
their existing command-specific controls. They have not all become supervised
workflow adapters in this increment.

Bindings use a separate strict JSON file:

```json
{
  "schema_version": 1,
  "steps": {
    "assets": {},
    "identify": {"project": "/srv/assessments/customer/source"},
    "evidence": {},
    "report": {}
  }
}
```

Every step must have exactly one binding object with the expected fields. Input
files must be in approved local roots and are capped at 2 MB each, 16 MB total.
Their exact bytes are fingerprinted at review and copied into the private run
directory before execution. A changed file requires another execution review.
The execution fingerprint also binds the installed distribution version, Python runtime identifier and trusted
package Python-source fingerprints; changes are checked before dispatch. This
is provenance checking, not code signing or independent software attestation.
Project bindings approve a **mutable local directory**, not an immutable source
snapshot. Its findings are candidate observations, not attested source proofs.

Service evidence format is exactly:

```json
{"services": [{"url": "https://approved.example/app", "service": "https"}]}
```

At most 500 entries; service is `http` or `https` and URL must exactly match a
declared step target. Imported assertions are not live verification. Nuclei and
ZAP input formats/limits remain as documented in `RESEARCH_WORKFLOWS.md`.

## Linux quick start

Install the reviewed 1.3.0 source normally. Use an existing authorized scope
profile and an approved parent directory with a narrow `source` subdirectory.
Keep configuration and run directories outside the reviewed source tree.
The source archive builder normalizes shell-script CRLF to LF for Linux and
hashes the actual packaged bytes; it does not alter working files or old releases.

```bash
export HUNTERQA_APPROVED_ROOTS="/srv/assessments/customer"

hunterqa workflow-setup \
  --profile "$HUNTERQA_APPROVED_ROOTS/profile.json" \
  --project "$HUNTERQA_APPROVED_ROOTS/source" \
  --target "https://approved.example/app" \
  --out-dir "$HUNTERQA_APPROVED_ROOTS/plan-001" --authorized
```

This generates a four-stage offline starter: declared assets, local review,
evidence indexing and reporting. Add `--observe` only when your written scope
permits a bounded HEAD/GET check; it adds a mandatory `validate` checkpoint.
It does not add credentials, active payloads or arbitrary test sequences.
The generated configuration has a one-hour window and conservative reservations.

Review the full protocol and bindings. After edits, create a fresh execution
plan output and inspect its fingerprints, paths, budgets and pending checkpoints:

```bash
hunterqa workflow-run-plan \
  --profile "$HUNTERQA_APPROVED_ROOTS/profile.json" \
  --protocol "$HUNTERQA_APPROVED_ROOTS/plan-001/protocol.json" \
  --bindings "$HUNTERQA_APPROVED_ROOTS/plan-001/bindings.json" \
  --out "$HUNTERQA_APPROVED_ROOTS/review-001.json"
```

For an offline protocol with no checkpoints:

```bash
hunterqa workflow-run \
  --profile "$HUNTERQA_APPROVED_ROOTS/profile.json" \
  --protocol "$HUNTERQA_APPROVED_ROOTS/plan-001/protocol.json" \
  --bindings "$HUNTERQA_APPROVED_ROOTS/plan-001/bindings.json" \
  --approve-execution EXACT_EXECUTION_SHA256 \
  --out-dir "$HUNTERQA_APPROVED_ROOTS/run-001" \
  --operator "Your operator reference" --authorized
```

If the protocol has `validate` or other checkpoints, also pass
`--approve-protocol EXACT_PROTOCOL_SHA256 --approve-step validate`; repeat the
step option for each required checkpoint. Every checkpoint must be reviewed,
including optional checkpoints explicitly requested for offline steps. These
flags are local attestations, not a means to verify a company's approval.

## Supervision and quotas

All steps are validated before a run directory or worker is created. Scheduling
uses the compiler's stage barriers and bounded dependency batches. Failed
dependencies block their dependents. Independent branches may continue after
an offline failure. Network safety responses or a network-worker failure stop
the whole run. No automatic retries, redirects or environmental proxies exist.
The pinned transport reuses existing DNS address checks and TLS verification.

Each network step's declared request reservation is durably charged **before**
launch. Unused reservations are never refunded, including after cancellation,
transport failure or coordinator death. The worker can request at most one
operation per declared target. Within a network worker, calls are sequential
and spaced by at least the protocol interval. Network workers are serialized;
the next waits at least one interval after the previous worker completes.
Offline workers share the total concurrency ceiling. Quotas are per run.

The coordinator supervises the worker process, not only its network timeout.
Workers also check parent-process death, the stop file, expiry and their own
deadline. Linux workers additionally cap CPU, address space (512 MiB) and file
descriptors (128), respecting lower existing hard limits. Those OS resource
caps are not implemented on Windows. Fixed workers cannot launch tool children.
There is no container, filesystem jail or OS-enforced network namespace.

```bash
hunterqa workflow-status --run "$HUNTERQA_APPROVED_ROOTS/run-001"
hunterqa workflow-stop --run "$HUNTERQA_APPROVED_ROOTS/run-001"
```

Changing or removing the source profile/protocol interrupts or cancels remaining
work. An already sent request cannot be recalled or rolled back. Deadlines cover
worker execution; bounded preparation and report serialization occur separately.

After an actual coordinator crash, its OS lock releases. Surviving fixed workers
stop through their independent watchdog. Reconcile the recorded run with:

```bash
hunterqa workflow-abandon --run "$HUNTERQA_APPROVED_ROOTS/run-001" --authorized
```

This refuses a held coordinator/reviewer lock, marks unfinished steps cancelled,
keeps charged quota, and never executes a request. A new run needs a new directory
and another explicit invocation/review. A recorded `running` state is not proof
that a coordinator is alive. Partial worker files can remain after a crash and
must not be promoted to completed evidence automatically.

## Evidence, review and reports

The run directory contains the protocol/profile snapshot, copied evidence input,
worker requests/results, network journals, SQLite events, JSON summary, HTML and
SARIF. On POSIX, directory/file creation uses 0700/0600; Windows confidentiality
depends on the parent directory's ACL. Copied scanner inputs can contain secrets
or sensitive responses: retain the complete directory in your approved private
evidence store and apply your organization's retention rules. Reports omit raw
source excerpts, HTTP bodies, credentials and free-text scanner payload fields;
operator-written review notes are not automatically secret-redacted.

Network journals fsync request intents before the transport call and record
response status or error type after it. An intent does not prove a packet was
sent or received. Worker death can leave an intent without an outcome, or an
incomplete final line. Complete record prefixes and raw-file fingerprints remain
available; a finished coordinator anchors their digest/counts in its event log.
An abruptly killed coordinator can leave unanchored partial journals for manual
forensic review. Request reservations remain charged regardless.

Result artifacts, review records, status/quota and event-chain consistency are
checked on reads. Hashes are not signatures and cannot stop a directory owner
from rewriting the entire history. The coordinator writes durable events for
dispatch state, quota, network evidence, completion/cancellation and reviews.
Standard output/error of workers is suppressed to avoid copying raw exceptions
or captured data into reports; worker exits are recorded as bounded error types.

```bash
hunterqa workflow-review --run /srv/assessments/customer/run-001 \
  --finding EXACT_CANDIDATE_ID --decision needs-review \
  --reviewer "Analyst reference" --note "Impact needs independent verification" \
  --evidence /srv/assessments/customer/private-proof.txt --authorized

hunterqa workflow-export --run /srv/assessments/customer/run-001 \
  --format html --out /srv/assessments/customer/reviewed-report.html

hunterqa workflow-compare --first /srv/assessments/customer/run-001 \
  --second /srv/assessments/customer/run-002 \
  --out /srv/assessments/customer/retest.json
```

Review decisions are `confirmed`, `false-positive`, or `needs-review`; each is an
analyst attestation with a reviewer reference, note, evidence hash and time.
SARIF intentionally keeps the existing conservative unverified export contract,
even after a local review. JSON/HTML distinguish review state from source severity.
For runs with multiple source projects, ambiguous repository-relative SARIF
locations are omitted and project fingerprints distinguish candidates.
Automatic run reports are snapshots; export again after review to include changes.

Set `HUNTERQA_WORKFLOW_RUN` to the complete run directory before starting the
local dashboard. `/workflows` reads only that configured directory and accepts
no URL-supplied file paths or execution requests. It uses the existing loopback,
Host, CSP and escaping protections. Refresh the page to see current records.

## Quality and next integration work

```bash
hunterqa workflow-benchmark --out /srv/assessments/customer/fixture-results.json
python -m pytest -q tests/test_workflow_protocol.py tests/test_workflow_runner.py
```

The benchmark covers three original Docker configuration fixtures. The regression
suite exercises real workers, timeouts, stop/cancellation, scope review, profile
changes, import snapshots, integrity checks, retesting, Linux/Windows coordinator
locks, an independent worker watchdog, owned-loopback HTTP spacing, and the
read-only mobile dashboard in an opt-in Chromium test. No public target is tested.

Before adding external scanners, browser workers, authenticated validation,
distributed workers or a multi-user UI, implement and test their specific
isolation/egress contract, process-tree cancellation, secret delivery and
revocation, authenticated identities and owner-grant verification, shared
organization quotas and deployment-specific retention. These are outstanding
production integrations, not capabilities hidden behind an approval flag.
