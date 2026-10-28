# Configurable assessment platform: architecture and first increment

**Historical first-increment specification:** the compiler described here remains
offline. The subsequent [workflow runner](WORKFLOW_RUNNER.md) now implements a
bounded local execution baseline. Its capability table supersedes the future
implementation status in this original architecture/roadmap.

## Delivered now

`workflow-tools` lists a closed catalog of planning adapters.
`workflow-preflight` compiles a JSON testing protocol into deterministic dependency
batches, budget reservations, and review checkpoints. Both commands are offline:
they do not resolve DNS, discover hosts, launch scanners, or run exploit chains.
The report always states `execution_enabled: false`.

This is the first platform increment. It is deliberately separate from existing
`engagement-run` checks: reviewing a workflow does not approve an engagement plan,
start a process, or change the existing scope policy. Development source only;
immutable v1.2.0 release assets are unchanged.

## Architecture

```text
Scope profile + protocol + exact-protocol local step reviews
                       |
                Offline compiler                  IMPLEMENTED
  exact target checks / time window / closed tool catalog
  dependency graph / stage barriers / aggregate reservations
                       |
             Private preflight report              IMPLEMENTED
                       |
      Persistent run coordinator + resource broker FUTURE
         |              |                  |
  offline adapters  scoped network broker   stop/deadline supervisor
         |              |                  |
         +----- bounded adapter workers ----+       FUTURE
                       |
        evidence store -> analyst validation -> report
                 existing components to integrate
```

The configuration describes assessments; it must never become a source of shell
commands, Python imports, downloaded plugins, or model-selected executable paths.
Add a tool through a reviewed code adapter with a fixed argument builder and an
explicit capability contract. External scanner output remains untrusted data.

| Requirement | First increment | Runner work still required |
| --- | --- | --- |
| Explicit targets and lab scope | Every exact URL is checked against the existing profile; each step must use a declared URL | Resolve and pin destinations at execution; enforce private/lab address rules and redirect policy |
| Modular tools | Closed catalog describes eight adapters and their stages | Implement and review each adapter; pin versions and fixed arguments; no arbitrary executable integration |
| Six-stage workflow | Ordered stage barriers plus explicit DAG dependencies | Persist actual results and stop dependent work after failures |
| Approval checkpoints | Active steps require checkpoints; local reviews bind to the canonical protocol hash and exact profile bytes | Verify actual owner grant through the deployment's identity system; use expiring, one-use, step-specific authorization |
| Rate, concurrency and time | Validate aggregate reservations and produce bounded planning batches | Enforce global dispatch intervals, atomic quotas, worker leases, deadlines and cancellation across every worker and retry |
| Emergency stop | Require a simple stop-file name for the eventual run directory | Poll and stop queued work, terminate worker process trees, close transport, and record cancellation |
| Reports and audit | Private create-only preflight contains fingerprints, time, steps, dependencies, budgets and review states | Append durable execution events; link evidence fingerprints; summarize findings, uncertainty, severity and remediation |

No additional exclusions means `excluded_hosts: []` and `excluded_paths: []` in
the scope profile. It never authorizes an undeclared host, port, path or method.
Wildcard targets, IP ranges and implicit discovered-host admission are absent.
Existing profile exclusions remain authoritative when present.

## Protocol schema 1

Unknown fields and duplicate JSON keys fail. Input is limited to 64 KiB. The
required top-level fields are:

| Field | Meaning |
| --- | --- |
| `schema_version` | Integer `1` |
| `policy_sha256` | SHA-256 of the exact scope profile bytes |
| `authorization_reference` | Exact reference from that profile |
| `starts_at`, `expires_at` | Timezone-aware window, at most 24 hours; expiry must be within the next 24 hours |
| `targets` | 1–40 unique exact URLs; no query strings or credentials |
| `limits` | `max_requests`, `interval_seconds`, `concurrency`, `timeout_seconds` |
| `stop_file` | Lowercase basename such as `emergency-stop`, relative to a future private run directory |
| `steps` | 1–64 declarations with the exact fields below |

Each step has `id`, `tool`, `depends_on`, `targets`, `requests`,
`timeout_seconds`, and `approval_required`. IDs are unique lowercase identifiers
up to 48 characters. Dependencies must exist, cannot point backwards across
stages, and cannot form cycles. Even independent graph branches respect global
stage barriers. Within a stage, sorted ready IDs form deterministic batches no
larger than `concurrency`.

Stages are asset discovery → service enumeration → vulnerability identification
→ controlled validation → evidence collection → reporting. A protocol may use a
subset. Dependencies describe ordering, not findings or proof of exploitability.

The current planning catalog is:

| Tool ID | Stage | Network reservation |
| --- | --- | --- |
| `declared-assets` | Asset discovery | 0; declared assets only |
| `service-evidence` | Service enumeration | 0; existing evidence only |
| `source-review` | Vulnerability identification | 0 |
| `external-findings` | Vulnerability identification | 0; existing Nuclei/ZAP import |
| `approved-observation` | Controlled validation | At least one request per target; mandatory checkpoint |
| `approved-account-check` | Controlled validation | At least one request per HTTPS target; mandatory checkpoint |
| `evidence-index` | Evidence collection | 0 |
| `report-draft` | Reporting | 0 |

These are declarations for later adapter integration, not callable workflow
implementations. `workflow-tools` explicitly reports execution unavailable for
every entry. Active declarations must still use separate existing engagement
plans to perform the narrow operations currently supported.

Global requests cannot exceed the profile budget. Interval must be at least the
profile minimum and at most 60 seconds. Concurrency is 1–8; global timeout is
1–3600 seconds and must fit the remaining authorized window. Every step reserves
1–300 seconds. The sum of step timeouts plus request spacing must fit the global
timeout even when concurrency is greater than one. Offline steps reserve zero
requests. These conservative accounting checks do not implement runtime limits.

## Example and review

Set `HUNTERQA_APPROVED_ROOTS` to a private directory containing the profile,
protocol, and new output paths, using the normal platform path separator.
Copy `examples/testing_protocol.example.json` into that directory. Replace its
placeholder profile fingerprint and authorization reference, set a current
timezone-aware window, and replace its fictional target with an exact permitted
URL in both the top-level and step lists. The example is intentionally invalid
until configured. Its scope profile must permit HEAD or GET for the target.

Compute the exact profile hash locally:

```bash
python -c 'import hashlib; print(hashlib.sha256(open("profile.json", "rb").read()).hexdigest())'
```

Inspect and compile:

```bash
hunterqa workflow-tools
hunterqa workflow-preflight --profile profile.json --protocol protocol.json --out preflight.json
```

Review the entire protocol, then record a **local operator attestation** for a
specific checkpoint using `protocol_sha256` from the first preflight:

```bash
hunterqa workflow-preflight --profile profile.json --protocol protocol.json \
  --approve-step validate --approve-protocol EXACT_PROTOCOL_SHA256 \
  --authorized --out reviewed-preflight.json
```

Outputs are create-only private files in an approved local directory. They
include review time, profile/protocol fingerprints, window, resource limits,
dependencies, and checkpoint states. They omit target URLs and do not contain
credentials, request bodies or raw evidence. Retain the exact private protocol
to interpret the fingerprint. A changed protocol invalidates prior reviews; a
changed profile invalidates the protocol. A future start window is reported as
closed. Expired windows fail. No review can enable execution in this increment.

Local hashes and `--authorized` do not authenticate owner consent or prevent
operator fabrication. This CLI is not a multi-user permission service. Existing
research journals can record operator notes, but neither a journal nor a
preflight report is a comprehensive execution audit log.

## Incremental implementation plan

1. **Delivered: protocol compiler.** Strict scope binding, staged DAG planning,
   reservations, local review binding, private preflight CLI and regression tests.
2. **Offline runner.** Add durable run IDs, an exclusive coordinator lease,
   bounded workers for existing local source/evidence adapters, output hashes,
   failure propagation, deadline/stop supervision and restart reconciliation.
   Never resume an active operation merely because a prior event exists.
3. **Bounded network adapters.** Integrate the existing exact-request engagement
   transport behind one shared broker. Consume quotas atomically across workers;
   count login, browser, retries and redirects if supported. Independent worker
   networking is forbidden. Preflight again immediately before every operation.
4. **Specific active validation.** Add only individually specified validation
   adapters, with explicit test-account and state-change constraints, step-bound
   grants, evidence expectations, cleanup plans and dedicated isolated tests.
   An arbitrary shell or exploit-chain executor is not part of this design.
5. **Evidence and reporting.** Preserve scanner-asserted severity separately from
   analyst validation. Link evidence digests, tool/version, step and target to
   each candidate. Include reproducibility, impact, limitations, remediation and
   reviewer decisions. Reuse existing dossier/SARIF exporters; send nothing by
   default. Add tamper-evident event storage with documented trust limits.

Before enabling an adapter, test out-of-scope destinations, DNS changes, budget
races, process-tree cancellation, deadline expiry, partial outputs, revoked
authorization, duplicate execution after restart, and malicious tool output.
Only tests of the actual execution boundary can establish runtime enforcement.
