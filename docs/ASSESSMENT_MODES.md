# Shared assessment modes and provenance

This extends the existing engines, dashboard, project history and SARIF exporter.
It does not replace SAST, API analysis, CVE intelligence, fuzzing, AI research,
the scoped workflow runner or their authorization contracts.

The [370-requirement baseline analysis](PLATFORM_GAP_ANALYSIS.md) was committed
before implementation. Its [machine-readable matrix](PLATFORM_REQUIREMENTS.json)
preserves the original classifications separately from incremental delivery.

## Modes and verification are different

| Label | Meaning |
| --- | --- |
| DEMO | Generated versioned synthetic inputs analyzed locally; never real discoveries |
| LAB | Operator-intended owned laboratory source; imported evidence alone does not prove a lab run |
| LIVE | Operator-intended real source; imported evidence alone does not prove live collection |

Shared reports separately record implementation, verification, collector,
evidence origin, timestamps, hashes and finding references. They never infer
provider verification from a mode selection. Current offline reviews use
`Not Yet Verified` for supplied LAB/LIVE inputs and `Tested with Mocks` for
synthetic demonstrations. Existing local HTTP/SQLite/Chromium/TCP evidence
remains documented separately in [scenario assessments](SCENARIO_ASSESSMENTS.md).

The five verification vocabulary values are Implemented, Tested with Mocks,
Validated in Local Lab, Validated Against Real Provider and Not Yet Verified.
An imported file cannot elevate itself to provider-validated status. Existing
legacy report schemas remain readable; they are not silently reclassified LIVE.

## 1. Try all eight analysis domains offline

Install the normal application first; no identity-provider or cloud account is
needed. Use a new output under an explicitly approved local directory:

```bash
umask 077
mkdir -p "$HOME/hunterqa-assessments"
export HUNTERQA_APPROVED_ROOTS="$HOME/hunterqa-assessments"
hunterqa assessment-modules
hunterqa assessment-demo --module all \
  --out-dir "$HOME/hunterqa-assessments/demo-1" --authorized
```

The demo preserves positive and negative source fixtures and reports for web,
business logic, internal network, AD, cloud, IAM, configuration/vulnerabilities
and evidence correlation. Actual existing analyzers process each fixture; results
are not hardcoded. `demo.json` records per-module controls, report hashes and
precision/recall/false-positive counts for ten selected rule labels. This tiny
original dataset is not an independent or representative accuracy study.
Evidence-link controls are evaluated separately from vulnerability detection.

Generated fixture directories carry a DEMO marker. The shared reviewer rejects
their reuse as LAB/LIVE, along with labeled synthetic reports. This protects
normal workflows from accidental relabeling; it is not cryptographic proof of
the truth of arbitrary operator-supplied files.

## 2. Review your own evidence

```bash
hunterqa assessment-review --module cloud --mode LAB \
  --input /absolute/approved/cloud-evidence.json \
  --out /absolute/approved/new-review.json --authorized
```

`ad`, `cloud`, `iam` and `network` reuse their existing normalized review schemas.
Native cloud exports use `--input-mode aws-iam`, `gcp-iam` or `azure-nsg`;
network settings use `sysctl-text` or `resolved-conf`. These reuse the original
readers and preserve their limitations.
`web` and `vulnerability` accept an approved source directory. The latter reuses
configuration and OpenAPI checks; existing Semgrep/CVE/fuzz/AI commands remain
available independently. `evidence` accepts `{"reports":["/absolute/one.json",
"/absolute/two.json"]}` and reuses digest correlation. `business` accepts explicit
states, transitions and observed events; see the synthetic example generated in
`business/positive/fixture.json`.

Business review checks permitted transitions, observed state continuity, roles,
tenant constraints and integer amount limits. Failed events do not advance state.
It does not infer business rules, execute arbitrary expressions or automatically
collect application transactions. Missing events and concurrency need review.

For real collection, use the existing scoped commands shown by
`assessment-modules`, or the new [read-only LDAPS collector](AD_DIRECTORY_COLLECTION.md).
Their scopes, approval fingerprints, private credentials, deadlines, quotas and
stop controls remain mandatory. Selecting LIVE does not bypass them.

The common collection facade preserves the original native report and links its
exact file hash into the shared report:

```bash
hunterqa assessment-collect --connector gcp-inventory --mode LIVE \
  --input /approved/gcp-scope.json --credentials /approved/private-token.json \
  --native-out /approved/new-native.json --out /approved/new-shared.json --authorized
```

Connectors: `azure-inventory`, `gcp-inventory`, `gcp-permissions`, `aws-inventory`,
`ad-directory`, `network-service` and `web-scenarios`. AWS/directory/scenario
connectors still require their original approval and credential options. Cloud
provider APIs require LIVE intent; this is not a provider-validation claim.
Azure/GCP also accept encrypted temporary tokens through `--session-file` and
`--session-key` instead of `--credentials`. See [token vault setup](CLOUD_TOKEN_VAULT.md).
The shared LAB facade accepts numeric private network/web targets only; original
scoped commands continue to support their documented DNS-based lab contracts.
Successful inert uploads and matched authorization-denial contracts are not
converted into vulnerability findings. Timing signals remain informational.
Reports count actual HTTP attempts, TCP connections and LDAP operations separately
from simulated operations. These are attempted operations, not successful requests
or proof that a finding has been validated.

## 3. Dashboard and project history

Open **Assessment modules** in a private authenticated workspace. Analysts and
administrators can run the bounded offline demo and optionally associate it with
an existing project. Viewers cannot start it. CSRF protection and the existing
operator audit gate apply. Only one demo can run at a time in that process.

Reports appear in **Scenario results**, with DEMO in the history kind and in
the finding display. Evidence source/hash, risk priority and remediation are
available for inspection. Completed source reports remain unchanged.

To associate an offline review with a project, add
`--workspace-config /private/control/workspace.json --project-id 1`, and keep
inputs/outputs under that workspace's assessment root. The dashboard does not
add a general remote network-execution endpoint: LAB/LIVE target collection
continues through the existing authorized CLI boundary. General asynchronous
multi-domain execution and progress in this UI remain incomplete.

## 4. Export and integrity

```bash
hunterqa assessment-export --input /absolute/review.json \
  --format sarif --out /absolute/new-review.sarif
```

JSON, HTML and SARIF retain DEMO/LAB/LIVE provenance; even an empty DEMO SARIF
run is labeled. The existing SARIF exporter still omits arbitrary messages,
source excerpts and unsafe paths. Shared finding confidence is not assigned a
made-up probability. Severity is a triage priority, not verified impact.

Saved dashboard records verify the exact persisted file hash before inspection
or export. Tampered reports become unavailable. Exports never upload results.
Use the existing workspace backup/recovery workflow for retained data.
Cross-module digest correlation retains each report's source and flags mixed
DEMO/LAB/LIVE/UNCLASSIFIED evidence without promoting a claim to another source.
Legacy evidence without provenance stays UNCLASSIFIED.

## Remaining scope

The new common facade is not a completed universal assessment engine. Complete
native IAM semantics, broad cloud configuration collection, effective AD ACLs,
automatic target SSO/business discovery, enterprise isolation, representative
effectiveness evaluation and real provider acceptance remain separate gaps in
the traceability matrix. The existing localhost runtime handoff does not certify
those areas.
