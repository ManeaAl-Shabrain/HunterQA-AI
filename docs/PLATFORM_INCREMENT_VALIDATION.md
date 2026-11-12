# Unified assessment increment: validation and remaining scope

Review date: 12 November 2026. Implementation source:
`aadf2179da660389ad7f98e2c4f8f91e1e635d3b`, proposed in
[PR81](https://github.com/ManeaAl-Shabrain/HunterQA-AI/pull/81).
This report extends the earlier personal-localhost handoff. It does not declare
the complete platform specification finished or certify production deployment.

**All seven CI jobs passed on the implementation source above.** Documentation
was finalized after observing those results. The broader requirements below
remain open. [Machine-readable evidence](PLATFORM_VALIDATION_EVIDENCE.json)
records the source, workflows, local results and artifact hashes.

## 1. Repository preservation and traceability

Before implementation, main at
`b4f9dbaabc8b6bc516a35d5debd14aa80cc65c12`, remote development branches,
pull requests, code, tests and deployment files were inspected. PR80 had merged;
no open PR existed at that inspection. The two unmerged historical branches were
reviewed for code differences and existing equivalents.

The [370-item matrix](PLATFORM_GAP_ANALYSIS.md) and its
[JSON source](PLATFORM_REQUIREMENTS.json) were committed before code changes.
Each item retains its baseline classification, current classification,
implementation/test references, evidence and limits. References are not a claim
that every broad clause has complete coverage.

| Current classification | Requirements |
| --- | ---: |
| Already Implemented and Verified | 55 |
| Implemented but Requires Improvement | 32 |
| Partially Implemented | 266 |
| Missing | 1 |
| Blocked by External Dependencies | 16 |

These counts describe individual specification items, including repeated clauses;
they are not a percentage of product readiness. GPO security-content collection
is explicitly missing; collecting GPO metadata does not satisfy that requirement.

Existing SAST, API analysis, CVE intelligence, fuzzing, AI research, workflow
supervision, correlation, triage and reporting remain in place. Existing CLI
commands and data stores are preserved. New outputs are create-only; no existing
user data, release tags or historical release archives were deleted or replaced.
The package version remains 1.3.0; install and record the source commit.

## 2. Delivered functionality

| Domain | Reused or added capability | Verification boundary |
| --- | --- | --- |
| Web | Existing Python source analysis and scoped scenarios; native results linked to common evidence/history | Synthetic source tests and actual owned HTTP/browser fixtures; general target SSO and arbitrary application compatibility incomplete |
| Business logic | Explicit states, allowed transitions, role/tenant/amount constraints and audit-trace continuity | Actual rule evaluation and owned workflow contracts; rules must be supplied, not automatically discovered |
| Internal networks | Existing TCP/TLS/UDP and selected service observations through the common facade | Actual owned loopback services; broad OS/service identification and segmentation assessment incomplete |
| Active Directory | Verified-TLS read-only single-domain LDAP, selected accounts/groups/domain policies and pseudonymized snapshots | Actual isolated Samba AD with a normal reader; effective DACLs, GPO content, AD CS and complete trust analysis incomplete |
| Cloud | New bounded AWS EC2/security-group/S3 inventory; existing Azure/GCP inventory and GCP permission query reused | Fixed API/signing/scope tests and synthetic responses; no actual AWS/Azure/GCP account validation |
| IAM | Existing native policy readers and normalized membership/grant/deny models; selected GCP caller-permission query | Synthetic/supplied-policy evaluation; no complete native effective-permission calculation |
| Vulnerabilities/configuration | Existing SAST, configuration, OpenAPI, dependencies/advisories and bounded runtime controls | Original regressions and owned controls; no universal detection or exhaustive vulnerability claim |
| Evidence/reporting | Shared source labels, hashes, finding references, deduplication, original native report retention and JSON/HTML/SARIF | Tamper, redaction, separate-event fingerprints and protected export tests; hashes do not authenticate an operator's assertions |

Collection remains separate from detection. The shared facade calls the original
collectors and analyzers. It does not introduce a second SAST/CVE/fuzzing engine.

## 3. Modes, dashboard and credentials

| Mode | Behavior |
| --- | --- |
| DEMO | Versioned synthetic positive/negative inputs passed to actual analyzers; no network requests; findings and exports explicitly labeled DEMO |
| LAB | Explicit owned-lab intent with existing authorization/scope gates; imported files alone are not proof of a real lab run |
| LIVE | Explicit authorized real-source intent; existing credential, scope, expiry, quota and stop controls apply; selecting LIVE never grants provider verification |

All eight domains have offline demos. The existing dashboard can select modules
and modes, run protected offline demos, associate results with projects, inspect
findings/evidence and export reports. Analysts/Admins require the existing role,
CSRF and audit controls; viewers cannot start analysis. Saved files are checked
against their persisted hash before viewing/export.

LAB/LIVE network collection uses the existing authorized CLI boundary and can
record results in the same project history. General dashboard target execution,
asynchronous multi-domain progress and a distributed queue remain incomplete.
See [architecture decisions](ASSESSMENT_ARCHITECTURE_DECISIONS.md).

Dedicated encrypted purposes now separate web sessions, directory passwords,
AWS signing keys and Azure/GCP temporary tokens. Tokens decrypt in memory;
changing the vault or key stops subsequent gated requests. Fixed provider origins,
short expiry, no ambient credential discovery and existing read-only APIs remain
mandatory. Legacy private token-file commands remain compatible; use
[encrypted token setup](CLOUD_TOKEN_VAULT.md) for the new shared path.

## 4. Verification record

| Check | Observed result |
| --- | --- |
| Latest targeted modes/AD/AWS/evidence/utility tests | 158 passed |
| Azure/GCP inventory, permissions and transport tests | 282 passed |
| Complete Windows-host regression on implementation source | 3542 passed, 59 skipped in 412.35 seconds |
| Linux Python 3.11/3.13 regression, browser and CLI acceptance | [Current source workflow](https://github.com/ManeaAl-Shabrain/HunterQA-AI/actions/runs/43276560463): passed; 3543 passed/58 skipped per regression run on both Python versions, plus separate browser/CLI checks |
| Actual Docker Compose and native systemd lifecycle | [Current deployment workflow](https://github.com/ManeaAl-Shabrain/HunterQA-AI/actions/runs/43276560434): both passed |
| Actual isolated Samba AD | [Current Samba workflow](https://github.com/ManeaAl-Shabrain/HunterQA-AI/actions/runs/43276560464): passed |
| Ruff undefined-name/unused-import checks | Passed |
| Bandit static checks | No medium/high finding in the checked application/tools; low findings are not a security certification |
| Installed local dependency advisory audit | No known vulnerabilities reported; editable project excluded from third-party audit |
| Source archive | 523 files verified against SHA-256 manifest; includes AD Dockerfile, shared collectors and traceability/token documentation |
| Documentation file links | 135 Markdown files checked; no missing local file link found; external URLs/anchor semantics not certified |
| Independent representative field evaluation | Not performed |
| Actual AWS/Azure/GCP and Google/Entra accounts | Not tested |
| Actual WSL2/Docker Desktop | Owner acceptance outstanding |

The first final-regression attempt had 3539 passes, 59 skips and one failure:
the generated category index still contained the old AD description. The index
was regenerated, its test passed, and a fresh complete run was started. Two
additional regression tests reproduced and verified the source-evidence repair:
unrelated files no longer hide an analyzed source receipt, and changed
configuration/OpenAPI source is rejected rather than paired with a stale hash.

The prior committed source `28aa485812e3e1d6419548d57f1152e59355633a`
also passed all seven CI jobs, including 3533 Linux regression passes/58 skips,
real Compose/native lifecycle and actual Samba. Those earlier results are
recorded separately in the matrix and are not substituted for the current run.

## 5. Detection measurements and lab evidence

The standalone `platform-demo-1` run exercised eight domains and retained 16
positive/negative reports. All controls matched, with zero network requests.
Ten selected detection labels produced TP=10, TN=10, FP=0 and FN=0; precision
and recall were 1.0 and false-positive rate 0.0 **on that original synthetic
fixture only**. Evidence-correlation controls are excluded from those metrics.
The fixture is neither independent nor representative of field accuracy.

The separate owned expansion lab distinguishes actual HTTP/SQLite/Chromium/TCP
activity from synthetic AD/cloud permission models. A canary response, timing
signal, inert upload roundtrip or matched authorization denial is not promoted
to confirmed exploit impact. HTTP attempts, TCP connections, LDAP operations and
simulated operations are reported separately.

The Samba lab runs with no external network interface, host mount or published
port. Collection uses verified LDAPS and OS UID 10001 with an ordinary directory
reader. Earlier and current lab runs are separate from mock/TLS-unit tests.
The current run observed five accounts, 38 groups, one domain, two GPO metadata
objects and no trusts, in one page. Selected password-length and lockout policy
checks matched. Inventory and policy receipts are retained in the workflow logs;
GPO counts refer only to metadata, not content/security validation.

Known accuracy limitations include narrow static syntax cues, possible alias or
shadowing ambiguity, incomplete/supplied business traces, omitted directory
attributes, bounded resource pages and unmodeled IAM conditions/denials. Missing
data and absent findings do not establish security. Shared confidence scores
remain unset rather than presenting an unsupported probability.

## 6. Deployment, authentication and security limits

Compose and native systemd share application logic/runtime configuration and
preserve localhost defaults, persistent storage, dedicated accounts, health,
recovery and audit behavior. Their lifecycle checks exercise actual Local login,
mandatory Admin MFA, role denial, source scanning, reports, demo history and
backup/restore with session revocation/credential renewal. They do not validate
every possible target integration or a hosted multi-tenant installation.

Optional Google and Entra remain configured through documented localhost OIDC
flows; public registration stays disabled and new SSO users do not acquire Admin
automatically. Local authentication works offline. Actual provider-account login
and WSL2/Desktop validation remain owner-run checks, as previously agreed.

Important unresolved security boundaries:

- Operator authorization statements are not independently verified owner grants.
- Private workspace stores and host-local quotas do not provide OS tenant
  isolation, distributed workers or enforced cross-host quotas.
- Encryption at rest does not protect against a compromised privileged process.
- Source reads reduce accidental changes but do not provide an atomic filesystem
  snapshot against another process changing and restoring files concurrently.
- Read-only collectors still consume target resources. Page/resource/time bounds,
  stop controls and exact scopes remain necessary; in-flight work may finish.
- Dependency/static/lab passes cannot establish absence of all vulnerabilities.

No known medium/high static-check finding was introduced by this increment.
That is a limited test result, not a penetration-test certificate or a production
readiness declaration.

Bandit still reports 64 low-severity patterns: 14 password-like constant/field
strings, nine subprocess imports, seven subprocess calls, two PATH-based tool
starts and 32 assertions in verification helpers. The strings inspected include
public disposable-lab values and status/policy labels, not embedded personal
credentials. Subprocess use remains in existing explicit local tools/workers;
fuzz replay intentionally executes an approved local binary and requires its
documented isolation. Assertions are test expectations, not application access
checks; run the verification helpers normally, without Python optimization.
These patterns remain visible rather than being globally suppressed.

## 7. Remaining implementation and external configuration

| Work | Why it remains |
| --- | --- |
| General application interactions, target SSO and business-process discovery | Existing bounded contracts require operator-selected actions/rules; broad compatibility needs implementation and representative evaluation |
| Wider SQLi/XSS/SSRF/upload/blind validation | Existing owned controls cover selected contexts and do not prove every vulnerability or real DBMS behavior |
| Effective AD ACL/GPO/trust/AD CS assessment | Metadata and selected policy attributes are insufficient; native security semantics and safe collection still require implementation |
| Comprehensive cloud inventory/configuration and effective IAM | Current API sets, regions, resource types and permission models are bounded; broader analysis remains implementation work |
| Dashboard-driven LAB/LIVE scheduling and progress | Requires an approved-workflow control plane, credential delegation, durable cancellation and isolation review |
| Independent effectiveness and broader production isolation | Requires representative labeled data and additional engineering; not just external credentials |
| Real providers and Windows desktop acceptance | Requires owner-configured authorized accounts or an equipped desktop; credentials should remain in private local storage |

New installations create their own administrator, keys, workspace and authorized
contracts. No personal account, cloud subscription or enterprise environment is
required for offline demos or the included owned labs. Real cloud configuration
is optional until supplied. Follow [README](../README.md),
[Zero to Start](../zero%20to%20start.md), [local deployment](PERSONAL_LOCALHOST_SETUP.md),
[assessment modes](ASSESSMENT_MODES.md), [AD collection](AD_DIRECTORY_COLLECTION.md)
and [AWS collection](SCOPED_AWS_INVENTORY.md).

Use the validated bounded capabilities for authorized work and retain their
evidence. Keep the broader specification open until its remaining implementation
and operational acceptance have their own test evidence.
