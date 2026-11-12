# Expansion progress

This tracks implementation against the requested seven-area expansion. Passing
a bounded fixture does not mark an entire area complete. Historical release
assets are unchanged.

## Native GPO file analysis

The [GPO reader](GPO_POLICY_REVIEW.md) adds selected native machine security-template
and binary registry-policy checks to existing AD history/reports. It runs offline,
retains evidence hashes and unknown counts, and has native-format fixture tests.
SYSVOL acquisition and effective/resultant Windows policy remain incomplete.

## Unified assessment increment

[Eight-domain modes](ASSESSMENT_MODES.md) reuse existing analyzers with common
DEMO/LAB/LIVE provenance, evidence hashes, JSON/HTML/SARIF export and protected
project history. Offline demos exercise versioned positive/negative fixtures;
their accuracy is not an independent or representative effectiveness estimate.

New collection extends existing boundaries: [read-only LDAPS](AD_DIRECTORY_COLLECTION.md)
has actual isolated Samba acceptance, [bounded AWS resources](SCOPED_AWS_INVENTORY.md)
use explicit STS signing, and Azure/GCP optionally consume
[encrypted temporary tokens](CLOUD_TOKEN_VAULT.md). No real cloud account has been
tested. Effective AD ACL/GPO/trusts, complete cloud inventory/IAM and general
dashboard-driven LAB/LIVE execution remain incomplete. See the
[370-requirement matrix](PLATFORM_GAP_ANALYSIS.md) for baseline/current status,
implementation files, tests and limits.

## Owned scenario expansion

The [scenario assessment guide](SCENARIO_ASSESSMENTS.md) adds a repeatable local
acceptance lab across the requested areas. Its 20 checks with Chromium separate
actual HTTP/SQLite/browser/TCP operations from synthetic AD/cloud models.

| Addition | Delivered | Still outside the verified scope |
| --- | --- | --- |
| Application interactions | Reviewed browser actions, dynamic route hashes, encrypted expiring origin-bound cookies/local storage | Autonomous application exploration and automatic target SSO negotiation |
| Validation | Three SQL boolean contexts, four XSS contexts, owned SSRF callback, inert upload/deletion and timing signals | General vulnerability coverage, stored XSS and real DBMS timing proof |
| Identity/business logic | Explicit GET/POST role/workflow contracts, named cookie sessions and anonymous controls | General business-rule discovery and arbitrary tenant models |
| Internal/AD | Fixed service observations, normalized candidate paths and separate actual Samba-tested bounded LDAPS | Verified OS/version identification, effective ACL/GPO/trusts and executed paths |
| Cloud/IAM | Offline AWS/Azure/GCP exact-action models with deny/unknown/tenant handling | Native policy completeness, broad inventory and live effective-access confirmation |
| Evidence/UI | Completed CLI history associated with projects, protected digest-checked summaries and correlation | Asynchronous scenario scheduling, independent evidence provenance and distributed execution |

This is a local-fixture delivery milestone, separate from the earlier personal
localhost runtime handoff. It does not mark all seven broad areas complete.

| Area | Delivered so far | Remaining work |
| --- | --- | --- |
| Web discovery | Opt-in scoped HTTPS rendered anchors and explicitly selected slash hash routes, separate discovered/visited reference recall, bounded same-origin resources and ephemeral conventional-login cookie reuse | SSO, complex sessions, general SPA actions, representative compatibility evaluation, complete endpoint discovery |
| Vulnerability validation | Fixed owned-endpoint SQL canary differentials, Chromium reflected-XSS execution controls and a six-endpoint HTTP baseline | General validation across input/SQL/HTML contexts, representative datasets and broader vulnerability classes |
| Identity and authorization | Explicit role contracts, optional signed ID-token verification, owned OIDC/PKCE/code/session/tenant/logout controls | External interactive SSO, production sessions/federation, stateful business logic and general tenant boundaries |
| Internal infrastructure | Exact TCP reachability, scoped verified TLS handshake, bounded server-first SSH identification claims, one expiring exact-endpoint UDP DNS A question with expected-answer comparison, and selected saved evidence review | Authenticated/general service and OS identification, protocol/cipher enumeration, revocation, broader UDP protocols, live directory/effective-access and attack-path assessment |
| Cloud | Narrow AWS APIs, bounded Azure/GCP visible-resource GETs, selected GCP caller permission-query responses with explicit temporary tokens, and saved AWS/Azure/GCP policy readers | Complete resource inventory, independently confirmed effective permissions, broader AWS/Azure/GCP coverage and representative cloud evaluations |
| Production and users | Local roles or explicit operator OIDC, separate process/workspace stores and secrets, authenticated HTTPS edge admission, bounded WSGI/scan queue, host-local lease/recovery, per-run controls and selected shared host-local quotas | Real provider/deployment acceptance, independently validated OS/tenant isolation, verified owner grants, distributed workers, cross-host quotas and coverage of other entry points |
| Effectiveness evidence | Endpoint-reference recall, separate HTTP runtime labels, per-class confusion/miss metrics and bounded WSTG mapping | Representative independent field evaluation, broader per-class coverage and a complete standards map |

First implementation: [scoped rendered discovery](SCOPED_RENDERED_DISCOVERY.md).
Second implementation: [controlled runtime validation](CONTROLLED_RUNTIME_VALIDATION.md).
Third implementation: [signed ID tokens and owned OIDC/session assurance](OIDC_SESSION_ASSURANCE.md).
Fourth implementation: [scoped TLS certificate and hostname inspection](SCOPED_TLS_INSPECTION.md).
Fifth implementation: [expiring scoped UDP DNS inspection](SCOPED_UDP_DNS_INSPECTION.md).
Sixth implementation: [bounded Azure resource inventory](SCOPED_AZURE_INVENTORY.md).
Seventh implementation: [bounded GCP project asset inventory](SCOPED_GCP_INVENTORY.md).
Eighth implementation: [shared host-local quotas for native commands](NATIVE_SHARED_QUOTAS.md).
Ninth implementation: [bounded SSH identification observation](SCOPED_SSH_IDENTIFICATION.md).
Tenth implementation: [selected GCP caller permission query](SCOPED_GCP_PERMISSIONS.md).
Eleventh implementation: [native cloud transport deadlines and slow-response controls](CLOUD_TRANSPORT_DEADLINES.md).
Twelfth implementation: [selected SPA hash routes and separate visit coverage](SCOPED_SPA_HASH_DISCOVERY.md).
Operator/workspace foundation: [separate workspaces](PRODUCTION_WORKSPACES.md),
[operator OIDC](OPERATOR_SSO.md) and [remaining completion gates](PRODUCTION_COMPLETION.md).
The shared runtime now includes [unified Local/Google/Entra authentication](UNIFIED_AUTHENTICATION.md)
and encrypted, enforced administrator TOTP, with recovery reenrollment. This
dashboard control does not complete general assessed-target federation or
independently validate multi-tenant production isolation.
These remain bounded source-development capabilities. Multi-user
production changes require a separate deployment architecture and threat model;
local roles alone do not provide tenant isolation.
