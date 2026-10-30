# Expansion progress

This tracks implementation against the requested seven-area expansion. Passing
a bounded fixture does not mark an entire area complete. Historical release
assets are unchanged.

| Area | Delivered so far | Remaining work |
| --- | --- | --- |
| Web discovery | Opt-in scoped HTTPS rendered-anchor crawl, bounded same-origin resources and ephemeral conventional-login cookie reuse | SSO, complex sessions, general SPA actions, representative compatibility evaluation, complete endpoint discovery |
| Vulnerability validation | Fixed owned-endpoint SQL canary differentials, Chromium reflected-XSS execution controls and a six-endpoint HTTP baseline | General validation across input/SQL/HTML contexts, representative datasets and broader vulnerability classes |
| Identity and authorization | Explicit role contracts, optional signed ID-token verification, owned OIDC/PKCE/code/session/tenant/logout controls | External interactive SSO, production sessions/federation, stateful business logic and general tenant boundaries |
| Internal infrastructure | Exact TCP reachability, one scoped verified TLS handshake, one expiring exact-endpoint UDP DNS A question with expected-answer comparison, and selected saved evidence review | Service/OS identification, protocol/cipher enumeration, revocation, broader UDP protocols, live directory/effective-access and attack-path assessment |
| Cloud | Existing narrow AWS APIs and saved AWS/Azure/GCP policy readers | Resource/effective-permission inventory, Azure/GCP runtime adapters and representative cloud evaluations |
| Production and users | Existing local roles, per-run controls and optional shared local quotas | Verified grants, tenant isolation, OS sandboxing, distributed workers and cross-host quotas |
| Effectiveness evidence | Endpoint-reference recall, separate HTTP runtime labels, per-class confusion/miss metrics and bounded WSTG mapping | Representative independent field evaluation, broader per-class coverage and a complete standards map |

First implementation: [scoped rendered discovery](SCOPED_RENDERED_DISCOVERY.md).
Second implementation: [controlled runtime validation](CONTROLLED_RUNTIME_VALIDATION.md).
Third implementation: [signed ID tokens and owned OIDC/session assurance](OIDC_SESSION_ASSURANCE.md).
Fourth implementation: [scoped TLS certificate and hostname inspection](SCOPED_TLS_INSPECTION.md).
Fifth implementation: [expiring scoped UDP DNS inspection](SCOPED_UDP_DNS_INSPECTION.md).
These remain bounded source-development capabilities. Multi-user
production changes require a separate deployment architecture and threat model;
local roles alone do not provide tenant isolation.
