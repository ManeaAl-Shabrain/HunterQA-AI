# Expansion progress

This tracks implementation against the requested seven-area expansion. Passing
a bounded fixture does not mark an entire area complete. Historical release
assets are unchanged.

| Area | Delivered in the first expansion | Remaining work |
| --- | --- | --- |
| Web discovery | Opt-in scoped HTTPS rendered-anchor crawl, bounded same-origin resources and ephemeral conventional-login cookie reuse | SSO, complex sessions, general SPA actions, representative compatibility evaluation, complete endpoint discovery |
| Vulnerability validation | Existing fixed source/canary checks and separate owned in-memory SQL fixture | Scoped runtime SQLi/XSS validators and independent positive/negative datasets; broader vulnerability classes |
| Identity and authorization | Existing explicit role/anonymous contracts; dedicated-account binding on rendered login | SSO, stateful business logic and general tenant boundaries |
| Internal infrastructure | Existing exact TCP reachability and selected saved evidence review | Service/OS identification, UDP, live directory/effective-access and attack-path assessment |
| Cloud | Existing narrow AWS APIs and saved AWS/Azure/GCP policy readers | Resource/effective-permission inventory, Azure/GCP runtime adapters and representative cloud evaluations |
| Production and users | Existing local roles, per-run controls and optional shared local quotas | Verified grants, tenant isolation, OS sandboxing, distributed workers and cross-host quotas |
| Effectiveness evidence | New offline endpoint-reference recall; synthetic Chromium route labels independent of the crawler | Representative independently labelled datasets, per-class missed-detection rates and a standards coverage map |

First implementation: [scoped rendered discovery](SCOPED_RENDERED_DISCOVERY.md).
The next coherent implementation should address a single runtime validation
contract together with its independent controls and metrics. Multi-user
production changes require a separate deployment architecture and threat model;
local roles alone do not provide tenant isolation.
