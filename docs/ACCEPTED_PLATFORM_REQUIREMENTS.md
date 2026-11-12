# Accepted platform requirements

Owner-approved baseline: 12 November 2026. Requested capabilities below are
requirements, not claims that they are already implemented or validated.
Existing functionality and the historical 1.3.0 release must be preserved.

Owner clarification, same day: normal operation is exclusively on the personal
computer, bound to localhost. No purchased domain, public HTTPS endpoint, VPS or
cloud hosting is required. Keep Compose, native systemd and Windows WSL2 support;
Local + MFA works offline, Google/Entra remain optional until real credentials
are configured. Hosted TLS gates apply only to the preserved optional hosted
profile. See [personal setup](PERSONAL_LOCALHOST_SETUP.md).

| ID | Required outcome | Implementation / acceptance status |
| --- | --- | --- |
| DEP-01 | Independent Linux Docker Compose and native systemd deployments, same application and API/security configuration | Shared runtime implemented; both actual Linux lifecycle jobs passed |
| DEP-02 | Windows development/run through WSL2 and Docker Desktop | Prerequisites, filesystem/UID/network behavior documented; actual acceptance assigned to the owner |
| AUTH-01 | Independently switchable local, Google OIDC and Entra OIDC | Unified policy and three-way selection implemented; owned signed-provider and browser tests; real registrations remain external acceptance |
| AUTH-02 | Verified identities map to one pre-approved local account | Exact signed subject/local role binding and explicit OS approval implemented; no automatic email linking, signup or role change |
| AUTH-03 | MFA according to policy, mandatory for administrators | Encrypted local TOTP, mandatory Admin challenge across all methods, replay/attempt limits and recovery reenrollment implemented; real-device operational acceptance remains |
| SEC-01 | No public signup, approved users only, no automatic Admin grants | OS-admin provisioning and local roles implemented; unknown identity and escalation-denial tests passed |
| SEC-02 | Protected credentials, sessions and tokens; code/S256 PKCE | Password/session hashes, encrypted TOTP/pending OIDC state, private keys/secrets and code/S256 checks implemented |
| SEC-03 | Audit authentication attempts and sensitive operations | Provider/MFA/approval/policy events and sensitive mutations audited without credential values; audit failure blocks authentication |
| OFF-01 | Offline operation for local functions and local authentication | Actual Linux Local/MFA/source/report/recovery lifecycle passed with non-loopback egress denied for the fixture UID |
| OFF-02 | Google/Entra contact identity services during authentication | Owned outage and no-bypass contracts passed; real-provider acceptance assigned to the owner |
| VAL-01 | Integration, security and operational tests with real evidence | Automated source/browser and actual Linux runtime checks passed; live-provider and desktop results remain unrun until owner acceptance |
| DOC-01 | Installation, settings, operation and troubleshooting for every environment | Shared deployment, personal setup, authentication and recovery guides provided; [handoff](LOCAL_RELEASE_HANDOFF.md) records remaining manual acceptance |

Implementation order: common runtime/deployment acceptance, multi-provider
authentication and policy, MFA enrollment/enforcement/recovery, then real
provider/platform acceptance. No stage may mark the whole platform complete
using template presence, an untested configuration or CI alone.

The owner has taken responsibility for real Google/Entra and WSL2/Desktop tests.
Those results remain pending, not failed or automatically approved. Provider
secrets are provisioned privately; do not send them in chat. Normal Local/MFA
operation does not depend on enabling either external provider.
