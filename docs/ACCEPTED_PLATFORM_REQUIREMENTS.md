# Accepted platform requirements

Owner-approved baseline: 12 November 2026. Requested capabilities below are
requirements, not claims that they are already implemented or validated.
Existing functionality and the historical 1.3.0 release must be preserved.

| ID | Required outcome | Current gap / acceptance evidence required |
| --- | --- | --- |
| DEP-01 | Independent Linux Docker Compose and native systemd deployments, same application and API/security configuration | Common runtime manifests, actual service/container acceptance and module compatibility evidence |
| DEP-02 | Windows development/run through WSL2 and Docker Desktop | Document prerequisites, filesystem/UID/network behavior; actual Desktop/WSL2 acceptance remains necessary |
| AUTH-01 | Independently switchable local, Google OIDC and Entra OIDC | Existing local and single explicit OIDC provider; simultaneous independent provider configuration remains open |
| AUTH-02 | Verified identities map to one pre-approved local account | Preserve exact issuer/subject bindings, local RBAC/revocation and no automatic email linking or signup |
| AUTH-03 | MFA according to policy, mandatory for administrators | Missing application-enforced admin MFA; provider authentication alone is insufficient evidence |
| SEC-01 | No public signup, approved users only, no automatic Admin grants | Preserve OS-admin provisioning and local roles; test unknown identities and escalation denial |
| SEC-02 | Protected credentials, sessions and tokens; code/S256 PKCE | Preserve hashed passwords/session tokens and strict OIDC; encrypt any future stored MFA secrets and protect provisioning keys |
| SEC-03 | Audit every authentication attempt and sensitive operation | Extend existing local audit to provider selection/failure/MFA and deployment maintenance without logging secrets |
| OFF-01 | Offline operation for local functions and local authentication | Verify local login, source/evidence workflows and recovery without an external IdP or AI service |
| OFF-02 | Google/Entra contact identity services during authentication | Test provider outages and no fallback that bypasses configured authentication policy |
| VAL-01 | Real integration, security and operational tests | Distinguish owned fixtures from real Google/Entra registrations and deployed OS/network validation |
| DOC-01 | Installation, settings, operation and troubleshooting for every environment | Keep one configuration contract; clearly mark unsupported or unverified scenarios |

Implementation order: common runtime/deployment acceptance, multi-provider
authentication and policy, MFA enrollment/enforcement/recovery, then real
provider/platform acceptance. No stage may mark the whole platform complete
using template presence, an untested configuration or CI alone.

No provider client IDs, secrets or real deployment registrations were supplied.
Those values must be provisioned privately; do not send secrets in chat.
