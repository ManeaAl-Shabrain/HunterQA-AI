# Completion gates and remaining scope

An implemented control, local fixture or successful CI run is evidence about
that control. It is not independent proof that the whole assessment platform is
complete. `workspace-check --require-production` must not pass through unchecked
deployment assumptions. Historical release assets remain unchanged.

| Area | Current implementation/evidence | Gate still required |
| --- | --- | --- |
| Dashboard SSO | Explicit OIDC code/S256, verified issuer/subject, local role binding, one-use browser state, native TLS and real Chromium owned provider controls | Real selected provider registration/consent/MFA, intended callback/TLS deployment, outage and operational validation; SAML/global provider logout are unsupported |
| Workspace access | Separate process, identity store, secret, data/evidence roots, sticky database identity, cross-process session/data/worker denial controls | Real OS identities/containers, denied filesystem and egress tests, Windows ACL validation, storage quotas and independent isolation review |
| Hosted entry point | Authenticated single-hop HTTPS edge admission, exact Host, Secure cookies, stripped forwarding data, bounded Waitress and queue, host-local lease | Real TLS proxy, firewall/key/log policy, load/failure/restore exercises, operational monitoring and independent deployment review |
| Assessed application identity | Fixed role matrices, optional token verification, owned OIDC/session fixtures | General external target SSO, complex session federation, stateful business workflows and broader tenant-boundary discovery |
| General browser interactions | Bounded rendered links and explicitly reviewed slash hash states | App-specific reviewed interaction contracts, state/impact oracles, general forms/actions and representative compatibility; no claim of universal automatic interaction |
| Active vulnerability validation | Fixed owned SQL canary and reflected-XSS controls with negative labels | Broader contexts/classes, blind/OOB/DOM/stored variants, representative independently labeled datasets and per-class error rates |
| Infrastructure | Scoped TCP/TLS, server-first SSH claims, one UDP DNS question and selected saved evidence readers | Authenticated service/OS identification, broader protocols, live AD/effective-access and real path validation |
| Cloud | Selected AWS APIs, scoped Azure/GCP metadata and selected caller permission responses, native I/O bounds | Representative real accounts, full resource/effective-permission inventory and independently confirmed impact/scope |
| Distributed production | Invocation controls, host-local shared reservations for selected native commands, bounded local workspace server | Durable distributed workers, cross-host cancellation/quota, network/OS isolation, authenticated owner grants and multi-host failure tests |
| Effectiveness | Versioned owned labels, discovery/visit reference metrics, limited standards map | Independent review of representative ground truth, repeatable field evaluation, complete standards coverage and published unknown/failure rates |

The current environment has not supplied a registered real IdP, target application
test accounts, deployment host/TLS edge, OS isolation runtime or independently
reviewed representative dataset. Do not replace these gates with an operator
checkbox or mark production complete from configuration alone.

Next deployment inputs are the intended IdP/issuer and registered client/callback
(secrets provisioned privately), deployment topology/OS identities, test tenant and
authorized test targets, and an independent evaluation protocol/data owner.
Implementation and owned testing can proceed without those secrets; real-world
acceptance cannot be honestly reported until those environments are exercised.
