# Personal localhost release handoff

Review date: 12 November 2026. Normal use is one personal computer, with private
workspaces on localhost. The package version remains 1.3.0; historical release
archives are unchanged. Identify the installed source with `git rev-parse HEAD`.

## Release decision

| Scope | Status |
| --- | --- |
| Local accounts, Admin MFA, roles, revocation and offline local workflows | Implemented; automated application and actual Linux lifecycle checks passed |
| Linux native systemd and Docker Compose | Shared application/runtime; both deployment jobs passed |
| Optional Google and tenant-scoped Entra OIDC | Implemented and tested with owned signed-provider/browser fixtures; real-account acceptance is assigned to the owner |
| Windows WSL2 and Docker Desktop | Setup documented; actual desktop acceptance is assigned to the owner |
| Broad assessment expansion and hosted/distributed multi-user production | Outside this local release's completion claim; see [remaining scope](EXPANSION_PROGRESS.md) |

The personal localhost engineering scope can be handed over for use and manual
acceptance. A suitable announcement is: **“Development of the personal localhost
edition is complete; optional identity-provider and Windows desktop integrations
are entering owner-run acceptance.”** This does not certify all vulnerability
classes, target applications, cloud accounts or multi-tenant deployments.

Local operation does not require Google/Entra credentials, a public domain,
public HTTPS, a VPS or cloud hosting. Use the guarded workspace profile in
[README](../README.md), not the legacy development dashboard, for named accounts
and enforced Admin MFA.

## Recorded validation

The merged authentication baseline is PR [#78](https://github.com/ManeaAl-Shabrain/HunterQA-AI/pull/78),
source commit `697479e56f92b946c8a0f5be9f3a2b597af9a947`.

| Check | Recorded result |
| --- | --- |
| Full local regression | 3435 passed, 52 skipped |
| Linux Python 3.11 and 3.13 regression | 3436 passed, 51 skipped on each |
| Unified Local/Google/Entra Chromium flows | 3 passed on each tested platform; provider UI/responses were owned fixtures |
| Shared systemd and Compose lifecycle | Both passed: Local/MFA, pre-MFA API denial, RBAC, source worker/Semgrep, reports, backup/restore and renewed login |
| Python syntax, Ruff F and medium/high Bandit | Passed |
| Installed Python dependency advisory audits | Passed in both deployment jobs |

Evidence: [Release QA #206](https://github.com/ManeaAl-Shabrain/HunterQA-AI/actions/runs/43207493384)
and [Linux Deployment QA #9](https://github.com/ManeaAl-Shabrain/HunterQA-AI/actions/runs/43207493375).
Current maintenance changes carry their own GitHub Checks. Counts overlap and
must not be summed. Optional browser checks run explicitly in dedicated steps;
a skipped default-suite test is not evidence that it passed.

The repository review checks tracked source/configuration/template syntax,
Markdown files and local links, command documentation, conflict markers,
selected credential patterns, packaging and the regression/security gates.
These checks do not prove that every file is free of every possible defect.

## Owner-run acceptance

Use [personal setup](PERSONAL_LOCALHOST_SETUP.md). Keep credentials and evidence
private; the checklist is an acceptance record, not an automatic approval gate.

1. Record the source commit, OS, runtime and browser versions.
2. For each configured provider, register the exact localhost callback, complete
   provider sign-in and approve its verified subject through the local OS command.
3. Restart and verify the intended local account, Admin MFA and logout. Test
   account disabling in a disposable workspace; retain a second active enrolled
   administrator before disabling an Admin, because last-admin protection is
   intentional. Check that the disabled account's old session is rejected.
4. With the network disconnected, verify enabled Local login, MFA and a saved
   report. Optional SSO should fail without bypassing the configured policy.
5. On WSL2/Desktop, check private Linux file ownership, localhost access, no
   unintended LAN listener, scan/report/export and backup/restore. Use a disposable
   test workspace for restore; do not overwrite live data.
6. Save the outcome as passed, failed or not run. A failure remains open until
   fixed and retested; do not mark real-provider or desktop acceptance passed
   from the synthetic fixtures or Linux CI alone.

## Operating limits

- Keep control files, OAuth client secrets and backups private. The OS owner is
  trusted; local roles do not protect secrets from a compromised OS account.
- Compose uses host networking; it does not install a separate egress firewall.
  The CI egress rejection is a test policy, not the deployment default.
- Users within one workspace share its saved data according to their roles.
  This is not independently certified per-project or hostile-tenant isolation.
- The shared runtime's documented Semgrep dependency repair is a local
  compatibility patch. Retain its provenance and review it when upstream changes.
- A clean static/advisory check is not a guarantee of security or complete
  detection coverage. See [security limits](LIMITATIONS.md) and
  [broader production gates](PRODUCTION_COMPLETION.md).

For day-to-day operation, start with [the deployment guide](LINUX_DEPLOYMENT.md),
[authentication](UNIFIED_AUTHENTICATION.md) and [recovery](WORKSPACE_RECOVERY.md).
