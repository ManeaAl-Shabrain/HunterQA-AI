# Local, Google and Microsoft Entra sign-in

One approved local account can have a password and explicit Google and Entra
subject bindings. Each method has its own switch. Providers prove identity;
the local account controls roles, activation and revocation. There is no public
registration, automatic email linking or provider-supplied Admin role.

Normal personal operation needs only localhost. Follow the
[personal-computer walkthrough](PERSONAL_LOCALHOST_SETUP.md) for supported local
redirect registrations and OS-approved first-subject enrollment. A domain,
public HTTPS endpoint and hosted server are not required.

This is dashboard authentication. It does not implement federation into an
assessed application's accounts, SAML, universal business interactions or global
provider logout. Owned signed-token tests are distinct from live-provider acceptance.

## First setup

Install the shared runtime described in [Linux deployment](LINUX_DEPLOYMENT.md).
After `workspace-init`, run these commands as the dedicated workspace OS user,
with the same `HUNTERQA_OPERATOR_ROOT` as the server. Use a private interactive
terminal, not a recorded CI console. The unchanged deployment example uses:

```bash
hunterqa identity-setup --config /srv/hunterqa-alpha/control/alpha/workspace.json \
  --origin http://localhost:8081 --authorized
hunterqa operator-mfa-enroll --database /srv/hunterqa-alpha/control/alpha/operators.sqlite3 \
  --key-file /srv/hunterqa-alpha/control/alpha/auth.key --username admin --authorized
hunterqa workspace-check --config /srv/hunterqa-alpha/control/alpha/workspace.json
```

Enrollment displays a private `otpauth` setup URI on the terminal's stderr.
Add it to an authenticator and confirm a current code. The confirmed code cannot
be used again; wait for a fresh code before signing in. No seed is returned in
the command's JSON output. For controlled secret-manager automation,
`--secret-stdin` accepts one 32-character uppercase Base32 seed through stdin,
without displaying it. Never put a seed in command arguments, shell history,
repository files or deployment logs.

In Compose, run the same commands with `docker compose ... run --rm app`
before `up`. In native mode, use the installed runtime's full binary path and
`sudo -u hunterqa-alpha env HUNTERQA_OPERATOR_ROOT=...` as in the deployment
guide. No application-code change is needed when switching deployment mode.

`identity-setup` creates owner-private `identity.json` and `auth.key` beside
the identity database and adds `auth_config` to `workspace.json`. It starts with
Local enabled, both external providers disabled, and MFA mandatory for Admin.
Every active account in a required role must enroll before startup. Local login
and TOTP work without an external identity or AI service after installation.

## Configuration

Stop the server before editing private configuration. Never expose the control
directory to assessments or publish it. A policy looks like this (paths must be
absolute and private; the example does not contain usable secrets):

```json
{
  "schema_version": 1,
  "local_enabled": true,
  "mfa_roles": ["admin"],
  "key_file": "/srv/hunterqa-alpha/control/alpha/auth.key",
  "callback_origin": "http://127.0.0.1:8081",
  "providers": {
    "google": {"enabled": false},
    "entra": {"enabled": false}
  }
}
```

To enable Google, replace its entry with:

```json
{
  "enabled": true,
  "client_id": "YOUR-REGISTERED-CLIENT.apps.googleusercontent.com",
  "client_secret_file": "/srv/hunterqa-alpha/control/alpha/google.secret",
  "bindings": [{"subject": "VERIFIED-GOOGLE-SUBJECT", "username": "admin"}]
}
```

To enable Entra, use a single organization tenant, with this entry:

```json
{
  "enabled": true,
  "tenant_id": "11111111-2222-4333-8444-555555555555",
  "client_id": "YOUR-REGISTERED-APPLICATION-ID",
  "client_secret_file": "/srv/hunterqa-alpha/control/alpha/entra.secret",
  "bindings": [{"subject": "VERIFIED-ENTRA-SUBJECT", "username": "admin"}]
}
```

Use the actual canonical tenant UUID and application ID. Put each registered
client secret in its own owner-private file (0600 on Linux), beside the policy.
Disabled provider entries contain only `enabled: false` and need no secret.
`local_enabled` can be false when at least one external provider is enabled.
To require MFA for other roles, add `analyst` or `viewer` to `mfa_roles` and
enroll every active account in those roles before restarting.

Register exact redirect URIs `<callback_origin>/auth/google/callback` and
`<callback_origin>/auth/entra/callback` with the respective providers. Use a
Google Web application and a tenant-scoped Entra Web registration with
Authorization Code flow. HunterQA always sends S256 PKCE, state and nonce;
the secret and verifier travel only in the server's token exchange. Provider
endpoints and RS256 verification are fixed by the presets. Entra checks both
the tenant-scoped issuer and signed `tid`. Google's documented bare issuer
alias is accepted only in its fixed preset. Subject bindings must be obtained
through a trusted administrator procedure for that exact registration; email
addresses and directory object IDs are not interchangeable with OIDC `sub`.

See the primary [Google OIDC documentation](https://developers.google.com/identity/openid-connect/openid-connect)
and [Entra OIDC documentation](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc).

## HTTPS deployment and policy changes

Use [authenticated HTTPS edge admission](PRODUCTION_WORKSPACES.md) for hosted
access. Set `workspace.json`'s `public_origin`, `edge_key_file`, and this policy's
`callback_origin` to the same canonical HTTPS origin. Do not expose Waitress
directly. Both deployment profiles enforce `--require-auth-policy`. The legacy
single-provider `oidc_config` and unified `auth_config` are mutually exclusive.

Changing the policy, provider secrets or encryption key while running makes
authentication fail closed until an OS administrator restarts the application.
Policy activation/reconfiguration revokes existing sessions and pending grants.
A sticky dashboard marker rejects silently removing the authentication policy.
Preserve an offline recovery path before disabling Local.

## Sessions, MFA and recovery

Passwords and full session tokens are hashed. MFA seeds and pending OIDC
nonce/verifier values are encrypted with a separate key. The key's owner is a
trusted OS administrator; encryption does not protect against that owner.
Cookies contain opaque grant/session handles, not seeds, passwords or provider
tokens. Full sessions last at most eight hours and never exceed the accepted
ID token's expiry. TOTP challenges expire after five minutes, allow five attempts
and reject previously used time steps, including concurrent submissions.
Clock synchronization matters: the accepted window is 30 seconds either side.

Failed/disabled sign-ins, first factors, MFA, policy changes, revocations and
sensitive dashboard operations enter the local audit chain. Audit failure blocks
authentication; consistency is not independent authenticity against a DB owner.

Lost authenticator: the trusted OS administrator stops the service and repeats
`operator-mfa-enroll` after independently checking the user's identity. This
revokes that account's sessions. There is no email bypass or reusable recovery
code. After [workspace restore](WORKSPACE_RECOVERY.md), all accounts remain
disabled, passwords must be renewed, factors/grants are removed and the MFA key
rotates. Explicitly enable reviewed accounts and enroll fresh factors before
restarting; old authenticator seeds are not retained as working factors.

| Symptom | Action |
| --- | --- |
| Startup requests MFA enrollment | Enroll every active user whose role appears in `mfa_roles` |
| Verification fails | Check clock, use a fresh code; cancel/start again after five failed attempts |
| Sign-in method missing | Review its independent switch; restart after editing the policy |
| Provider denies redirect or consent | Compare the exact registered origin/client/tenant/callback |
| Provider outage | External sign-in fails; approved Local accounts work only if Local is enabled |
| HTTP 503 after configuration edit | Review the private change and restart; do not remove the policy |

Live Google/Entra registration, MFA enrollment on real devices and the intended
local WSL2 deployment still require acceptance in those environments. The test
suite uses owned credentials and signed fixtures; it does not claim external
consent or real-provider availability.
