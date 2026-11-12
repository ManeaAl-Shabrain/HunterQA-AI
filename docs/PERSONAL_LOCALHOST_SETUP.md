# Personal-computer setup

HunterQA's normal private-workspace server binds **127.0.0.1 only**. No domain,
public HTTPS endpoint, VPS or cloud hosting is needed. Use
`http://localhost:8081` in your browser. Google and Entra are optional; leave
both disabled until you configure your own registrations. Local passwords and
TOTP work offline after installing dependencies.

This guide uses the unchanged `alpha` example from
[Linux deployment](LINUX_DEPLOYMENT.md). Substitute your existing paths/port
consistently. Preserve existing workspaces; do not initialize over their data.

## 1. Choose your local runtime

- **Native Linux:** use the shared installer and systemd unit in the deployment
  guide, under a dedicated non-root account.
- **Linux Compose:** use the same guide's image, private paths and numeric owner.
  The container uses host networking and the application binds loopback; no
  public port mapping, Docker socket or privileged container is required.
- **Windows:** install a WSL2 Linux distribution and Docker Desktop with its
  WSL2 integration and Linux containers. Keep source and private files on the
  Linux filesystem, use the Linux instructions inside WSL, and enable Desktop's
  host-network feature for this Compose profile. Native systemd requires
  systemd enabled in the WSL distribution; check `systemctl` before using it.
  See [WSL localhost networking](https://learn.microsoft.com/en-us/windows/wsl/networking).

Do not add router forwarding, LAN listeners, public firewall rules or public
admin/scanner endpoints. If Windows cannot reach WSL's localhost, fix the
localhost forwarding/integration instead of binding HunterQA to `0.0.0.0`.
Use only one runtime against a workspace at a time.

## 2. Enable Local and MFA

After `workspace-init`, run `identity-setup` and enroll the existing administrator
before starting the service. In native mode, as the workspace OS account:

```bash
export HUNTERQA_OPERATOR_ROOT=/srv/hunterqa-alpha/control
/opt/hunterqa-runtime/bin/hunterqa identity-setup \
  --config /srv/hunterqa-alpha/control/alpha/workspace.json \
  --origin http://localhost:8081 --authorized
/opt/hunterqa-runtime/bin/hunterqa operator-mfa-enroll \
  --database /srv/hunterqa-alpha/control/alpha/operators.sqlite3 \
  --key-file /srv/hunterqa-alpha/control/alpha/auth.key --username admin --authorized
```

For Compose, use the same arguments with the deployment guide's
`docker compose ... run --rm app` command. Use a private terminal for the
authenticator URI and confirmation. Do not record the URI in logs.
Then start systemd or Compose and sign in at `http://localhost:8081`: password,
then a fresh authenticator code. No external provider is contacted.

Already configured? Keep your data and keys. If changing from `127.0.0.1` to
`localhost`, stop the server, edit only `identity.json`'s `callback_origin`, and
restart. Do not repeat `identity-setup`, remove an existing policy or set
`public_origin`/`edge_key_file` for normal local operation.

## 3. Optional Google OIDC

1. In Google Cloud's Google Auth Platform, select/create your own project and
   configure its application name, contact and audience. For an external app in
   testing, add your own account as a test user where required.
2. Create an OAuth client of type **Web application**. This is a local Python
   web backend, not a browser-only SPA.
3. Register exactly `http://localhost:8081/auth/google/callback` as an authorized
   redirect URI. Use the actual configured port. No wildcard or public domain
   is needed for this localhost registration.
4. Retain the client ID. Put its client secret in the private control directory
   as `google.secret`, owned by the workspace OS account with mode 0600.
5. Stop HunterQA, replace only the `google` entry in `identity.json` with:

```json
{
  "enabled": true,
  "client_id": "YOUR-CLIENT-ID.apps.googleusercontent.com",
  "client_secret_file": "/srv/hunterqa-alpha/control/alpha/google.secret",
  "bindings": []
}
```

Keep `local_enabled: true`, `mfa_roles: ["admin"]` and Entra disabled unless you
also configure it. Restart, then follow step 5 below to approve your identity.
The provider uses code flow with S256 PKCE and `openid`; no Google API access or
refresh-token storage is requested. See
[Google's local web OAuth instructions](https://developers.google.com/identity/protocols/oauth2/web-server).

## 4. Optional Microsoft Entra ID OIDC

1. Open App registrations in your Entra directory. You need permission to
   register applications there; a personal Microsoft login alone is not a
   substitute for a configured Entra tenant.
2. Register a **single-tenant** application. Record its Application (client) ID
   and Directory (tenant) ID.
3. Under Authentication, add the **Web** platform with
   `http://localhost:8081/auth/entra/callback`. Keep implicit/hybrid grants and
   public-client flows disabled; HunterQA uses confidential code flow with PKCE.
4. Create a client secret. Save its **value**, not its secret ID, in private
   `entra.secret` beside the policy, owned by the workspace OS account, mode 0600.
   Retain its expiry date and renew it before expiry.
5. Stop HunterQA and replace only its `entra` entry:

```json
{
  "enabled": true,
  "tenant_id": "YOUR-CANONICAL-DIRECTORY-UUID",
  "client_id": "YOUR-APPLICATION-UUID",
  "client_secret_file": "/srv/hunterqa-alpha/control/alpha/entra.secret",
  "bindings": []
}
```

Restart, then approve the identity as below. HunterQA uses a fixed tenant, checks
the signed tenant claim and never accepts a generic `common` tenant. Microsoft's
[redirect rules](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url)
support HTTP localhost for this Web configuration. Avoid multiple registrations
of the same localhost callback path with different ports/platforms. This guide
uses `localhost`; literal `127.0.0.1` HTTP registrations can require manifest
editing in Entra and are not needed here.

## 5. Approve a verified subject locally

An empty `bindings` list enables provider verification but grants **no workspace
access**. It does not enable signup. The first successful provider verification
shows a five-minute enrollment reference and still returns access denied.

1. Open HunterQA at the registered `http://localhost:8081`, choose the configured
   provider and select your intended account in its own sign-in screen.
2. Copy the returned reference from HunterQA. It is not a workspace session.
   The candidate's subject is encrypted in the private identity database; the
   reference is stored only as a hash. Pending candidates are bounded and expire.
3. As the trusted workspace OS account, explicitly bind that reference to the
   existing local account you intend to use:

```bash
/opt/hunterqa-runtime/bin/hunterqa identity-provider-approve \
  --config /srv/hunterqa-alpha/control/alpha/workspace.json \
  --provider google --username admin --authorized
```

For Entra use `--provider entra`. For Compose use `docker compose ... run --rm app`
with the same command arguments. Paste the reference at the private prompt.
Only approve a reference from the account you just selected; do not approve one
sent by another person. `--reference-stdin` is available for deliberate private
automation. The command cannot create an account or change a role. Approval is
audited, exact signed `sub` is bound to the existing local user, and current
sessions/pending authentication are revoked. It never links by email, `oid` or
unverified claims.

4. Restart the selected runtime. The running application fails closed after the
   policy changes until this restart. Sign in through that provider again; Admin
   still needs local TOTP. Repeat for the other provider to bind both to the same
   approved local account.

## 6. Check operation and common failures

`workspace-check` validates startup configuration without external requests. Its
`production_ready: false` concerns broad independently verified multi-user
production gates; it does not require public hosting or prevent local operation.
Keep Local enabled for offline use and provider outages. External sign-in needs
internet at the time it runs; Local does not silently bypass a disabled method.

| Issue | Check |
| --- | --- |
| Redirect mismatch / AADSTS50011 | Exact hostname, port, path, platform and configured client/tenant; restart after changes |
| Five-minute approval expired | Repeat provider verification; never substitute email or an unsigned token |
| Provider verified but still denied | Approve through the OS command; restart, then sign in again |
| MFA fails | Correct authenticator, synchronized clock and fresh unused code |
| Provider secret rejected | Secret value, owner-private file, expiry and correct registration |
| No internet | Use enabled Local; optional Google/Entra will fail closed |
| Localhost cannot be reached | Runtime status, port conflict, WSL/Desktop integration; keep loopback binding |

Do not put passwords, seeds, client secrets or tokens in Git, screenshots, chat
or command arguments. Keep private backups under controlled custody. See
[authentication details](UNIFIED_AUTHENTICATION.md),
[recovery](WORKSPACE_RECOVERY.md) and [remaining scope](PRODUCTION_COMPLETION.md).
Live Google/Entra verification is still pending real registrations and cannot
be inferred from passing owned fixtures. Actual WSL2/Desktop acceptance also
requires that runtime to be available.
