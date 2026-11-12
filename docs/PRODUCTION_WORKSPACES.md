# Separate workspaces and controlled serving

For new deployments, use [the shared Linux profile](LINUX_DEPLOYMENT.md) and
[unified Local/Google/Entra authentication with Admin MFA](UNIFIED_AUTHENTICATION.md).
The single-provider setup below remains a compatibility profile. The new
`auth_config` replaces its `oidc_config`, and `--require-auth-policy` prevents
accidentally serving the new deployment without the unified policy.

Use a separate workspace for each group allowed to share projects, findings and
evidence. Each workspace has its own operator database, session key, dashboard
database, approved source/evidence root and process. Accounts within one workspace
can read that workspace according to the existing viewer/analyst/admin roles;
this is not private ownership of each project by an individual user.

Application separation has owned cross-process regression tests. It is not an OS
sandbox. Untrusted groups still need separate OS accounts/containers, storage
quotas and independently tested network policy. The legacy shared dashboard is
not a hosted multi-user deployment mode.

## Create a workspace

Install current source with `python -m pip install -e '.[identity,production]'`.
Choose existing empty private directories outside Git. On POSIX use mode 0700;
on Windows configure and verify owner-only ACLs before deployment.

```bash
export HUNTERQA_OPERATOR_ROOT=/var/lib/hunterqa/alpha-control
hunterqa workspace-init --workspace-id alpha --root /srv/hunterqa/alpha \
  --username admin --authorized
```

The command prompts for the initial local administrator password. A dedicated
automation can supply `HUNTERQA_OPERATOR_PASSWORD`; never put it in a command
argument, commit it or paste it into a chat. Initialization displays configuration
and database paths, never generated session/edge keys. Use `operator-add` with
the returned operator database path to add approved workspace members.

The private configuration is `alpha-control/alpha/workspace.json`. It contains
the registered root, optional evidence bindings, optional OIDC configuration and
optional HTTPS edge settings. Existing roots with files are not adopted. Duplicate
IDs and overlapping registered roots are rejected. Dashboard data is bound to
both workspace ID and identity-store instance; it cannot silently become a
different workspace or an unauthenticated legacy database.

```bash
hunterqa workspace-check --config /var/lib/hunterqa/alpha-control/alpha/workspace.json
hunterqa workspace-serve --config /var/lib/hunterqa/alpha-control/alpha/workspace.json --port 8081
```

`workspace-serve` uses Waitress on **127.0.0.1 only**, with four HTTP threads,
64 connections, 8-KiB headers and a 1-MiB request-body cap. Its host-local OS file
lease excludes a second supported server for the same workspace and releases on
process exit. It does not work as a cross-host lock or distributed scheduler.
Interrupted queued/running scans are marked failed on supported server restart;
they are not automatically replayed. Review evidence and explicitly authorize a
new scan. There are at most four admitted source-scan threads per workspace
process and one executing scan at a time. Capacity rejection is visible as 429.

Each process fixes its configuration. A second different workspace or a fallback
to legacy mode is rejected. Ambient report/root/session environment settings do
not replace its private bindings. Shared local AI is disabled in workspace mode
to avoid sending workspace evidence to a common model service. Operator CLI and
the OS administrator remain trusted and can bypass application boundaries.

## HTTPS gateway profile

For a remote workspace, first configure [operator OIDC](OPERATOR_SSO.md), register
the exact HTTPS callback, and save the client secret privately. Set these private
workspace configuration fields (all other generated fields stay present):

```json
{
  "oidc_config": "/var/lib/hunterqa/alpha-control/alpha/oidc.json",
  "public_origin": "https://alpha.example.test",
  "edge_key_file": "/var/lib/hunterqa/alpha-control/alpha/edge.key"
}
```

The gateway profile requires SSO-only login, a confidential OIDC client, a
host-only Secure cookie and an exact HTTPS origin. It accepts only a loopback
upstream peer with the workspace's 256-bit edge key, exact Host, HTTPS protocol
and one canonical client address. It strips forwarding/key headers before Flask
sees the request. A direct or forged request is rejected before Flask routing.
Forwarded data is not trusted through ProxyFix or a wildcard trusted-proxy setting.

The edge must overwrite incoming forwarding/key headers, rather than append
client input. Keep the backend bound to loopback. Examples in `examples/deploy/`
are templates with placeholders, not a validated deployment. Install the real
certificate and protect the gateway configuration/key. Do not expose the backend
directly or forward its secret to a browser. Redact authorization callback query
parameters from logs. The server deliberately preserves raw proxy headers for
its own authenticated admission layer; see [Waitress settings](https://docs.pylonsproject.org/projects/waitress/en/latest/arguments.html).

Use one OS identity and private control root per untrusted workspace. The example
systemd unit supplies filesystem/process restrictions; it does not implement an
egress allowlist, distributed workers, cross-host quotas or a provider MFA policy.
Test denied access between deployed accounts/containers, allowed IdP backchannels,
blocked unintended egress and credential/log handling in the actual environment.

## Readiness and operations

`workspace-check` validates startup configuration without contacting a target.
It reports unverified production gates. `--require-production` exits 2 while
those gates remain unverified; configuration or a template does not self-certify
the deployment. See [the completion gates](PRODUCTION_COMPLETION.md).

Use [offline workspace recovery](WORKSPACE_RECOVERY.md) to snapshot both stores
and evidence privately, verify the archive and restore only the original empty
paths. Recovery disables accounts, requires renewed credentials, revokes sessions
and rotates local/gateway keys. Review restored roles/provider settings, re-enable
the intended administrator and update the gateway key before restarting. This
does not rotate the provider's client secret or end its global sessions.

The bounded queue is not a durable distributed worker system. Process failure,
disk exhaustion and independent job deadlines still need deployment-level
supervision, alerting, resource/storage quotas and tested recovery. Network filesystems
are unsupported. Windows ACLs and the real TLS gateway have not been independently
verified by the owned application tests.
