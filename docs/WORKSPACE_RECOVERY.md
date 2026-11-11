# Offline workspace backup and recovery

Use these commands for one private workspace at its **original absolute paths**.
They do not migrate tenants or merge databases. Stop its server and every CLI or
external process that can write its evidence before starting. The server lease
excludes another supported server; it cannot stop unrelated filesystem writers.

Backups contain account password hashes, evidence, local session/edge keys and
any configured OIDC client secret. They are **not encrypted**. Use an existing
owner-private directory outside Git, the control root and every registered
workspace, on encrypted storage with a reviewed retention/access policy. On
POSIX the backup directory must be mode 0700 and the archive is created 0600;
Windows ACLs require deployment-level validation. Do not attach private backups
to issues or pull requests.

## Create and check

Set `HUNTERQA_OPERATOR_ROOT` to the workspace's private control root as usual.
Use a new filename for each backup; existing archives are never overwritten.

```bash
hunterqa workspace-recover --config /var/lib/hunterqa/alpha-control/alpha/workspace.json --authorized
hunterqa workspace-backup --config /var/lib/hunterqa/alpha-control/alpha/workspace.json \
  --out /srv/hunterqa-backups/alpha-2026-11-12.zip --authorized
```

`workspace-recover` is optional if no scans are interrupted. Under the offline
lease it marks queued/running source scans failed and records the maintenance
action in the operator audit chain. It never executes or replays a scan. Backups
refuse unresolved queued/running work; completed results remain unchanged.

Retain the returned `sha256` separately, through a trusted private channel. Set
`BACKUP_SHA256` to that 64-character lowercase value, then verify:

```bash
hunterqa workspace-backup-check --backup /srv/hunterqa-backups/alpha-2026-11-12.zip \
  --sha256 "$BACKUP_SHA256"
```

This checks archive structure, the supplied whole-file digest, exact manifest
membership and each file digest without extracting or contacting a network.
It proves file consistency against the supplied digest, **not backup ownership**,
database semantics, confidentiality or production readiness. A database/backup
owner can forge the files and their digests. Use only backups from a trusted
custodian; database integrity and workspace bindings are also checked before
restored data is published.
Custom triggers, views and virtual tables are unsupported and rejected before
account or identity changes; they cannot undo the recovery safeguards.

The format is intentionally bounded: 2,000 source entries, 64 MB per file,
256 MB of file content, and a 1 MB manifest. ZIP compression, ZIP64/multi-volume
archives, links/reparse points, duplicate/case-colliding names, unsafe paths,
unexpected control dependencies and oversized directories are rejected. SQLite
databases use bounded online snapshots rather than copying WAL/journal files.
Changed evidence prevents a successful manifest from being written. A failed
operation can leave an invalid partial archive; retain its error and choose a
fresh filename after fixing the cause.

## Restore without overwriting data

Keep the server stopped. Preserve the current data/control directories separately
before recovery. The original data root must exist and be **empty**; the original
per-workspace control directory must be **absent**. The private parent control
root must exist. The archive's workspace ID and both absolute paths must match
the explicit destination and current control root. Another workspace's registry
entry cannot be replaced or overlapped. An unrelated or populated destination is
rejected; this command does not remove existing data.

```bash
hunterqa workspace-restore --backup /srv/hunterqa-backups/alpha-2026-11-12.zip \
  --sha256 "$BACKUP_SHA256" --workspace-id alpha --root /srv/hunterqa/alpha --authorized
```

Restore validates the entire archive before staging files privately. It checks
database integrity and matching workspace/identity bindings, then:

- preserves reports, evidence, local audit history and OIDC configuration;
- disables every restored account and requires a different password before it
  can be enabled again;
- revokes all local sessions and pending OIDC attempts;
- changes the identity instance and updates the dashboard's binding together;
- rotates the local session key and default/configured gateway keys;
- marks any recovered queued/running scan failed without execution;
- records the recovery and source archive digest in the operator audit chain.

Review restored roles, subject bindings and OIDC client credentials against
current records; an old backup can contain old account and provider settings.
Review/reset the intended administrator, using the private prompt:

```bash
hunterqa operator-update --database /var/lib/hunterqa/alpha-control/alpha/operators.sqlite3 \
  --username admin --enable --reset-password --authorized
hunterqa workspace-check --config /var/lib/hunterqa/alpha-control/alpha/workspace.json
```

Until an administrator is deliberately re-enabled, startup/status checks fail
closed because no active administrator exists. Other restored accounts remain
disabled until individually reviewed and enabled with different passwords.
Update the gateway with its newly generated private edge key before starting
the server. OIDC client secrets are preserved, not rotated at the provider;
rotate them through the provider when required. Test a fresh sign-in, old-session
denial and evidence/report access before resuming assessments.

Publication renames the staged data and control directories separately. It is
not a cross-directory/filesystem atomic transaction. If publication or registry
commit fails, keep the original archive, inspect both destinations and resolve
the interrupted recovery before retrying. Existing data is never automatically
deleted. Network filesystems, hostile same-OS-user writers and coordinated
multi-host recovery are outside this model.

## Acceptance scope

Owned tests exercise actual CLI backup/check/restore, forced credential renewal,
SQLite WAL capture, retained reports, revoked sessions and OIDC attempts, changed
evidence, malformed archive controls and key rotation. These controls do not
replace independent restore drills, real TLS/IdP tests, storage quotas, monitoring,
OS/container isolation or distributed workers in the intended deployment.
`workspace-check --require-production` still exits 2. See
[completion gates](PRODUCTION_COMPLETION.md) and [workspace setup](PRODUCTION_WORKSPACES.md).
