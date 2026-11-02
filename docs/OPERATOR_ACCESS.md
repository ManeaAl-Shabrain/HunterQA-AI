# Authenticated local operator access

**Post-v1.3.0 development.** HunterQA can require named accounts for its local
dashboard, with viewer, analyst and administrator roles and server-side revocable
sessions. These accounts control **HunterQA access**. They are separate from target
test accounts and do not grant permission to assess an organization or website.

This is one shared organization workspace on a trusted local host. Loopback peer
and Host checks remain enforced, and proxy headers are not trusted. There is no
hosted deployment, SSO, tenant/project segregation, verified owner grant, OS sandbox
or distributed RBAC enforcement. The CLI and filesystem OS owner remain trusted.
Do not expose this dashboard through a reverse proxy or use a shared OS account
with untrusted people. Production multi-user readiness remains false.

Optional [native shared quotas](NATIVE_SHARED_QUOTAS.md) coordinate selected
commands on this host; they do not change permissions or add tenant isolation.

## Permissions

| Role | Read saved workspace data | Register approved projects / start local source scans / review triage | Read operator state and auth-audit consistency |
| --- | --- | --- | --- |
| Viewer | Yes, across the shared organization workspace | No | No |
| Analyst | Yes | Yes, with existing CSRF, scope and typed authorization gates | No |
| Administrator | Yes | Yes, with the same gates | Yes |

Account creation, role changes, password resets and disabling accounts use local
OS-administrator CLI commands, not public signup or web-management endpoints.
All HTTP mutations are denied unless they belong to the explicit permitted
endpoint list; even an administrator cannot invoke a new unreviewed mutation route.
Viewer write forms are hidden and direct write requests are rejected server-side.

## Establish a private local installation

Use current source containing the `operator-*` commands. The original v1.3.0 ZIP
does not include this feature. Start with two **separate**, existing private roots:

```bash
mkdir -p "$HOME/hunterqa-control" "$HOME/hunterqa-cases"
chmod 700 "$HOME/hunterqa-control" "$HOME/hunterqa-cases"
export HUNTERQA_OPERATOR_ROOT="$HOME/hunterqa-control"
export HUNTERQA_APPROVED_ROOTS="$HOME/hunterqa-cases"

hunterqa operator-init \
  --database "$HUNTERQA_OPERATOR_ROOT/operators.sqlite3" \
  --username admin --authorized

hunterqa operator-add \
  --database "$HUNTERQA_OPERATOR_ROOT/operators.sqlite3" \
  --username reviewer --role viewer --authorized

hunterqa operator-add \
  --database "$HUNTERQA_OPERATOR_ROOT/operators.sqlite3" \
  --username assessor --role analyst --authorized
```

Each command prompts twice for a new password without echoing it. Passwords must
be 14–256 characters; use unique passwords stored through your approved process.
There is no command-line password argument. For controlled automation only,
`HUNTERQA_OPERATOR_PASSWORD` supplies the value; remove it immediately afterward.
Command output never includes passwords or password hashes.

The operator root must not overlap an assessment/source root in either direction.
It must also stay outside Git checkouts and the installed HunterQA package so
operator secrets cannot be accidentally created in publishable source folders.
On POSIX, the control directory must be owned by the server OS account with mode
0700, and its database/key files must be owned by that account with mode 0600.
Symlink components and UNC control roots are rejected. On Windows, restrict the
directory using OS ACLs yourself; Python file modes do not establish ACL isolation.
No source project should contain the control directory or its secrets.

## Configure a persistent session key and start

```bash
hunterqa operator-secret \
  --out "$HUNTERQA_OPERATOR_ROOT/session-key" --authorized

export HUNTERQA_OPERATOR_DB="$HUNTERQA_OPERATOR_ROOT/operators.sqlite3"
export HUNTERQA_OPERATOR_SESSION_KEY_FILE="$HUNTERQA_OPERATOR_ROOT/session-key"

hunterqa assessment-readiness
python run.py
```

The key command creates a private random key file once and prints only its path.
Keep it persistent across restarts; existing files are never overwritten. A strong
`HUNTERQA_SECRET_KEY` (or legacy equivalent) is an alternative, but do not configure
an environment secret and a session-key file together. Operator mode rejects
missing/short keys, invalid databases and overlapping roots at startup.

Open the local URL printed by `run.py` and sign in. Login does not start a scan.
Registering/scanning still requires the exact approved project root and the existing
authorization acknowledgement. Workflow execution remains a local CLI operation;
web roles do not replace protocol/execution fingerprints or customer permission.

Once enabled, authentication is recorded as required in the dashboard history
database. Removing `HUNTERQA_OPERATOR_DB` does **not** silently return that same
database to anonymous mode; startup refuses the missing configuration. Restore the
configuration or perform an explicit, separately reviewed OS-admin migration.
Do not edit the sticky marker to bypass authentication.

## Revoke access and inspect state

```bash
hunterqa operator-status --database "$HUNTERQA_OPERATOR_DB"
hunterqa operator-audit --database "$HUNTERQA_OPERATOR_DB"

hunterqa operator-update --database "$HUNTERQA_OPERATOR_DB" \
  --username reviewer --disable --authorized

hunterqa operator-update --database "$HUNTERQA_OPERATOR_DB" \
  --username assessor --role viewer --authorized

hunterqa operator-update --database "$HUNTERQA_OPERATOR_DB" \
  --username assessor --reset-password --authorized
```

Role, enabled-state and password changes revoke that account's existing sessions.
Logout revokes its server-side session, including replay of a copied signed cookie.
Sessions have a hard eight-hour lifetime and are checked against current account
state on every request. At most eight sessions per account are retained; a new
login replaces the oldest when necessary. The last active administrator cannot be
disabled or demoted, including concurrent updates. Keep an OS-admin recovery path.

Incorrect and unknown-account logins use the same generic failure message. Login
attempt limits persist across app restarts: 10 per username, 60 per loopback peer
and 200 overall in a ten-minute fixed window, including successful attempts.
Throttled attempts return 429; wait for the window rather than repeatedly retrying.
There is no password guessing or credential attack function.

Sessions contain an opaque random identifier; the database stores its hash.
Passwords use salted PBKDF2-HMAC-SHA-256 with one million iterations through
Werkzeug. Cookies are host-only, HttpOnly and SameSite=Strict. Local HTTP is still
the supported deployment; these settings do not establish internet-facing TLS or
remote multi-user security. No password, signing key, raw session identifier,
password hash or session-token hash is shown in the operator management page.

## Audit, backups and limits

Authentication decisions, OS-admin account changes and HTTP mutation permission
decisions are recorded in the separate operator database. A permitted mutation
event records the access decision, not successful completion of the underlying
scan or review. Read-only page views are not individually recorded there; existing
application/workflow audit logs remain separate.

`operator-audit` recomputes the hash-linked history. The database is capped at 64 MB
and 100,000 audit events; reaching capacity causes protected changes/sign-in to
fail closed. Preserve/export the database through OS administration before an
explicit rotation. No automatic audit deletion or account-database overwrite occurs.
The OS/control-directory owner can forge a consistent history; hashes are not an
independent signature or organization-owner verification.

Protect the operator database, dashboard database and signing key together in
backups. Restoring old state can restore old sessions/revocation state; rotate the
session key and perform reviewed account/session recovery before resuming access.
Test first with owned accounts. This layer does not replace independent grants,
hostile-tenant isolation, OS sandboxing or distributed quotas.

Design references: [OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
and [Flask web security](https://flask.palletsprojects.com/en/stable/web-security/).
These references inform the controls; they do not certify this implementation.
