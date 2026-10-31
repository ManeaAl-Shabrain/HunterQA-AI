# Shared quotas for native assessment commands

The optional local ledger now covers the four native commands below as well as
the existing workflow coordinator. Cooperating processes on one trusted host
reserve from the same request budget and active-run limit before target traffic.
This does not add tenant isolation, verified owner grants, OS isolation or
distributed enforcement.

## Configure every cooperating process

Use an existing private approved directory on a local filesystem:

```bash
export HUNTERQA_APPROVED_ROOTS=/absolute/private/assessment
hunterqa quota-init --ledger /absolute/private/assessment/quota.sqlite3 \
  --max-requests 100 --max-active-runs 2 \
  --expires-at REPLACE_WITH_UTC_EXPIRY_WITHIN_24_HOURS --authorized
export HUNTERQA_QUOTA_LEDGER=/absolute/private/assessment/quota.sqlite3
```

On PowerShell set `$env:HUNTERQA_QUOTA_LEDGER = 'C:\private\assessment\quota.sqlite3'`
and set `HUNTERQA_APPROVED_ROOTS` to its containing private approved root.
No new command flags are needed. Written authorization, scope and individual
budget checks remain required.

| Entry point | Upfront reservation | Active checks |
| --- | --- | --- |
| `workflow-run` | Existing entire protocol budget, including zero for offline work | Existing coordinator and worker supervision |
| `tls-service-inspect` | 1 connection/handshake operation | Before/after DNS, before TCP and TLS |
| `udp-dns-inspect` | 1 DNS question | Before UDP connect and immediately before send |
| `azure-resource-inventory` | `1 + max_pages` GET operations | Before calls, after DNS/TLS before bearer transmission |
| `gcp-resource-inventory` | `1 + max_pages` GET operations | Before calls, after DNS/TLS before bearer transmission |

These are reserved operations, not delivered requests, packets or bytes. DNS
resolution, TLS messages and local database I/O are not separate units. Legacy
`bounty-*`, `engagement-*`, separate labs and custom caller code are not
automatically covered by this extension. This is not a universal network firewall.

## Reservations, stopping and recovery

Invalid scope/credential inputs are rejected before admission and do not consume
a reservation. With a configured ledger, an atomic transaction checks its exact
configuration, expiry/stop state, remaining budget and active slots. The native
command reserves its maximum before DNS/target transport. For example, Azure with
`max_pages: 5` needs six units even when only two GETs are eventually completed.

The full reservation is never refunded after success, failure, cancellation or
an empty result. The active slot is released after normal completion, an early
return or an exception. A crash/forced termination can strand a slot. If cleanup
cannot confirm release, completed native evidence is preserved and the receipt
states `manual-reconciliation-required`.

```bash
hunterqa quota-status --ledger /absolute/private/assessment/quota.sqlite3
hunterqa quota-stop --ledger /absolute/private/assessment/quota.sqlite3 --authorized
hunterqa quota-reconcile --ledger /absolute/private/assessment/quota.sqlite3 \
  --run-id RESERVATION_ID --authorized
```

Never reconcile until the original process is confirmed dead. Releasing a live
client's slot can permit overlapping work. Recovery does not refund its charge
or replay work automatically.

Native guards stop later operations if the ledger stops/expires, its reviewed
configuration changes, a reservation is reconciled or the ledger becomes
inaccessible. Changing/removing the setting during an invocation also stops it;
it never silently switches to unmetered mode. Setting a ledger during an initially
unconfigured invocation stops that invocation's later operations too. A request
already in flight can finish; these checkpoints are not atomic revocation.

Admission denial raises an error before target traffic. Some pre-dispatch stops
also raise errors and can leave the create-only CLI output empty. Stops inside
native transport/collection loops report `outcome: quota-stopped`. Evidence
collected before a stop stays partial. No unavailable-ledger fallback is allowed.

## Native report receipt

The additive `shared_quota` field contains no ledger path or other clients' rows:

| Field | Meaning |
| --- | --- |
| `configured` | Whether a ledger was used |
| `reservation_id` | Random local reference for explicit crash recovery |
| `reserved_requests` | Full charged maximum, zero if unconfigured |
| `configuration_sha256` | Reviewed configuration hash, not a signature or owner proof |
| `reservation_released` | Confirmed release; false on cleanup failure, null if unconfigured |
| `release_state` | `released`, `manual-reconciliation-required` or `not-configured` on completion |
| `charge_policy`, `scope` | No refunds; cooperating host-local processes |

Existing workflow reports keep their original quota format. Local receipts and
hashes do not independently authenticate the database owner or contents.

## Trust and validation limits

The CLI, environment and database OS owner remain trusted. Someone who can edit
source, omit the setting before invocation, alter rows or choose another ledger
can bypass this cooperative mechanism. It is not an authorization service or a
secure multi-user boundary. Unconfigured native commands keep their individual
limits and report `configured: false`.

Use one local filesystem on one host with reliable SQLite locking. UNC/share
paths are rejected before filesystem lookup; mapped drives and NFS mounts cannot
be reliably identified by these portable checks and remain unsupported. A shared
network file does not create a distributed quota service. See SQLite's
[network filesystem caveats](https://www.sqlite.org/useovernet.html).

Owned tests cover real loopback TLS/UDP, cloud contract gates, four independent
competing processes, workflow/native slot sharing, stop/configuration changes,
early returns, no refunds and cleanup failure. They do not establish adversarial
tenant isolation or representative distributed production readiness. See the
[expansion tracker](EXPANSION_PROGRESS.md).
