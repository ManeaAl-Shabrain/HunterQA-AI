# Scoped Azure resource inventory

`azure-resource-inventory` reads the context of one commercial Azure subscription,
then bounded pages of generic ARM resources visible to a supplied temporary
token. It exports hashed resource references and selected public kind labels.
No Azure SDK or optional extra is needed. It does not assess effective permissions
or claim complete inventory.

## Prepare private inputs

Obtain written permission for the exact subscription and tenant. Obtain a
short-lived ARM token through your organization's approved sign-in process,
using a dedicated identity with owner-approved read access. This command never
runs Azure CLI, discovers credentials, uses managed-identity metadata, refreshes
tokens or modifies resources. ARM handles token acceptance; the command does not
decode or independently verify JWTs. The supplied expiry is an operator bound.

Save this contract in a private approved directory, replacing every placeholder:

```json
{
  "schema_version": 1,
  "provider": "azure",
  "subscription_id": "REPLACE_WITH_LOWERCASE_SUBSCRIPTION_UUID",
  "tenant_id": "REPLACE_WITH_LOWERCASE_TENANT_UUID",
  "authorization_reference": "REPLACE_WITH_WRITTEN_PERMISSION_REFERENCE",
  "acknowledged_authorization": true,
  "expires_at": "REPLACE_WITH_TIMEZONE_AWARE_ISO_EXPIRY_WITHIN_24_HOURS",
  "max_pages": 2,
  "page_size": 50,
  "max_resources": 100,
  "interval_seconds": 1
}
```

Save a separate credential file; never commit it or put the token on the command line:

```json
{
  "access_token": "REPLACE_WITH_TEMPORARY_ARM_BEARER_TOKEN",
  "expires_at": "REPLACE_WITH_ACTUAL_TOKEN_EXPIRY_WITHIN_24_HOURS"
}
```

Both files must be under `HUNTERQA_APPROVED_ROOTS`. Contracts accept exactly these
fields: canonical lowercase UUIDs, 1–5 pages, page size 1–100, 1–500 retained
resources and spacing 0.5–5 seconds. Both expiry windows must be future,
timezone-aware times within 24 hours. Protect private folders with OS access controls.

## Run

```bash
export HUNTERQA_APPROVED_ROOTS=/absolute/private/assessment
hunterqa azure-resource-inventory \
  --input /absolute/private/assessment/azure-contract.json \
  --credentials /absolute/private/assessment/azure-token.json \
  --out /absolute/private/assessment/azure-01.json --authorized
```

On PowerShell set `$env:HUNTERQA_APPROVED_ROOTS = 'C:\private\assessment'`
and put the command on one line. Output is create-only, reserved before network
activity. Invalid inputs can leave an empty file; correct them and choose a new
name. Exit success means a receipt was saved; inspect its `outcome`.

Only GETs to `management.azure.com:443` are allowed. Subscription Get with API
`2022-12-01` must return the expected subscription ID, resource ID and tenant ID
before Resources List with API `2021-04-01` is called. This verifies API-reported
subscription context, not principal tenant, ownership or an independent grant.
The request budget is one context GET plus `max_pages` resource-list GETs.

Continuation links must retain the exact HTTPS host and subscription list path,
fixed API version, one bounded `$skiptoken` and optionally the same `$top`.
Unsupported formats, extra parameters and repeated links stop collection.
No redirects or retries, including for 401/403/429, are followed. Azure can
disregard `$top`; local limits still apply.

Inputs are checked for changes and expiry before each call, after DNS and after
TLS before the bearer header. Change/remove either input to stop between calls.
Changing a token stops the invocation; a replacement requires a new invocation.
These checks are local controls, not atomic grant revocation. In-flight requests
can finish after expiry. A configured `HUNTERQA_QUOTA_LEDGER` reserves
`1 + max_pages` units and a slot before transport and is rechecked at these same
gates. See [native shared quotas](NATIVE_SHARED_QUOTAS.md) for release, stopping
and no-refund semantics. Cross-host enforcement remains unavailable.

## Results and limits

| Outcome | Meaning |
| --- | --- |
| `visible-pages-exhausted` | No continuation remained, without local truncation |
| `page-limit`, `resource-limit` | A configured bound stopped collection |
| `subscription-context-mismatch` | No resource GET followed the unexpected context |
| `next-link-rejected`, `pagination-loop` | An unsupported/repeated link stopped collection |
| `authorization-stopped` | Input changed, disappeared or expired |
| `http-error` | Non-200 response; status retained, no retry |
| `invalid-response`, `transport-rejected` | Parsing, scope, TLS, network or size checks prevented usable evidence |

Attempt receipts can contain null response fields when a later gate or transport
stops them. `requests_attempted` is not delivery proof. `requests_completed`
counts captured bounded responses. Duplicate resources are counted and omitted;
an invalid resource invalidates its whole page before retention.

Rows contain resource/group/type hashes and a public kind label for selected
common compute, storage, network, database, vault, app and container types;
others use `other`. Raw IDs, names, groups, tags, properties, bearer tokens,
credential hashes, continuation tokens, exception text and private paths are
withheld. IDs are case-normalized before hashing. Hashes permit correlation,
not anonymization of guessable values or independent provenance.

Ordinary ASCII subscription-level/resource-group IDs with nested type/name pairs
are supported. Encoded, Unicode, extension-provider and other unsupported shapes
can stop a page. This is not every Azure resource representation.

Exhausting visible pages does not establish completeness. Permissions, API
omissions, service behavior and concurrent changes can hide resources; there is
no point-in-time snapshot. `inventory_complete`, `effective_permissions_verified`
and `owner_grant_verified` remain false. There are no automatic findings,
RBAC/deny/PIM/condition calculations, configuration or data-plane assessments.

The native transport pins a globally admitted DNS address and verifies platform
TLS trust, TLS 1.2 minimum and strict X.509 policy. It ignores proxies, suppresses
HTTP debug output and does not apply `SSLKEYLOGFILE`. Private DNS answers and
sovereign/custom ARM hosts are unsupported. Each response is bounded to one MiB,
500 rows, 20,000 parsed nodes and depth 32; compression is rejected. Its five-second
socket timeout is an inactivity limit, not a process-wide deadline or OS isolation.

Tests use synthetic contracts and an owned loopback HTTPS server with a test CA
and controlled DNS/dial mapping. They exercise context, pagination, TLS/SNI,
bearer destination, limits, input changes, privacy and malformed data. No real
subscription was assessed. Representative cloud field effectiveness and GCP
runtime remain unfinished.

API references: [Subscription Get](https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/get?view=rest-resources-2022-12-01)
and [Resources List](https://learn.microsoft.com/en-us/rest/api/resources/resources/list?view=rest-resources-2021-04-01).
See the [expansion tracker](EXPANSION_PROGRESS.md) for wider remaining work.
