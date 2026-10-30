# Scoped GCP resource inventory

`gcp-resource-inventory` checks one project's identity and immediate parent using
Resource Manager v3, then reads bounded Cloud Asset Inventory v1 pages. It requires
an explicit temporary token and exports hashed asset references with selected
public kind labels. It does not calculate effective permissions or establish a
complete inventory. No Google SDK or optional extra is required.

## Private inputs

Obtain written permission for the exact project and an appropriate temporary
Google Cloud access token through the owner's approved authentication process.
The Resource Manager and Cloud Asset Inventory APIs must already be available,
and the identity must have the owner-approved API read permissions. The command
does not enable APIs or grant permissions. It never invokes gcloud, discovers ADC
or environment credentials, accesses metadata, refreshes tokens or impersonates
service accounts. It sends no quota-project header. Provider authentication
handles token acceptance; the supplied expiry is an operator bound, not an
independently verified token claim.

Save this contract in an existing private approved directory. Replace placeholders:

```json
{
  "schema_version": 1,
  "provider": "gcp",
  "project_id": "REPLACE_WITH_CANONICAL_PROJECT_ID",
  "project_number": "REPLACE_WITH_NUMERIC_PROJECT_NUMBER",
  "expected_parent": "REPLACE_WITH_folders/NUMBER_OR_organizations/NUMBER",
  "read_time": "REPLACE_WITH_APPROVED_UTC_SNAPSHOT_TIME_WITHIN_THE_PAST_HOUR",
  "authorization_reference": "REPLACE_WITH_WRITTEN_PERMISSION_REFERENCE",
  "acknowledged_authorization": true,
  "expires_at": "REPLACE_WITH_TIMEZONE_AWARE_ISO_EXPIRY_WITHIN_24_HOURS",
  "max_pages": 2,
  "page_size": 50,
  "max_resources": 100,
  "interval_seconds": 1
}
```

Use the exact immediate folder or organization in `expected_parent`, or JSON
`null` for a project without one. This does not independently verify an ultimate
organization when the immediate parent is a folder. Project IDs use 6–30 lowercase
ASCII letters, digits and hyphens, beginning with a letter and ending with a
letter/digit. Numeric IDs must be canonical positive decimal strings, at most
20 digits. Scope fields, bounds and protocol are fixed; unknown fields are rejected.

Save a separate credential file and protect both files with OS access controls:

```json
{
  "access_token": "REPLACE_WITH_TEMPORARY_GOOGLE_CLOUD_ACCESS_TOKEN",
  "expires_at": "REPLACE_WITH_ACTUAL_TOKEN_EXPIRY_WITHIN_24_HOURS"
}
```

Both windows must be future timezone-aware times within 24 hours. Limits are
1–5 asset pages, page size 1–100, 1–500 retained assets and spacing 0.5–5 seconds.
Never commit the credential file or put its token on the command line.

## Run

```bash
export HUNTERQA_APPROVED_ROOTS=/absolute/private/assessment
hunterqa gcp-resource-inventory \
  --input /absolute/private/assessment/gcp-contract.json \
  --credentials /absolute/private/assessment/gcp-token.json \
  --out /absolute/private/assessment/gcp-01.json --authorized
```

On PowerShell set `$env:HUNTERQA_APPROVED_ROOTS = 'C:\private\assessment'`
and put the command on one line. The destination must be new and its parent must
exist inside approved roots. Output is reserved before traffic; invalid inputs
can leave an empty file. Choose a new name after correcting them. Exit success
means a receipt was saved; inspect its `outcome`.

## What is collected

Only two fixed hosts receive GET requests:

1. `cloudresourcemanager.googleapis.com`: project number, ID, direct parent and
   ACTIVE state must match before asset listing. A fixed field projection requests
   only these context fields.
2. `cloudasset.googleapis.com`: RESOURCE assets under `projects/PROJECT_NUMBER`,
   with a fixed projection of name, type, ancestry, read time and continuation
   token. No resource-data or IAM content is requested in that projection. If
   extra fields are nevertheless returned, they are not retained or followed.

The budget is one context GET plus at most `max_pages` asset-list GETs. Opaque
page tokens are bounded and encoded into a locally built URL on the same project
endpoint. Even a URL-shaped token is data, not a destination. There are no
redirects, retries, API enablement, resource mutations, folder/organization
enumeration or data-plane requests. A 401/403/429 stops collection without retry.

The contract's `read_time` must be a UTC timestamp ending in `Z`, within the past
hour. Fractional seconds can have 3, 6 or 9 digits. Every asset request uses that
same instant from the first page onward, keeping pagination parameters stable.
Every response must report an equivalent `readTime`, including nanosecond value;
equivalent fractional precision is normalized without rounding nanoseconds away.
This is a local freshness bound and metadata consistency check, not independent
freshness or atomicity proof; Cloud Asset Inventory indexing can still be volatile.

Every asset needs bounded numeric ancestry beginning at the approved project,
followed by its approved direct parent where present. Conflicting project names,
unexpected ancestry and unsupported identifier shapes invalidate the whole page
before retention. Bucket names without an embedded project are bound by ancestry.
Names remain case-sensitive when hashed. Duplicates are counted and omitted.

## Results and boundaries

| Outcome | Meaning |
| --- | --- |
| `visible-pages-exhausted` | No continuation remained without local truncation |
| `page-limit`, `resource-limit` | A configured bound stopped collection |
| `project-context-mismatch` | No asset-list GET followed the unexpected context |
| `snapshot-mismatch` | Reported read time changed; that page was not retained |
| `page-token-rejected`, `pagination-loop` | Invalid or repeated continuation stopped collection |
| `authorization-stopped` | Input changed, disappeared or expired |
| `http-error` | A non-200 response stopped collection |
| `invalid-response`, `transport-rejected` | Parsing, scope, TLS, transport or size checks prevented usable evidence |

Receipts include status, counts, read time and hashes, not tokens, credential
hashes, raw names, IDs, ancestors, labels, properties, URLs or exception messages.
Asset/type hashes and a public kind label are retained. Hashes support correlation;
they do not anonymize guessable inputs or independently establish provenance.
Missing `assets` on a valid ProtoJSON page is interpreted as an empty repeated
field. Attempt counts are not delivery proof; an attempt can have null response
fields. Completed counts refer to captured bounded responses.

`inventory_complete`, `effective_permissions_verified` and `owner_grant_verified`
remain false. Matching context and exhausted pages do not prove ownership,
complete API coverage, caller visibility, IAM conditions/denies, full hierarchy
isolation or accurate inventory during indexing delays. No automatic vulnerability
findings, IAM/organization-policy assessment or service configuration checks occur.

Inputs are fingerprinted and rechecked before calls, after DNS and after TLS
before bearer transmission. Change/remove an input to stop between calls; a new
token requires a new invocation. In-flight requests can complete after expiry.
These are local attestations, not independently authenticated grants or atomic
revocation. Quotas are invocation-local, without cross-host enforcement.

The transport admits global DNS answers only, pins a numeric address, verifies
the original host with platform TLS trust, uses TLS 1.2 minimum/strict X.509, and
suppresses HTTP debug and `SSLKEYLOGFILE`. Proxies and custom endpoints are not
used. Compressed bodies are rejected. Limits are one MiB per response, 500 input
rows, 20,000 parsed nodes and depth 32. The five-second socket timeout is an
inactivity limit, not an independent process deadline or OS isolation.

Tests use synthetic contracts and owned HTTPS with a fixture CA and controlled
DNS/dial mapping for both hosts. They cover scope/ancestry, pagination, nanosecond
read-time comparison, case sensitivity, token routing, TLS, privacy and bounds.
No real GCP project was assessed. Field effectiveness remains unverified.

References: [Projects Get](https://docs.cloud.google.com/resource-manager/reference/rest/v3/projects/get),
[Assets List](https://docs.cloud.google.com/asset-inventory/docs/reference/rest/v1/assets/list),
[Asset schema](https://docs.cloud.google.com/asset-inventory/docs/reference/rest/v1/Asset)
and [response field filtering](https://docs.cloud.google.com/apis/docs/system-parameters).
See the [expansion tracker](EXPANSION_PROGRESS.md) for remaining work.
