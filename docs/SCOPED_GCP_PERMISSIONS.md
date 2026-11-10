# Scoped GCP caller permission check

`gcp-permission-check` queries which of a small, explicitly selected set of
project permissions the supplied caller token is reported to have. It first
matches the exact project number, ID, direct parent and ACTIVE state, then calls
Resource Manager v3 `testIamPermissions`. It never exercises the tested
permissions or changes IAM policy or project resources. Core installation is
sufficient; no SDK, gcloud, credential discovery or login is used.

This complements [resource inventory](SCOPED_GCP_INVENTORY.md); that command's
GET-only behavior is unchanged. The new command is separate from workflow
adapters. Generic bounty observation remains HEAD/GET-only.

## Prepare

Obtain written permission for the exact project and two API calls. Save the
contract below in a private approved directory. Replace the example identifiers,
permission reference, parent and timezone-aware expiry within 24 hours.

```json
{
  "schema_version": 1,
  "provider": "gcp",
  "project_id": "replace-project-id",
  "project_number": "123456789012",
  "expected_parent": "folders/123456789",
  "authorization_reference": "REPLACE_WITH_WRITTEN_PERMISSION_REFERENCE",
  "acknowledged_authorization": true,
  "expires_at": "REPLACE_WITH_TIMEZONE_AWARE_EXPIRY_WITHIN_24_HOURS",
  "permissions": [
    "resourcemanager.projects.get",
    "resourcemanager.projects.getIamPolicy",
    "resourcemanager.projects.setIamPolicy"
  ],
  "interval_seconds": 0.5
}
```

Exactly these fields are accepted. `expected_parent` is an exact canonical
`folders/NUMBER`, `organizations/NUMBER`, or null for no parent. The numeric
project number has no leading zero. A project ID uses the same bounded lowercase
format as resource inventory. Input is capped at 16 KiB.

Choose 1–5 unique permission names from this fixed set:

| Permission suffix after `resourcemanager.projects.` | Query subject |
| --- | --- |
| `get` | Project metadata read |
| `getIamPolicy` | Project IAM policy read |
| `setIamPolicy` | Project IAM policy change capability, queried only |
| `update` | Project update capability, queried only |
| `delete` | Project deletion capability, queried only |

Wildcards, other permissions and arbitrary request bodies are rejected. The
command's only POST is the fixed `:testIamPermissions` query on
`cloudresourcemanager.googleapis.com:443`. It cannot send `setIamPolicy`, project
updates/deletes or requests to a caller-supplied URL.

Save a separate temporary credential JSON, capped at 32 KiB:

```json
{
  "access_token": "REPLACE_WITH_EXPLICIT_TEMPORARY_OAUTH_ACCESS_TOKEN",
  "expires_at": "REPLACE_WITH_TIMEZONE_AWARE_TOKEN_EXPIRY_WITHIN_24_HOURS"
}
```

Use a dedicated caller permitted to read the project context and invoke the
permission query with a suitable OAuth scope. See Google's [query API and
supported scopes](https://docs.cloud.google.com/resource-manager/reference/rest/v3/projects/testIamPermissions).
If context cannot be retrieved and matched, no permission query is sent; all
permission values remain unknown. No token refresh, impersonation, metadata
credential access, quota-project header or API enablement is performed.

## Run

```bash
export HUNTERQA_APPROVED_ROOTS=/absolute/private/assessment
hunterqa gcp-permission-check \
  --input /absolute/private/assessment/gcp-permissions.json \
  --credentials /absolute/private/assessment/gcp-token.json \
  --out /absolute/private/assessment/gcp-permissions-01.json --authorized
```

On PowerShell, set `$env:HUNTERQA_APPROVED_ROOTS = 'C:\private\assessment'`
and use one command line. The destination must be new under an existing approved
parent. It is reserved before traffic. Rejected inputs can leave an empty file;
choose a new filename after correcting them. Do not commit credential/evidence
files to the repository.

There are at most two requests with a 0.5–5 second interval: one fixed context GET
and one fixed permission POST. DNS must yield only public addresses; the selected
address is pinned and TLS certificate/hostname verification remains required.
Authorization is rechecked before calls, after DNS and after TLS before bearer
transmission. Redirects, retries, compression and fallback are unsupported.
The response caps are one MiB for context and 16 KiB for permissions, with a
five-second socket inactivity timeout rather than a process-wide deadline.

With `HUNTERQA_QUOTA_LEDGER`, two operations and an active slot are reserved
upfront, even if context fails. Units are not refunded; the slot is released and
cleanup confirmation recorded. See [shared quotas and recovery](NATIVE_SHARED_QUOTAS.md).

## Read the result

Each requested permission has `provider_reported_granted`:

- `true`: included in the accepted provider response.
- `false`: absent from that successful response's permission subset. An omitted
  `permissions` field is the provider's empty repeated field, not a transport error.
- `null`: no accepted query response, including context mismatch, invalid response,
  401/403/404/429, timeout, authorization or quota stop. These are never negative
  permission evidence.

Only a successful bounded 200 response with unique names drawn from the requested
set completes the query. Other permission names, duplicate names, unsupported
fields, malformed JSON and oversized data are rejected as a whole. See Google's
[response definition](https://docs.cloud.google.com/resource-manager/reference/rest/Shared.Types/TestIamPermissionsResponse).

`permission_query_completed` describes this subset only. `principal_identity_verified`,
`effective_permissions_verified` and `owner_grant_verified` remain false, and
findings remain empty. The token subject is not introspected or independently
matched to an operator/owner. No actual operation is attempted to confirm a
grant. IAM conditions, deny policies, organization policies, other resources and
other principals are not independently evaluated. Context and query are sequential,
not an atomic snapshot; results can change and in-flight work can finish after stop.

Reports retain public permission names, hashed project references, status/body
size/digests and a path-free quota receipt. Tokens, raw project/parent values,
provider error details and response bodies are withheld. Hashes do not establish
provenance or conceal guessable identifiers. Custom Python transports remain
trusted caller code, not an isolation boundary.

Owned controls include an actual TLS-verified loopback GET/POST exchange plus
positive/negative/unknown responses, scope mismatches, malformed responses,
credential changes, public-address admission, pre-bearer stops and quota
conservation. No real Google account or project is assessed by these tests.
Representative provider-account evaluation and complete effective-access and
multi-user production readiness remain unfinished.
