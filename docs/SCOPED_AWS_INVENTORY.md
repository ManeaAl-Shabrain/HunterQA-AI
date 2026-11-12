# Bounded AWS resource inventory

This extends the existing two-call AWS account adapter with separately approved
resource reads. It uses the SDK only for signing, the existing pinned TLS
transport/deadline components, encrypted assessment credentials, shared quotas,
existing cloud review rules and the shared report/history contract.

| Operation | Scope and output |
| --- | --- |
| STS GetCallerIdentity | Must match the exact approved account before any inventory call |
| EC2 DescribeInstances | One region; hashed instance IDs, state and public-address presence; selected running-instance IMDSv2 declarations |
| EC2 DescribeSecurityGroups | Owner account must match; hashed group IDs and selected broad-source administrative ingress declarations |
| S3 ListBuckets | General-purpose bucket names in the selected region, hashed; bucket configuration is not assessed |

No instance metadata, role assumption, SDK/CLI credential discovery, credential
refresh, endpoint override, resource mutation, bucket data, redirects or retries
are used. Ingress declarations are not proof of actual reachability. S3 directory
buckets, complete IAM, storage policies/encryption, logging, key management and
other AWS resource types remain outside this collector.

## 1. Prepare temporary credentials privately

Install `.[cloud,identity]` or use the shared deployment runtime. Obtain a dedicated
short-lived STS session through your normal approved process. The read policy
needs only `ec2:DescribeInstances`, `ec2:DescribeSecurityGroups` and
`s3:ListAllMyBuckets`, plus the caller identity operation. Use an approved region
condition where the service supports it. These list APIs may require `Resource:
"*"`; that does not require granting broad write or data access. Check your
organization's policies independently.

Create a separate vault with:

```bash
hunterqa assessment-session-create --purpose aws-signing \
  --out /private/aws-reader.json --key-file /private/aws-reader.key --authorized
```

Supply the same bounded stdin schema described in the
[session guide](SCENARIO_ASSESSMENTS.md), with these three actors:

| Actor | Exact origin for the example region |
| --- | --- |
| aws-sts | https://sts.amazonaws.com |
| aws-ec2 | https://ec2.us-east-1.amazonaws.com |
| aws-s3 | https://s3.us-east-1.amazonaws.com |

Each actor has empty `cookies` and `local_storage`, and exactly
`X-AWS-Access-Key-ID`, `X-AWS-Secret-Access-Key`, `X-AWS-Session-Token` in its
`headers`. All actors must contain the same reviewed temporary identity. These
values feed the signer; they are never sent as those HTTP headers. Long-lived
AKIA keys are rejected. Vault expiry must be within 24 hours.

Use the private secret root outside Git, assessment/source roots and the operator
control root, with 0700/0600 permissions. Do not put real keys in chat, commands,
Git or reports. Cryptographic purpose separation prevents this vault being
loaded by the generic web-session or directory-reader path, even if its wrapper
metadata is changed.

## 2. Review an exact account and region

This is a schema illustration; substitute your approved account, region and a
future UTC expiry. No real account is included:

```json
{
  "schema_version": 1,
  "provider": "aws",
  "account_id": "123456789012",
  "region": "us-east-1",
  "authorization_reference": "Owner-approved read-only inventory",
  "acknowledged_authorization": true,
  "expires_at": "REPLACE_WITH_UTC_EXPIRY_WITHIN_24_HOURS",
  "max_pages": 2,
  "page_size": 50,
  "max_resources": 100,
  "interval_seconds": 0.5,
  "timeout_seconds": 120
}
```

```bash
hunterqa aws-resource-preflight --input /approved/aws-scope.json \
  --session-file /private/aws-reader.json --session-key /private/aws-reader.key

hunterqa aws-resource-inventory --input /approved/aws-scope.json \
  --session-file /private/aws-reader.json --session-key /private/aws-reader.key \
  --approval REVIEWED_SHA256 --out /approved/new-aws-report.json --authorized
```

Approval binds account/region, limits, encrypted credentials, quota and runtime.
Only derived commercial AWS hosts are used; sovereign/GovCloud/China partitions
are not supported. Pages, resources, XML size/node count and overall runtime are
bounded. Tokens are encoded into fixed API requests, not followed as URLs.
At most 100 resources are retained across the three resource types; larger
accounts require broader future collectors. A separate region run covers that
region; this command does not resume past its retained resource cap.
HTTP errors, wrong account/owner/region, contract changes, expiry, quota stop and
a `stop` file beside the scope prevent further calls. Partial observations remain
explicit; an unassessed service is not secure by default.

## 3. Evidence and integration

Reports retain hashes and selected redacted resource/configuration facts. Add
`--evidence-dir /approved/new-private-evidence` to preserve original XML response
bytes in new private files and a manifest. Raw provider responses can contain
infrastructure names or tags: keep them private and outside Git. They are not
uploaded. Without this option, the tool records response hashes but does not
retain original XML.

Workspace/project options register the shared report in existing history.
Alternatively use `assessment-collect --connector aws-inventory --mode LIVE`
with the same scope, vault, approval and separate `--native-out`/`--out` paths.
Azure inventory, GCP inventory and GCP permission queries have equivalent shared
wrappers while retaining their existing private-token interfaces and scopes.

Unit tests use explicit simulated transports, labeled DEMO. They exercise real
signing, parser, policy, account-binding and evidence logic, and do not contact
AWS. Actual AWS account validation remains outstanding. Provider readiness must
not be inferred from these tests or a LIVE source-intent label.

Primary API contracts: [DescribeInstances](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html),
[DescribeSecurityGroups](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html),
[ListBuckets](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html).
