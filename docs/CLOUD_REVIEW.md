# Cloud review pack

**Post-v1.3.0 development capability.** The `offensive-cloud` contract adds
selected offline AWS, Azure and GCP policy review. It does not implement the full
offensive methodology or a comprehensive runtime cloud assessment.

The vocabulary references [Claude-Red's Cloud category](https://github.com/SnailSploit/Claude-Red/tree/main/Skills/cloud).
HunterQA's implementation is original. Upstream prompts, credential-collection
steps, tool libraries, escalation chains and mutation commands are not imported,
installed or executed.

## What is available

| Mode | Selected coverage | Important limits |
| --- | --- | --- |
| Normalized AWS/Azure/GCP evidence | Identity, storage, network, audit, federation, permissions and provider-specific compute declarations | Owner-supplied observations, not inventory or independently verified enforcement |
| Native AWS IAM JSON | Allow action patterns/all-actions, wildcard principals, inverted selectors, declared PassRole and selected web-identity trust without conditions | No policy evaluator, role chaining, condition/variable evaluation, boundary/SCP/RCP resolution or effective-access proof |
| Native GCP IAM JSON | Public principal classes, broad basic roles and selected service-identity administration roles | No CEL, custom-role resolution, hierarchy/deny/principal-access-boundary evaluation or token creation |
| Native Azure NSG JSON | Broad-source inbound TCP/any-protocol declarations overlapping selected admin ports | No rule ordering, default rules, route/ASG resolution, attached controls or actual reachability validation |

All findings are **unverified review candidates**. INFO/WARNING are triage labels,
not proven impact or CVSS scores. Broad roles, public endpoints and administrative
assignments may be intentional. Conditions, denies, boundaries, inheritance and
other controls can restrict a declaration. No quiet result certifies security.

The existing `aws-account-audit` remains a separate, explicitly approved runtime
adapter with its original two read-only account APIs. This pack does not expand
that adapter, add Azure/GCP connections or reuse its credentials.

## Mode A — normalized owner evidence

Copy [the JSON template](../templates/HunterQA-cloud-review-template.json) and
[reviewer worksheet](../templates/09-cloud-review.md) into a private directory
outside the checkout. A qualified owner must map approved source observations
to the exact fields. Do not populate facts by guessing provider defaults.

The exact top-level fields are `schema_version: 1` and `records`. Each record has
`id`, `provider`, `area`, and `observations`. Providers are aws/azure/gcp. Areas
are identity/storage/network/audit/federation/permissions/compute. IDs are unique
neutral labels matching `[a-z][a-z0-9-]{0,47}`. The catalog prints every field:

```bash
hunterqa cloud-review-catalog
```

| Area | Required observation fields |
| --- | --- |
| Identity | `principal_kind` (human/workload/root/unknown), `privileged`, `mfa_enforced`, `long_lived_keys_present`; root is an AWS-only kind. Human MFA checks require declared privilege; workload credentials need a different policy. |
| Storage | `public_access`, `encrypted_at_rest`, `https_only`, `access_logging` |
| Network | `internet_admin_ports`, `public_database_endpoint`, `flow_logs_enabled` |
| Audit | `control_plane_logging`, `data_access_logging`, `retention_reviewed`, `log_protection_reviewed` |
| Federation | `issuer_validated`, `audience_restricted`, `subject_restricted`, `trust_scope_reviewed` |
| Permissions | `wildcard_actions_allowed`, `unrestricted_resources`, `privileged_assignment`, `assignment_scope_reviewed` |
| AWS compute | `imds_v2_required`, `metadata_hop_limit_reviewed`, `instance_role_scope_reviewed` |
| Azure compute | `managed_identity_scope_reviewed`, `encryption_at_host_enabled`, `public_ip_present` |
| GCP compute | `secure_boot_enabled`, `service_account_scope_reviewed`, `os_login_enabled` |

Every observation is boolean or null except `principal_kind`, which also accepts
the listed enum or null. `null`/`unknown` mean unassessed; false means an observed
false setting. Do not set true just to silence a cue. Remove unavailable records;
providers without records remain not assessed. The untouched template reports
insufficient evidence for all providers, not a pass.

Encryption fields refer to actual protections of the selected resource, not
merely the absence of a customer-managed key or optional encryption agent.
In particular, Azure managed-disk SSE is always enabled; `encryption_at_host_enabled`
addresses the separate host/cache/temp-disk layer and is an INFO review cue.
It must not be interpreted as "Azure disk encryption is off". See
[Microsoft's encryption overview](https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption-overview).
GCP Secure Boot and OS Login have image/compatibility and alternative-control
considerations; their absence alone is not proof of a vulnerability.

On Kali/Linux, with the development checkout installed and environment active:

```bash
mkdir -p "$HOME/hunterqa-cases/cloud"
chmod 700 "$HOME/hunterqa-cases/cloud"
cp templates/HunterQA-cloud-review-template.json "$HOME/hunterqa-cases/cloud/evidence.json"
chmod 600 "$HOME/hunterqa-cases/cloud/evidence.json"
# Edit only the PRIVATE copy using independently reviewed source evidence.
export HUNTERQA_APPROVED_ROOTS="$HOME/hunterqa-cases/cloud"
hunterqa cloud-review \
  --input "$HOME/hunterqa-cases/cloud/evidence.json" \
  --out "$HOME/hunterqa-cases/cloud/review.json" \
  --authorized
```

On Windows, use an access-controlled private directory and the platform's path
separator for multiple roots. Input must be an approved regular file. Output
requires an existing approved parent and is private/create-only. Existing files
are never overwritten. Secure source evidence yourself; input permissions are
not modified by these commands.

## Mode B — selected native provider JSON

Use a private, authorized, already-resolved policy/resource export. This command
does not collect it. Never upload real exports: they can contain resource names,
identities and other sensitive configuration.

```bash
hunterqa cloud-policy-review \
  --mode aws-iam \
  --input "$HOME/hunterqa-cases/cloud/aws-policy.json" \
  --out "$HOME/hunterqa-cases/cloud/aws-review.json" \
  --authorized
```

Choose exactly one mode:

- `aws-iam`: a policy document containing `Statement` as an object or nonempty
  list, optionally `Version`/`Id`. Statements use selected standard IAM selectors,
  `Effect`, optional `Sid` and optional condition objects. It is not a wrapper
  returned by GetRole, GetPolicyVersion, CloudFormation or Terraform. Variable,
  condition, wildcard matching and effective-policy semantics are not evaluated.
  `Deny` statements do not generate these selected Allow cues, but are not
  applied against other statements. A present condition is not assumed safe.
  The web-identity cue detects absent condition declarations only; it does not
  validate specific issuers, audiences or GitHub repository/branch restrictions.
- `gcp-iam`: an IAM allow-policy object with nonempty `bindings`, optionally
  `version` (0/1/3), `etag`, `auditConfigs`. Each binding has a role string, a
  nonempty members list and optional condition object. Public classes are
  allUsers/allAuthenticatedUsers; selected roles are owner/editor and service
  account TokenCreator/KeyAdmin. Custom roles, CEL, auditConfigs, deny policies,
  organization controls and inheritance are not interpreted.
- `azure-nsg`: a resolved NSG resource object with nonempty
  `properties.securityRules`. Each selected rule uses its `properties` object:
  access, direction, protocol, custom priority 100..4096, source address prefix
  or prefix array, and destination port or port-range array. Supported protocol
  values are Tcp/Udp/Icmp/Esp/Ah/*. Singular/plural selectors must not conflict.
  Explicit ARM expressions in source selectors are rejected; full ARM/Bicep
  templates and PowerShell-shaped exports are unsupported. Only broad sources
  */Internet/0.0.0.0/0/::/0 and inbound Tcp/* declarations intersecting
  ports 22, 3389, 5985 or 5986 produce the selected network cue. Default rules,
  source ports, destination scope, ASGs, priorities/overrides, routes and other
  controls still require independent effective-access review.

Native syntax readers are not complete provider schema validators. Missing or
unsupported selected input shapes fail with contents withheld. Other supported
metadata/context may be ignored; no provider validity or enforcement is claimed.
Snapshot/source changes produce different receipt-derived case IDs in SARIF.

## Privacy, reports and limits

Reports retain neutral case context, provider/area, UTC review time, unknown
fields, candidate limits, remediation and exact input-byte SHA-256. Native modes
also retain statement/binding/rule counts via records and condition-presence
metadata where applicable. They omit source identifiers, selector values,
resource paths, names, addresses, conditions, principal strings and credentials.
Diagnostic text necessarily describes the selected cue. Keep input, mappings
and reports private. Hashes do not independently prove source truth or consent.

Machine-readable report flags explicitly state that provider enforcement,
effective permissions and actual resource reachability have **not** been verified.
No credentials, metadata endpoints, SDK/CLI, network, role assumptions, tokens,
key creation, cloud resource changes, exploit chains or log suppression are used.
The commands are standalone offline evidence review, not new live workflow adapters.

Input is bounded to 1 MiB. Normalized evidence allows at most 10 records per
provider/area, 210 total. Native documents support 1..100 selected statements,
bindings or rules; selector/member lists support 1..100 bounded strings.
At most 500 findings are retained; `truncated` and `candidates_not_retained`
make omissions visible. Tests use owned synthetic JSON, not live cloud accounts.
Real-world effectiveness remains unverified.

For source-free SARIF export, without uploading:

```bash
hunterqa report-sarif \
  --file "$HOME/hunterqa-cases/cloud/review.json" \
  --out "$HOME/hunterqa-cases/cloud/review.sarif"
```

## Primary references and next category

- [AWS policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html), [OIDC trust](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html) and [IMDS configuration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [Google Cloud IAM roles](https://cloud.google.com/iam/docs/roles-overview) and [Shielded VM](https://cloud.google.com/compute/shielded-vm/docs/shielded-vm)
- [Azure NSG processing](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview) and [disk encryption layers](https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption-overview)

This pack does not implement complete provider standards or replace actual
effective-permission and runtime assessment. **Following category: [Mobile](MOBILE_REVIEW.md).**
Its later offline declarations and decoded Android/iOS XML review are separate
from this Cloud pack and do not provide device/runtime assessment.
