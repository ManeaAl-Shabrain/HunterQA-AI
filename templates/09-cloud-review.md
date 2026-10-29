# Cloud — private reviewer worksheet

Copy outside the public checkout. Read [the Cloud guide](../docs/CLOUD_REVIEW.md).
This worksheet is a human record, not an authorization grant or executable plan.
Keep actual account/tenant/project IDs, resource paths, identities and neutral-ID
mappings in separate private records. Never include credentials, tokens or keys.

- Written permission / selected evidence scope: `<private reference>`
- Reviewer / UTC date: `<reviewer and date>`
- Provider(s), collection time and source revisions: `<private references>`
- Neutral case IDs / private mapping: `<reference>`
- Input SHA-256 and private report files: `<references>`
- Missing evidence, conditions, inherited policy and provider-default limitations: `<record>`

| Review area | Independent evidence to inspect | Decision / private reference |
| --- | --- | --- |
| Identity | Actual principal type, privileged assignments, human MFA and credential lifecycle | Not assessed |
| Storage | Intended publication, effective access, actual encryption/transport and audit policy | Not assessed |
| Network | Routes, priorities, denies, attached controls, admin access and actual reachability | Not assessed |
| Audit | Actual control/data-plane coverage, exceptions, retention and log protection | Not assessed |
| Federation | Trusted issuer/audience/subject, relying-party context and actual enforcement | Not assessed |
| Permissions | Identity/resource policies, conditions, boundaries, organization controls and inheritance | Not assessed |
| Compute | Provider-specific instance/identity, encryption/boot and supported access configuration | Not assessed |

For native inputs also verify the exact source shape: AWS IAM policy document,
GCP IAM allow-policy bindings, or resolved Azure NSG resource JSON. These readers
do not calculate effective permissions or network access and do not validate the
complete document. A broad declaration may be restricted by other controls.

Use **not assessed**, **reviewed with no issue observed**, **candidate**, or
**validated finding**. A quiet report, missing section, null observation or
declared control is not a security certification. Retain original approved
evidence privately and document source age/applicability separately.

For each candidate record: rule ID, source revision, expected/observed policy,
false-positive and applicability review, independent authorized validation,
impact, remediation, reviewer decision and fresh retest results. No policy is
uploaded, simulated against a provider or applied by these offline commands.
