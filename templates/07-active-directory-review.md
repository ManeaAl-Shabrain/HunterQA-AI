# Active Directory — private review worksheet

Copy outside the public checkout. Read [the AD guide](../docs/ACTIVE_DIRECTORY_REVIEW.md).
This worksheet is not an authorization grant or executable testing protocol.
Keep names, SIDs, DNs, domain/host identifiers and any mapping to neutral IDs in
separate private records. Do not include credentials, hashes, keys or tickets.

- Written permission and permitted evidence: `<private reference>`
- Reviewer / UTC date: `<reviewer and date>`
- Evidence collection time and source revision: `<private reference>`
- Neutral record IDs / private mapping reference: `<reference>`
- Input receipt SHA-256 and private report: `<references>`
- Unknown fields / omitted objects / collection limitations: `<record>`

| Review area | Independent evidence needed | Decision / private evidence reference |
| --- | --- | --- |
| Account posture | Actual UAC flags, enabled state, identity type, DC status, Tier-0 assignment, SPN/credential-management context | Not assessed |
| SMB/LDAP policy | Effective server policies and client compatibility; policy declarations alone do not prove transport enforcement | Not assessed |
| Delegation | Actual service scope, permitted delegation, identity protections and reviewed exceptions | Not assessed |
| ACL grants | Object types, canonical ACL, deny/inheritance behavior, nested memberships and effective rights | Not assessed |
| AD CS | Published templates, precise EKUs, enrollment and CA permissions, approval/signature policy, mapping and patches | Not assessed |
| Trusts | Direction, trust type, effective SID filtering and intended authentication scope | Not assessed |
| Hybrid identity | Actual synchronization and independently established on-premises/Entra privilege assignments | Not assessed |

Use **not assessed**, **reviewed with no issue observed**, **candidate**, or
**validated finding**. Do not infer secure configuration from null/unknown data,
an empty findings array, disabled accounts, skipped checks or expired evidence.

For each candidate record: rule ID, exact evidence revision, expected/observed
configuration, false-positive and applicability review, authorized independent
validation, impact, remediation, reviewer decision and fresh retest results.
An ACL cue is not an executable attack path; the certificate cue does not certify
an ESC classification. These checks do not run NetExec or change the directory.
