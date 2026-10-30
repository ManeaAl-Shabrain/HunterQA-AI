# HunterQA — private Privilege Escalation worksheet

Copy outside this repository. Never commit completed copies, host inventories,
source paths, accounts, credentials, tokens or client identifiers.

1. Record owner authorization reference, scope, reviewer, collection provenance,
   date and the actual user/namespace/service context being reviewed.
2. Linux: independently review sudo policy, setid file ownership/need, file
   capabilities and namespace/mount/bounding restrictions, privileged jobs,
   service configuration and patch status. Saved declarations do not prove access.
3. Windows: independently review service/file/directory ACLs, exact binary path
   and service identity, restart rights, token privileges, tasks, installer and
   DLL-search policy, patch status and compensating controls.
4. Fill JSON observations: true = supported assurance review, false = assurance
   gap, null = unassessed. Keep supporting private references in this worksheet.
5. Optionally review saved getcap text or Win32_Service JSON. Record unreviewed
   lines/unknown fields. No findings is not proof of safe privileges.
6. Independently validate each candidate within the authorized protocol; record
   actual impact, evidence, remediation owner and retest. Never infer effective
   privileges or exploitability from a capability/account/path declaration alone.

| Skill | Private evidence reference | Unresolved assurance gaps | Remediation owner / retest |
| --- | --- | --- | --- |
| offensive-linux-privesc | Fill privately | Fill privately | Fill privately |
| offensive-windows-privesc | Fill privately | Fill privately | Fill privately |

Open the [privilege guide](../docs/PRIVILEGE_ESCALATION_REVIEW.md) from your trusted
checkout if this private copy has moved from its original location.
