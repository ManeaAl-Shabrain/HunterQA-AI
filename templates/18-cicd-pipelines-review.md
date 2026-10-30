# HunterQA — private CI/CD & Pipelines worksheet

Copy outside the repository. Do not commit completed copies, credentials, tokens,
workflow contents or private infrastructure identifiers.

1. Record private owner authorization, repository scope, reviewer and review date.
2. Inventory build/deploy triggers, contributors and trust boundaries. Identify
   external actions, reusable workflows and independently reviewed immutable refs.
3. Review actual workflow/job grants, repository/org defaults, runner isolation,
   environments and approval rules. Do not infer enforcement from declarations.
4. Review secret mappings, federation subjects/audiences, redaction, artifact/cache
   access and retention, rotation and revocation evidence. Never copy secret values.
5. Fill the JSON observations: true = supported review, false = assurance gap,
   null = unassessed. Keep private evidence references in this worksheet only.
6. Optionally review a saved GitHub Actions JSON declaration using the guide.
   Verify any independent YAML conversion; no native Jenkins/GitLab/Azure parser.
7. Independently triage every candidate, document context, evidence, remediation,
   responsible owner and retest outcome. Keep real-world effectiveness unverified.

| Skill | Private evidence reference | Unknowns / assurance gaps | Remediation owner / retest |
| --- | --- | --- | --- |
| offensive-cicd-pipeline | Fill privately | Fill privately | Fill privately |
| offensive-cicd-secrets | Fill privately | Fill privately | Fill privately |

See [the guide](../docs/CICD_PIPELINES_REVIEW.md) in the source repository; if this
copy is moved, open the guide from your trusted checkout.
