# HunterQA — private AI Security worksheet

Copy outside this repository. Never commit prompts, responses, model/probe/tool/
document identifiers, tenant details, secrets or completed client evidence records.

1. Record owner authorization, local evidence scope/provenance/date, reviewer,
   application/model version, dataset version and approved role/tenant test context.
2. Independently review prompt trust boundaries, RAG permissions, tool grants,
   output handling, sensitive-data controls, model/data provenance, inference access
   limits, audit logging, evaluation coverage and adversarial robustness.
3. Fill assurance values: true = supported review, false = assurance gap, null =
   unassessed. Keep private supporting references here, not extra JSON fields.
4. For owned saved cases, use synthetic responses and neutral mapped IDs only.
   Use null for unobserved data; empty observations mean explicitly saved empty
   output/call lists. The fixed public canary is not a real secret.
5. Record actual allowlist/tenant grants and collection integrity independently;
   saved-list mismatches do not prove tool execution or unauthorized content access.
6. Optionally review minimized numeric garak summaries. Keep detector calibration,
   original outputs and dataset scope private; do not combine overlapping counts
   into a model score or treat imported pass labels as independently validated.
7. Triage every candidate, document remediation owner and authorized retest.
   Keep runtime authorization, model behavior and real-world effectiveness unverified
   until supported by separate, appropriately scoped evaluation evidence.

| Skill topic | Private evidence reference | Unresolved assurance gaps | Remediation owner / retest |
| --- | --- | --- | --- |
| offensive-ai-security | Fill privately | Fill privately | Fill privately |

Open the [AI Security guide](../docs/AI_SECURITY_REVIEW.md) from your trusted
checkout if this private copy has moved from its original location.
