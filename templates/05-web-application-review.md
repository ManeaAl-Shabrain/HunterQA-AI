# Web Application — private review worksheet

Copy outside this public repository. Do not commit filled client information.
Read [the category guide](../docs/WEB_APPLICATION_REVIEW.md) before use.
This worksheet is a human record, not a runnable workflow or authorization grant.

- Approval reference: `<private reference>`
- Approved source revision / receipt set: `<revision>`
- Reviewer / date: `<name and date>`
- Private source-review report: `<path>`
- Scope exclusions / skipped files / coverage limits: `<record>`

For each row record **not assessed**, **reviewed with no issue observed**,
**candidate**, or **validated finding**, with private evidence references.
Only mark a finding validated after independent reproduction and impact review.

| Skill | Required review evidence | State / evidence / remediation |
| --- | --- | --- |
| SQL injection | Database callsites, value binding and approved baseline controls | Not assessed |
| XSS | Output contexts, encoding, sanitization and approved browser evidence | Not assessed |
| SSRF | URL provenance, address validation, redirects and egress policy | Not assessed |
| SSTI | Template provenance and rendering context | Not assessed |
| XXE | Parser options, resource loading and input trust | Not assessed |
| IDOR | Known object ownership and dedicated-role authorization contracts | Not assessed |
| File upload | Type/size policy, generated names, permissions and storage isolation | Not assessed |
| RCE | Command construction, input provenance and process privilege | Not assessed |
| Deserialization | Format, loader options and input trust | Not assessed |
| Race condition | Atomic state transitions, transactions and idempotency | Not assessed |
| Request smuggling | Edge/backend framing and protocol configurations | Not assessed |
| Open redirect | Destination allowlist, normalization and validation | Not assessed |
| Parameter pollution | Duplicate-value policy across each application layer | Not assessed |
| GraphQL | Schema policy, resolver authorization, depth and cost budgets | Not assessed |
| WAF defensive review | Edge/application normalization and approved defensive evidence | Not assessed |
| Business logic | Server-side ownership, price, approval and state invariants | Not assessed |

## Findings and retest

For each candidate retain: skill, exact source revision and line, expected versus
observed behavior, impact, false-positive analysis, evidence reference, suggested
fix, reviewer decision and a fresh authorized retest. Source cues alone are not
validated vulnerabilities. Leave unsupported and untested areas explicitly open.
