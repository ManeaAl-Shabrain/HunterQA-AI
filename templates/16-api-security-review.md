# Private API Security review worksheet

Copy outside the repository. Never commit filled approvals, account mappings,
tokens, specifications or reports. See [the guide](../docs/API_SECURITY_REVIEW.md).
This is a human review record, not CLI input or independently verified consent.

## Scope and provenance

- Private approval reference and permitted evidence handling:
- Neutral case IDs, separate role/account/tenant mapping and data minimization:
- Specification provenance, version, exact receipt and actual deployment relevance:
- Independently permitted validation and reviewer:

## Assurance review

| Contract | Evidence and reviewer conclusion | Remaining unknowns |
| --- | --- | --- |
| Object/function authorization and authentication | | |
| Response minimization, resource and transport policy | | |
| Business invariants, workflow and idempotency | | |
| Batch limits and webhook destination/authenticity | | |

## OpenAPI contract review

- Case/operation indices and private path-hash mapping:
- Root/operation security, alternatives and intended public access:
- Referenced/undefined schemes, skipped paths and unresolved schemas:
- Intended server precedence and actual TLS deployment not verified:
- Pagination/array/property declarations and independent runtime controls:
- Findings accepted/rejected with reasons; no direct BOLA/BFLA or mass-assignment inference:

## Remediation and retest

- Owner-approved documentation/code/control changes:
- Fresh specification/evidence receipts and report paths:
- Independent authorization/business-logic results and remaining uncertainty:

The reader sends no API requests, follows no references and performs no account
actions. Contract syntax does not establish actual server enforcement or impact.
