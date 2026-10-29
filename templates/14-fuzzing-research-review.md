# Private Fuzzing & Vulnerability Research worksheet

Copy outside the repository. Never commit approvals, build identities, corpora,
crash inputs, logs or filled reports. See [the guide](../docs/FUZZING_RESEARCH_REVIEW.md).
This is a human review record, not CLI input or independently verified consent.

## Scope and provenance

- Private approval reference and permitted evidence handling:
- Neutral case/build/run IDs and separate private mapping:
- Exact evidence receipts, fuzzer/build versions and applicable harness:
- Capture completeness, worker/restart context and independently reviewed limits:

## Assurance review

| Contract | Applicable evidence and reviewer conclusion | Remaining unknowns |
| --- | --- | --- |
| Harness, instrumentation, corpus and limits | | |
| Owned lab, coverage exercises and crash triage | | |
| Taint boundaries, unsafe operations and regression | | |
| Classification, impact evidence and remediation | | |

## Native metric review

- Source stats/log receipt, report path and private line mapping:
- Selected and missing metrics; unsupported fields/events:
- Bitmap occupancy versus actual source/edge coverage evidence:
- Saved artifacts/error markers and separate independent reproduction:
- Repeated events, worker interleaving, restarts and capture incompleteness:
- Findings accepted/rejected with reasons; no automatic unique-vulnerability count:

## Remediation and retest

- Owner-approved harness/configuration/code changes:
- Fresh evidence receipts and independently justified comparisons:
- Regression outcome, reviewer and unresolved uncertainty:

The readers do not run fuzzers, replay inputs, minimize corpora or verify coverage.
Counters and log markers alone do not establish vulnerability impact or effectiveness.
