# HunterQA — Utility review

Two offline assurance contracts, a saved-report metadata checker and CVSS 3.1 Base
arithmetic complement existing triage, analyst decisions, HTML and SARIF exports.
This is partial coverage, not independent evidence validation or report certification.

| Upstream skill ID | Implemented review coverage | Independent work still needed |
| --- | --- | --- |
| `offensive-fast-checking` | Scope/budget/coverage/triage/validation/handoff observations; conservative exact-context duplicate suggestions and source-truncation cues | Actual assessment completeness, evidence correlation, authorization and business priority |
| `offensive-reporting` | Report-content/severity/remediation/retest/redaction observations; selected metadata completeness, CVSS consistency and sanitized Markdown quality summaries | Evidence contents/provenance, executive narrative, justified metrics, confirmed impact, retest and delivery approval |

## Start privately

1. Record owner authorization, local report/evidence scope, original provenance,
   reviewer/date and the permitted reporting/delivery context.
2. Copy [the assurance template](../templates/HunterQA-utility-review-template.json),
   [report input template](../templates/HunterQA-report-quality-template.json) and
   [worksheet](../templates/27-utility-review.md) outside this repo. Template empty
   strings/lists are placeholders; fill privately from independently reviewed evidence.
3. Set `HUNTERQA_APPROVED_ROOTS` to a narrow absolute private directory covering
   inputs and output parent. Use fresh outputs; existing files are never overwritten.
4. Assurance values: `true` = supported review; `false` = assurance gap; `null` =
   unassessed. Keep supporting client references in the worksheet, not extra fields.
5. Review JSON or generate the sanitized Markdown **quality summary**. This does
   not replace the original client report, alter it or publish anything.

```text
hunterqa utility-review-catalog
hunterqa utility-review --input /absolute/private/observations.json --out /absolute/private/review.json --authorized
hunterqa utility-report-review --input /absolute/private/findings.json --out /absolute/private/quality.json --authorized
hunterqa utility-report-review --input /absolute/private/findings.json --out /absolute/private/quality.md --format markdown --authorized
hunterqa utility-cvss31 --vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

PowerShell: `$env:HUNTERQA_APPROVED_ROOTS = 'C:\Private\HunterQA'`, with Windows
absolute paths. Linux: `export HUNTERQA_APPROVED_ROOTS=/absolute/private`.
The CVSS command is local arithmetic only and reads no file or target; file-based
reviews require explicit authorization. No target validation is started here.

## Saved finding report metadata

Input is a JSON object with a `findings` array. Selected fields are `title`,
`remediation`, `verification_status`, `rule_id`, `severity`, `evidence`, source
location/context and optional `cvss_vector`, `cvss_score`, `cvss_justification`.
Other root/finding fields are not evaluated. No referenced file, evidence hash,
URL, screenshot, report, PoC or attachment is opened or verified.

The checker flags selected missing metadata, absent evidence declarations,
unrecognized verification/severity labels, source truncation and supported CVSS
metadata discrepancies. Evidence can be nonempty string/list/object metadata;
presence is not quality, authenticity or reproducibility. `confirmed` is retained
only as an unverified source declaration, never promoted into a new trusted verdict.

Recognized verification labels: `unverified`, `needs-review`, `confirmed`,
`false-positive`, `remediated`. Other conventions remain unknown. Source severity
labels are retained only from a fixed enum; scanner INFO/WARNING/ERROR labels are
not converted into CVSS categories. Missing/unknown labels can be intentional and
require review rather than proof that a report is wrong.

Potential duplicates require matching nonempty rule ID, a positive declared line,
an exact non-placeholder file location or a syntactically valid target SHA-256,
and identical file/target/case/role context. Paths, case and hashes are not
normalized or resolved. Matching metadata suggests a review group, not identical
root cause or redundant evidence. Findings are never deleted, merged or confirmed.
Missing context yields no duplicate suggestion, not proof of uniqueness.

Report quality outputs retain input receipts and generated case IDs, missing-field
names, enum/boolean declarations, counts and generic INFO/unverified quality cues.
Source titles, paths, rule/target/case IDs, evidence values, notes and remediation
text are withheld. Markdown renders only generated/allowlisted metadata, not
client narratives, source links or raw text. Keep even these summaries private.

## CVSS 3.1 Base arithmetic and consistency

`utility-cvss31` accepts exactly a complete CVSS 3.1 Base vector: AV, AC, PR, UI, S,
C, I, A, once each, in any order. It returns canonical vector **and** Base score,
qualitative Base severity and attribution together. Calculations use decimal
arithmetic and upward one-decimal rounding. Metrics are caller-chosen; their
justification, applicability and actual impact are not verified.

**CVSS is owned by FIRST.Org, Inc. and used by permission.** Include vector and
score together when publishing justified scores. CVSS 4.0, 3.0, Temporal and
Environmental metrics are unsupported by this helper; it is not a full CVSS toolkit.
Other versions can be valid but require separate review/calculation.

The report checker compares a supplied supported vector with optional numeric
`cvss_score` and explicit LOW/MEDIUM/HIGH/CRITICAL/NONE labels, and notes absent
metric justification. Unsupported/invalid Base-profile vectors remain a review
cue rather than being scored. It emits only consistency booleans/states, **not**
source vectors or numeric CVSS scores. Score-only metadata requires vector review.
No automatic rating, metric inference, exploitability verdict or business-risk
priority is assigned to the original finding.

## Bounds, validation and remaining work

File reviews require approved-root regular non-symlink files and at most 2,000,000
bytes. Strict JSON rejects duplicate keys, nonfinite numbers, depth over 40 and
over 60,000 tree nodes. Limits: 10 assurance records per skill/20 total; 1,000 source
findings; evidence lists up to 20 entries; selected narrative fields 16,384
characters; other selected text up to 4,096; 500 retained quality findings with
explicit truncation counts. Global budgets also apply. Errors withhold contents.
Approved roots reduce accidental access, not hostile concurrent filesystem mutation.

No complete-schema/report validation, evidence-content checking, customer PDF/DOCX
report authoring, scope approval, analyst-verdict verification, remediation/retest
proof, external submission or delivery is provided by this pack. Existing report
and review workflows remain separate. A clean metadata check is not a complete,
accurate or publishable penetration-test report.

Tests use owned synthetic reports, metadata/privacy/budget cases and reference
CVSS vectors. They check local behavior, not real-world vulnerability detection.
All seven broad readiness areas remain partial; real-world effectiveness remains unverified.

## Category sequence and references

The review-pack sequence is catalogued in [the category index](CATEGORY_REVIEW_INDEX.md).
Its counts describe source review contracts and selected implementations, not all
upstream offensive operations or full automated pentesting coverage. Legacy-name
aliases are not additional independent implementations. The next work is integration
and evidence-based readiness review, not an automatic release or target assessment.

- [Upstream Utility category](https://github.com/SnailSploit/Claude-Red/tree/main/Skills/utility)
- [FIRST CVSS 3.1 specification](https://www.first.org/cvss/v3.1/specification-document)
- [FIRST CVSS 3.1 examples](https://www.first.org/cvss/v3.1/examples)
