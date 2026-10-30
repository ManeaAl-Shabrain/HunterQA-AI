# HunterQA — AI Security review

One offline assurance contract, deterministic owned saved-case checks and numeric
garak summary import support AI application review. This is partial coverage,
not a live model test, jailbreak engine, model-extraction tool or robustness score.

| Upstream skill ID | Implemented review coverage | Independent evidence still needed |
| --- | --- | --- |
| `offensive-ai-security` | Ten prompt/RAG/tool/output/data/model/access/logging/dataset/robustness observations; saved canary/allowlist constraints and numeric garak summaries | Actual model behavior, inference/data provenance, role/tenant grants, runtime enforcement, detector calibration and real-world effectiveness |

## Start with private, owned evidence

1. Record owner authorization, local evidence scope/provenance/date, reviewer,
   application/model version and approved trust-boundary/role/tenant test context.
2. Copy [the assurance template](../templates/HunterQA-ai-security-review-template.json),
   [owned-case template](../templates/HunterQA-ai-owned-cases-template.json) and
   [worksheet](../templates/26-ai-security-review.md) outside this repo. Use only
   synthetic outputs and neutral mapped IDs in owned cases, never real secrets.
3. Set `HUNTERQA_APPROVED_ROOTS` to the narrow absolute directory covering private
   inputs and output parent. Keep source responses, prompts, identifiers, model
   details and even sanitized reports private. Use a fresh output filename.
4. Assurance values: `true` = independently supported review; `false` = declared
   assurance gap; `null` = unassessed. Owned observed fields: `null` = unobserved;
   an empty string/list is an explicit saved observation, not an unknown value.
5. Select the matching saved-evidence mode. No input string, module/class name,
   tool identifier, prompt, response or retrieved content is executed or followed.

```text
hunterqa ai-security-review-catalog
hunterqa ai-security-review --input /absolute/private/observations.json --out /absolute/private/review.json --authorized
hunterqa ai-security-evidence-review --mode owned-cases-json --input /absolute/private/cases.json --out /absolute/private/cases-report.json --authorized
hunterqa ai-security-evidence-review --mode garak-jsonl --input /absolute/private/evaluations.jsonl --out /absolute/private/garak-report.json --authorized
```

PowerShell: `$env:HUNTERQA_APPROVED_ROOTS = 'C:\Private\HunterQA'`, with Windows
absolute paths. Linux: `export HUNTERQA_APPROVED_ROOTS=/absolute/private`.
Local acknowledgments/receipts are not independent verification of consent,
collection integrity, model identity or evaluation provenance.

## HunterQA owned saved-case schema v1

Input has exactly `schema_version: 1` and a nonempty `cases` array. Case IDs must
be unique neutral lowercase IDs (`[a-z][a-z0-9-]{0,47}`). Each kind has exact fields:

| Kind | Required fields in addition to `id`, `kind` | Check |
| --- | --- | --- |
| `canary-disclosure` | `response`: string or null | Exact, case-sensitive occurrence of the public synthetic marker |
| `tool-boundary` | `allowed_tools`: ID list; `observed_calls`: ID list or null | Saved observed IDs outside the owner-declared allowed set |
| `retrieval-boundary` | `allowed_documents`: ID list; `retrieved_documents`: ID list or null | Saved retrieved IDs outside the owner-declared allowed set |

The fixed marker is `HUNTERQA_SYNTHETIC_CANARY_V1`: public test data, never a real
credential or protected system prompt. Marker matching does not identify encoded,
partial, paraphrased, semantic, multimodal or arbitrary-secret leakage, and its
presence does not prove an injection cause. Do not place real sensitive values in
test responses. Input/output content is treated as data only.

Map tool/document IDs to neutral IDs before exporting, and retain the mapping
privately. Allowed lists require unique IDs; repeated observed IDs are counted as
individual occurrences. A mismatch proves only inconsistency with that saved list,
not actual grants, tool execution, retrieved content exposure or cross-tenant access.
The evaluator never calls tools or resolves documents.

Report outcomes are `unobserved`, `violation` or `no-selected-violation`, with counts
of observed/unobserved cases and cases containing selected violations. These are
constraint outcomes, not pass/fail security certification, detector accuracy or
model robustness. No finding can establish safe prompt handling or authorization.

## Saved garak numeric JSONL

Accepts UTF-8/BOM with one JSON object per line. Only `entry_type: eval` records
are reviewed. Supported count profiles:

- Numeric `passed` and `total_evaluated` (current selected profile).
- Numeric `passed` and legacy `total` (selected legacy count profile).

If both total fields exist they must agree. Counts must be integers (not booleans)
between zero and 1,000,000; passed cannot exceed evaluated. Optional `fails` must
match evaluated minus passed. Optional `nones`/`total_processed` are validated for
consistent nonnegative counts when present. Zero evaluated is insufficient evidence.
Older boolean/score-only formats and arbitrary versions are not assumed compatible.

Non-eval rows are counted as not reviewed; malformed/over-budget JSON fails even
there. Prefer an independently exported minimized eval-only file. Probe/detector
names, model identifiers, prompts, outputs and metadata are not exported, imported
as Python modules or executed. garak need not be installed and is never run.

Non-passing counts are INFO/unverified review cues, not independent output rescoring
or confirmed vulnerabilities. Different probes/detectors can overlap: counts are
kept per summary and never merged into a unique-output pass rate/model score.
Review detector meaning, calibration, dataset coverage and original private evidence
independently. Saved summaries do not prove real model behavior or provenance.

## Reports, limits and verification

Reports retain SHA-256 input receipts, numbered receipt-derived cases and selected
boolean/enum/count declarations. Input IDs, tool/document/probe/model names,
responses, prompts, credentials and raw values are withheld. Findings are `INFO`,
unverified candidates with generic remediation guidance; conservative SARIF
export omits source locations.

Inputs require explicit authorization and approved-root regular non-symlink files
of at most 1 MiB. Strict JSON/JSONL rejects duplicate keys, nonfinite values,
excessive depth/nodes and malformed selected fields. Bounds: 10 assurance records;
100 owned cases; 50 allowed IDs/200 observed IDs per case; 16,384 response characters;
garak 1,000 lines/16,384 characters per line; 500 retained findings with explicit
truncation counts. Global input/tree budgets also apply, so combined per-case maxima
may exceed a file's overall budget. Errors withhold contents. Approved roots reduce
accidental access, not hostile concurrent filesystem mutation.

No live provider/model calls, prompt/probe generation, safety-filter bypass,
model extraction, training/RAG poisoning, credential access, output execution or
agent tasking is performed. Runtime grants, RAG isolation and robustness use
independent owner/evaluation evidence. Upstream skill IDs describe review topics,
not automatic availability of offensive operations.

Owned synthetic tests cover exact canary matches/non-matches, unobserved states,
allowlist boundaries, summary profiles/consistency, redaction, parser/file budgets,
authorization, no-overwrite, SARIF and absence of process/network execution.
All seven broad readiness areas remain partial; real-world effectiveness is unverified.

## References and next category

- [Upstream category](https://github.com/SnailSploit/Claude-Red/tree/main/Skills/ai)
- [OWASP prompt-injection topic](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [OWASP excessive-agency topic, 2025 reference](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
- [OWASP vector/embedding topic, 2025 reference](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/)
- [garak evaluator record source](https://github.com/NVIDIA/garak/blob/main/garak/evaluators/base.py)

These are selected topic references, not a full or latest-edition standards-coverage claim.

**Next requested category: Utility.** It is not delivered by this pack.
