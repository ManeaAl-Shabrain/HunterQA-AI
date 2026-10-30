# Fuzzing & Vulnerability Research review pack

**Post-v1.3.0 development capability.** Four offline contracts review owner
observations. Two bounded readers inspect selected existing AFL++ snapshots and
libFuzzer log events. They do not launch a campaign, validate a harness, mutate
inputs, minimize a corpus, replay a crash or verify instrumentation/coverage.

Category vocabulary references [Claude-Red](https://github.com/SnailSploit/Claude-Red/tree/main/Skills/fuzzing).
HunterQA's implementation is original; upstream scripts, payloads and operational
instructions are not imported, installed or executed.

## Coverage and interpretation

| Contract | Selected observations |
| --- | --- |
| `offensive-fuzzing` | Harness, instrumentation, seed corpus and resource-limit review |
| `offensive-fuzzing-course` | Owned lab, coverage exercises and crash triage review |
| `offensive-bug-identification` | Taint boundaries, unsafe operations and fix-regression review |
| `offensive-vuln-classes` | Classification, impact evidence and remediation mapping review |

These fields are declarations, not code-analysis detectors, a complete course or
independent verification. INFO cues are unverified review aids, not CVSS ratings,
confirmed vulnerabilities or automatic CVE assignment. All broader readiness areas
remain partial. Independent real-world detection effectiveness remains unverified.

## 1. Prepare private evidence

After merging and pulling, activate the development environment and refresh with
`python -m pip install -e .`. The readers need no new dependency, compiler or fuzzer.
Copy [the JSON template](../templates/HunterQA-fuzzing-review-template.json) and
[private worksheet](../templates/14-fuzzing-research-review.md) outside the checkout.
Keep original logs, builds, corpora, owner approvals and identity mappings private.

```bash
umask 077
mkdir -p "$HOME/hunterqa-cases/fuzzing"
cp templates/HunterQA-fuzzing-review-template.json "$HOME/hunterqa-cases/fuzzing/evidence.json"
export HUNTERQA_APPROVED_ROOTS="$HOME/hunterqa-cases/fuzzing"
# Edit only the private evidence copy using applicable source observations.
hunterqa fuzzing-review-catalog
hunterqa fuzzing-review \
  --input "$HOME/hunterqa-cases/fuzzing/evidence.json" \
  --out "$HOME/hunterqa-cases/fuzzing/review.json" \
  --authorized
```

Root fields are exactly `schema_version: 1` and `records`; each record has exactly
`id`, `skill`, `observations`. IDs are unique neutral labels matching
`[a-z][a-z0-9-]{0,47}`. Use full contract names from the table. Catalog/template
list the exact required fields. Values must be boolean or null. False means a
declared incomplete review/control; null means unknown. An untouched template
reports insufficient evidence, not a pass. Remove inapplicable records; do not
mark unknown observations true. Maximum ten records per contract, 40 total.

## 2. Selected AFL++ snapshot review

Supply an already collected `fuzzer_stats` file, not a terminal status screen,
`plot_data`, corpus, executable or JSON export.

```bash
hunterqa fuzzing-artifact-review \
  --mode afl-stats \
  --input "$HOME/hunterqa-cases/fuzzing/fuzzer_stats" \
  --out "$HOME/hunterqa-cases/fuzzing/afl-review.json" \
  --authorized
```

The reader accepts nonblank `key: value` rows. Keys must match
`[a-z_][a-z0-9_]{0,63}` and be unique, including unselected keys. Maximum 512 rows.
Selected unsigned integers are `execs_done`, `cycles_done`, `corpus_count`,
`saved_crashes`, `saved_hangs`, `total_tmout`, `exec_timeout`, `peak_rss_mb`.
`execs_per_sec` accepts a nonnegative decimal. `stability` and `bitmap_cvg` require
a percent suffix and range 0..100. Integers allow at most 18 digits; decimals allow
at most 18 integer and six fractional digits. Signs, exponent notation, NaN,
infinity, duplicate keys and malformed selected values are rejected.

Unselected values, including command lines, identities and paths, are ignored and
not exported. Older aliases such as `unique_crashes`/`paths_total` are not mapped:
their corresponding selected fields remain unknown. No selected fields means
insufficient evidence. No defaults are inferred.

Review cues cover declared zero executions, saved crashes/hangs, timeouts and
stability below 100. The snapshot is not a live process-health check. Reduced
stability may have environmental or harness causes. Saved artifacts need independent
triage; their counts are not unique vulnerability counts. Bitmap occupancy is not
the percentage of source code covered. Metrics from unrelated builds/runs are not
compared or combined.

## 3. Selected libFuzzer log review

```bash
hunterqa fuzzing-artifact-review \
  --mode libfuzzer-log \
  --input "$HOME/hunterqa-cases/fuzzing/libfuzzer.log" \
  --out "$HOME/hunterqa-cases/fuzzing/libfuzzer-review.json" \
  --authorized
```

Column-one progress rows have `#ITERATIONS EVENT` followed by optional fields.
Selected events are `READ`, `INITED`, `NEW`, `REDUCE`, `RELOAD`, `pulse`, `DONE`.
Selected metrics are unsigned `cov`, `ft`, `exec/s` and the entry-count portion of
`corp: COUNT/SIZE`. The corpus-size suffix is opaque: no byte-size conversion or
validation is claimed. Other fields, mutation details and paths are not exported.
Repeated selected metric keys or invalid selected numeric tokens are rejected.
Metrics require whitespace after the colon; unsupported layouts remain unparsed.

At most 200 selected progress/error events are retained; exceeding the bound is
rejected. Unsupported progress event names are counted without exporting their
text. Recognized events without selected metrics remain insufficient evidence.
Missing/unsupported rows do not prove a clean run. Rows retain source order;
repeated events are not deduplicated into unique campaigns or crashes.

Selected error markers are `deadly signal`, `timeout`, `out-of-memory` after a
column-one `ERROR: libFuzzer:` header, optionally prefixed with `==PID==`.
Other diagnostics, summary-only lines and sanitizer traces are outside this reader;
use the separate [sanitizer review](EXPLOIT_DEVELOPMENT_REVIEW.md) where applicable.
An error marker is unverified text, not demonstrated security impact.

A missing selected DONE event generates a capture-review cue, not a campaign-failure
verdict. DONE presence does not establish that no errors occurred. Decreasing
iteration counters prompt review for restarts, concatenation or interleaved workers.
No progress deltas, source-coverage percentages, unique-crash counts or cross-build
comparisons are calculated. Even monotonically increasing counters are not proof
that the capture belongs to one authentic run.

## Boundaries, reports and validation

All modes accept approved local regular files of at most 1 MiB and require explicit
authorization. Native text must be plain UTF-8, with no ANSI escape sequences or
unsupported control characters, at most 20,000 lines and 8192 characters per line.
Do not truncate real evidence to fit the bounds; review it separately. Authorization
is an operator attestation, not independently verified owner consent.

Outputs use the existing private/create-only writer; their approved parent must
exist and prior files are never overwritten. On Windows use an access-controlled
private directory. Input permissions remain the operator's responsibility.
Do not upload real logs, inputs, filled worksheets or reports to GitHub.

Reports retain UTC time, exact input SHA-256, neutral/receipt-derived IDs, unknown
fields, selected metrics, original diagnostic/field line numbers and remediation.
Paths, arguments, inputs and raw source text are withheld. Keep normalized IDs
neutral and privately map case/event IDs to the original evidence. Hashes do not
prove provenance or consent. At most 500 findings are retained with explicit
truncation metadata. Coverage verification, reproduction, exploitability and
zero-day confirmation flags remain false.

```bash
hunterqa report-sarif \
  --file "$HOME/hunterqa-cases/fuzzing/afl-review.json" \
  --out "$HOME/hunterqa-cases/fuzzing/afl-review.sarif"
```

Tests use owned synthetic observations and text fixtures with positive/negative
and unknown controls. They establish reader behavior and compatibility, not
real-world detection rates, validated instrumentation or complete standards coverage.
Historical lab source examples remain separate; this pack does not turn them into
production fuzzing engines or execute them.

## Primary references and next category

- [LLVM libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
- [AFL++ status metrics](https://aflplus.plus/docs/status_screen/) and [stats writer](https://github.com/AFLplusplus/AFLplusplus/blob/stable/src/afl-fuzz-stats.c)

The next category now has a separate [Reconnaissance review guide](RECONNAISSANCE_REVIEW.md).
Its scoped local name imports do not extend this pack into live reconnaissance or collection.
