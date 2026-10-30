# HunterQA — Owned SQL impact validation

This development-source command demonstrates one concrete SQL injection impact
in an original in-memory toy application. It accepts no target URL, database,
SQL, payload, executable or customer input. It makes no network requests and
does not call an external scanner. It is separate from the HTTP SQL-error checks.

## Run and retain evidence

With the virtual environment active, use a private approved directory and a
fresh output name. This command is absent from the immutable v1.3.0 archive.

```bash
umask 077
mkdir -p "$HOME/hunterqa-private"
export HUNTERQA_APPROVED_ROOTS="$HOME/hunterqa-private"
hunterqa lab-sql-validation --out-dir "$HOME/hunterqa-private/sql-001" --authorized
hunterqa lab-sql-verify --run "$HOME/hunterqa-private/sql-001"
```

On Windows, use `.\.venv\Scripts\hunterqa.exe`, an existing absolute private
directory in `$env:HUNTERQA_APPROVED_ROOTS`, and Windows paths for both commands.
The verifier replays the same fixed in-memory cases; it is not a read-only file
inspection command. Neither command connects to a database server or website.

## What is demonstrated

Two synthetic records belong to different toy owners. The intended query should
return only the viewer's own record. One variant concatenates its fixed test
input into SQL; the control uses a bound parameter. After seeding the database,
query-only mode, size limits, an instruction limit and a SELECT/READ authorizer
restrict execution. The database is closed after the cases finish.

| Case, run against both variants | Expected literal variant | Expected bound control |
| --- | --- | --- |
| Missing-name baseline | No rows | No rows |
| Negative comparison | No rows | No rows |
| Legitimate own record | One own row | One own row |
| Fixed lab probe | One foreign synthetic row | No rows |

The legitimate case ensures an implementation that returns nothing cannot pass.
The negative and parameterized cases ensure indiscriminate matches cannot pass.
All eight cases must match; otherwise the CLI exits with code **2** and retains
the failed observations. Expected labels are versioned separately from execution.

`impact_demonstrated_in_owned_fixture: true` means exactly this cross-owner row
read occurred in the deliberately vulnerable toy and its controls matched.
It does not confirm authentication bypass or a vulnerability in a customer app.
`customer_findings_confirmed` remains zero and real-world effectiveness unverified.

## Evidence and verification

| Artifact | Contents |
| --- | --- |
| `ground-truth.json` | Versioned expected cases and outcomes |
| `observations.json` | Case IDs, row counts, foreign-row booleans and query/result hashes |
| `validation.json` | Per-case matches, TP/FP/FN, evidence/source hashes and limitations |

Reports do not export raw SQL, probe text or synthetic row values. Keep the whole
directory. Outputs are create-only. Verification checks the current fixture and
labels, recomputes measured claims and replays the deterministic fixed cases to
compare observations. A modified receipt alone cannot hide changed observations
from that replay. Code changes require a new run under a fresh name.

This remains local consistency checking with a trusted installation and directory
owner. It is not signed evidence, independently audited provenance or a field
detection-rate estimate. Per-case metrics describe this tiny fixture only.

## Coverage and next work

This adds a demonstrated SQL impact case, not a general SQL injection validator.
It does not establish that the HTTP scanner detects exploitable SQL injection.
No blind/OOB testing, database fingerprinting, extraction, exploit chaining or
arbitrary live probing is provided by this command. XSS, SSRF, upload/traversal,
SSO/business workflows, directory/cloud expansion and production isolation remain
separate work. All seven broad readiness areas remain partial.

See [rendered browser discovery](BROWSER_LAB_V1_2.md), the separate
[HTTP/TCP benchmark](READINESS.md) and the [coverage checklist](FEATURE_READINESS_CHECKLIST.md).
