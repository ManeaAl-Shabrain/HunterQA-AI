# Web Application review pack

**Post-v1.3.0 development feature.** This category contains 16 review contracts:
10 have narrow, offline Python syntax checks and 6 provide guided review only.
It does **not** implement all techniques described by the referenced skills.
Real-world detection effectiveness remains unverified.

The category names reference [Claude-Red's Web Application index](https://github.com/SnailSploit/Claude-Red#web-application).
HunterQA's implementation and review guidance are original. No upstream agent
prompts, payload libraries, installation scripts or tools are imported or run.

## What each skill does here

| Skill | Implemented source cue / review mode | What remains unproven |
| --- | --- | --- |
| `offensive-sqli` | Interpolated expression passed to database-like `execute`, `executemany` or `executescript` | Input reachability, SQL injection and database-specific coverage |
| `offensive-xss` | Dynamic `markupsafe.Markup` / `flask.Markup` argument | HTML context, sanitization, reflected/stored/DOM XSS or script execution |
| `offensive-ssrf` | Dynamic destination in selected requests/httpx/urllib calls | Attacker control, egress filtering and SSRF |
| `offensive-ssti` | Dynamic Flask template-string / Jinja Template source | Untrusted provenance and template injection |
| `offensive-xxe` | lxml parser explicitly enables `resolve_entities=True` | External entity access and document provenance |
| `offensive-idor` | Guided ownership/tenant review; existing `authorization-matrix` supports exact role cases | General object discovery or authorization correctness |
| `offensive-file-upload` | File-like `.save(object.filename)` call | Upload provenance, unsafe storage or executable content |
| `offensive-rce` | Dynamic os shell calls / selected subprocess calls with `shell=True` | Input control or command execution vulnerability |
| `offensive-deserialization` | Dynamic input to selected pickle/dill/unsafe YAML loaders | Untrusted provenance or exploitable object construction |
| `offensive-race-condition` | Guided atomicity, transaction and idempotency review | Concurrent/race validation; no bursts are sent |
| `offensive-request-smuggling` | Guided edge/backend protocol review | Parser disagreement; no ambiguous HTTP requests are sent |
| `offensive-open-redirect` | Dynamic Flask redirect destination | Missing validation or external redirect vulnerability |
| `offensive-parameter-pollution` | Guided duplicate-value handling review | Proxy/framework parsing disagreement |
| `offensive-graphql` | Explicit `introspection=True` on selected Ariadne/Strawberry setup calls | Schema exposure alone is not a vulnerability; no resolver/complexity testing |
| `offensive-waf-bypass` | Guided defensive normalization review | No WAF evasion or bypass execution |
| `offensive-business-logic` | Guided server-side invariant and state-transition review | Application-specific workflow correctness |

All source cues are **INFO / unverified**. A dangerous-looking API may be used
safely. Missing matches, an empty report and completion of a checklist never
mean the application passed a penetration test.

## Start with authorized source

Use a private case directory outside this checkout. On Kali/Linux, with the
environment activated and your authorization already established:

```bash
mkdir -p "$HOME/hunterqa-cases/web-review"
export HUNTERQA_APPROVED_ROOTS="/absolute/path/to/owned-app:$HOME/hunterqa-cases/web-review"
hunterqa web-review-catalog
hunterqa web-source-review \
  --project /absolute/path/to/owned-app \
  --out "$HOME/hunterqa-cases/web-review/source-review.json" \
  --authorized
```

Replace the application path with a source directory you are authorized to
inspect. This command does not accept a website URL and never imports or executes
the application's code. The output parent must already exist inside an approved
root. Output is private and create-only; choose a fresh name for each run.

The same source cues are integrated into the existing `scan` engine and
`source-review` workflow through the local orchestrator. Those paths still have
their existing Semgrep dependency and approval requirements. The standalone
`web-source-review` command does not require Semgrep.

For SARIF, use the existing exporter on the private JSON report:

```bash
hunterqa report-sarif \
  --file "$HOME/hunterqa-cases/web-review/source-review.json" \
  --out "$HOME/hunterqa-cases/web-review/source-review.sarif"
```

Use [the category worksheet](../templates/05-web-application-review.md) to review
all 16 contracts. For already implemented bounded live observations, follow
[the adapter guide](ASSESSMENT_ADAPTERS.md) and its separate scope, plan and
execution approvals. The source review does not grant permission for live tests.

## Interpreting retained evidence

- `source_receipts`: relative paths and SHA-256 of the exact bytes parsed.
- `findings`: rule, skill, source line, receipt hash and remediation. No source
  snippets, argument values, passwords or source contents are exported.
- `skills`: one row per contract. `guided-review-only` means no automated detector.
  `not-assessed` means no Python file was successfully parsed. A no-cue state
  means only that the selected syntax checks observed no cue.
- `skipped`, `truncated`, `files_examined`, `files_parsed`: review these before
  relying on the report. Parse failures, unsupported languages and exclusions
  reduce coverage. Neither full-project nor per-skill completeness is claimed.

The pack examines at most 500 Python files, 128 KiB each, and retains at most
500 candidates. The shared enumerator also limits directory entries and excludes
symlinks, `.env*`, secrets, dependencies and build directories. Source-changing
races remain possible; these are local checks, not OS isolation.

Checks recognize selected direct calls and imported aliases. There is no taint,
flow, reachability, alias-shadowing, sanitization or dependency-version analysis.
JavaScript, TypeScript, PHP, Java, .NET and other languages are outside this
pack. Existing Semgrep coverage is separate and does not complete this category.

## Validation and next category

Owned synthetic positive/negative fixtures exercise every implemented check,
approval and root enforcement, output non-overwrite, parsing/size/result bounds,
alias handling and non-execution of inspected code. These fixtures establish
implementation behavior, not real-world detection rates.

**Following category: [Auth & Identity](AUTH_IDENTITY_REVIEW.md).** Its later
offline JWT/OAuth evidence review is separate from this source pack. Dedicated-role
access contracts and local dashboard accounts do not establish full JWT/OAuth coverage.
