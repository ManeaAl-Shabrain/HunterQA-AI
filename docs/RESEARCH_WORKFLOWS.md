# Review playbooks, private research context, scanner imports and SARIF

These additions are development-source capabilities. They are not a replacement
for historical release archives or an autonomous pentesting system. Their scope
comes from the [seven-reference comparison](FRAMEWORK_COMPARISON_2026_10.md).

## Original playbooks

Run `hunterqa research-playbooks` or visit `/playbooks` on the existing loopback
dashboard. Ten original checklists cover source boundaries, API authorization,
sessions, dependencies, containers, pipelines, response controls, AI grounding,
business workflows and data handling. These are review questions, not executable
skills, exploit instructions or imported third-party prompts.

## Private research workspace

Use an existing private scope profile and approved directory. The following
operations are offline. Initialization requires a new directory; no existing
research folder is overwritten.

```bash
export HUNTERQA_APPROVED_ROOTS="$HOME/private-hunterqa"
folder="$HOME/private-hunterqa"

hunterqa research-init --profile "$folder/profile.json" \
  --out-dir "$folder/research-001" --playbook api-authorization \
  --playbook ai-output-review --authorized

hunterqa research-note --profile "$folder/profile.json" \
  --workspace "$folder/research-001" --kind observation \
  --summary "The captured owned fixture differs from the expected denial." \
  --evidence "$folder/result-001.json" --authorized

hunterqa research-note --profile "$folder/profile.json" \
  --workspace "$folder/research-001" --kind negative-result \
  --summary "The permitted control did not reproduce the hypothesis." --authorized

hunterqa research-resume --workspace "$folder/research-001"
```

Kinds are `observation`, `hypothesis`, `negative-result`, and `next-step`.
There is no note state that automatically marks a vulnerability validated.
Summaries are single-line operator text, up to 1000 characters. Do not put
passwords, tokens, personal data or raw captures into notes. The CLI displays
recent notes to its invoking operator; they are not automatically sent to a model.
Evidence references store a bounded file's SHA-256 and byte count, not its content
or file name. The private original artifact remains necessary for review.

The manifest binds selected playbooks and the exact permission-profile bytes.
A changed profile requires a new workspace. Each append verifies the journal's
ordered hash links, uses a create-only lock to reject concurrent appends, flushes
the write, and retains at most 200 events. Manifest/journal input sizes are bounded.
Directories use mode 0700 and files 0600 on POSIX. These modes do not establish
Windows ACL isolation or protection from another process under the same account.

An interrupted final write is rejected. A leftover `append.lock` blocks further
appends; inspect the journal and establish that no writer is active before manually
removing a stale lock. Partial initialization is retained for inspection rather
than recursively deleted. Hashes show consistency, not signatures or proof that
an artifact supports the operator's claim. `research-resume` returns context only:
it launches no tests and does not renew a live assessment approval.

## Offline external scanner imports

```bash
hunterqa external-import --profile "$folder/profile.json" --tool nuclei \
  --file "$folder/already-captured-nuclei.jsonl" --authorized \
  --out "$folder/nuclei-import-001.json"

hunterqa external-import --profile "$folder/profile.json" --tool zap \
  --file "$folder/already-captured-zap.json" --authorized \
  --out "$folder/zap-import-001.json"
```

Supported formats are Nuclei **HTTP JSONL** result events and ZAP **traditional
JSON** site/alert/instance reports. Other Nuclei protocols, XML, arbitrary ZAP API
responses and scanner versions with incompatible shapes are not claimed supported.
The importers do not install or launch these tools and make no network requests.
The operator must already have permission to hold and analyze the captures.

Inputs must be under approved roots, at most 2 MB, with at most 2000 rows/instances
and 500 distinct accepted candidates. ZAP site/alert arrays also have bounds.
Malformed structure and duplicate keys fail closed; unsupported/out-of-scope
entries are counted as skipped. Candidate identity deduplication is exact, not
semantic evidence correlation. Queries/fragments are removed before endpoint
scope checks; embedded credentials and paths prohibited by the existing profile
validator are rejected/skipped. This does not authorize the scanner's original
request method or create an approved replay target.

Only hashed endpoint identity, rule identifier, conservative metadata and source
fingerprints are retained. Raw requests, responses, attacks, extraction values and
arbitrary scanner prose are omitted. A source severity maps to a scanner label,
not a verified impact rating. No new imported rule bypasses the existing known-rule
correlation/dossier boundary. Independently reproduce a real candidate and use
the established human review workflow; a scanner's assertion is not that review.

## SARIF export

```bash
hunterqa report-sarif --file "$folder/source-scan.json" \
  --out "$folder/source-review.sarif"
```

The input is a normalized HunterQA findings object, bounded to 2 MB and 1000
findings. Export writes a new private SARIF 2.1.0 file under approved roots.
It emits stable rule IDs, generic unverified review messages, levels and safe
repository-relative locations when available. Absolute/drive/traversal/URI paths
are omitted, and spaces/non-ASCII characters are URI-encoded. External endpoint
locations are omitted rather than leaking targets into a code-scanning view.
Source excerpts, arbitrary messages/titles, AI prose, raw traffic and suggested
fixes are not exported. The private source report remains necessary for context.
Generating SARIF does not upload it and does not authenticate source assertions.

## Reusable source-only GitHub Action

The repository root `action.yml` supports Linux runners and requires explicit
acknowledgment. It installs HunterQA and the optional Semgrep executable into an
isolated runner-local environment, then analyzes a selected source directory as
data. It never builds/imports/executes the target project and accepts no live URL.
Package installation needs internet; this is not an air-gapped setup procedure.
Semgrep analysis uses the local bundled rules, with metrics/version checks disabled.

```yaml
name: Authorized source review
on: [workflow_dispatch]
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          persist-credentials: false
      - name: Analyze source already authorized for review
        id: hunterqa
        uses: ManeaAl-Shabrain/HunterQA-AI@FULL_REVIEWED_COMMIT_SHA
        with:
          authorized: 'true'
          project-path: '.'
          fail-on: none
```

Replace `FULL_REVIEWED_COMMIT_SHA` with the reviewed implementation commit; the
placeholder is intentionally not a moving release/version claim. Outputs are
`sarif-path` and `candidate-count`. Files stay in private runner temporary storage;
retain or upload them only through a separately reviewed workflow step. There are
no automatic PR comments, check-run writes or report submissions. Minimal read
permissions suffice for this action alone. Apply normal untrusted-PR workflow
restrictions and never grant it deployment secrets merely to scan source.

`project-path` must resolve within the checkout; traversal, absolute/drive paths
and symlinked selected project paths are rejected. Inputs are passed as environment
data rather than assembled into shell commands or `eval`. `fail-on: error`
optionally returns failure for ERROR **scanner labels**; default `none` exports
review candidates without interpreting them as confirmed vulnerabilities.

The Action itself is not an OS sandbox for a compromised runner or scanner binary.
See [security boundaries](../SECURITY.md) and the
[comparison and deferred features](FRAMEWORK_COMPARISON_2026_10.md).
