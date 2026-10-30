# HunterQA — Privilege Escalation review

Two offline Linux/Windows assurance contracts and selected saved inventory checks
support defensive review. This is partial coverage, not an automated privilege
escalation test, effective-access calculation or certification.

| Skill | Implemented | Independent evidence still needed |
| --- | --- | --- |
| `offensive-linux-privesc` | Owner assurance observations and selected saved `getcap` declarations | Actual sudo/setid/capability/job/service policy, namespace context, patch status and exploitable access |
| `offensive-windows-privesc` | Owner assurance observations and selected saved process-service path ambiguity cues | Service/file ACLs, tokens, identity, tasks, installer/DLL policy, patch status and exploitable access |

## Start with private evidence

1. Obtain owner authorization for the local evidence review; record its reference,
   scope, collection provenance and date privately. A local acknowledgment is not
   independent proof of owner consent or trustworthy inventory.
2. Copy [the JSON template](../templates/HunterQA-privilege-review-template.json)
   and [worksheet](../templates/20-privilege-escalation-review.md) outside this repo.
   Do not copy credentials, tokens, registry secrets or credential-store contents.
3. Set `HUNTERQA_APPROVED_ROOTS` to the narrow absolute private input/output-parent
   directory. Existing outputs are never overwritten; choose a fresh name.
4. Set observations to `true` for independently supported assurance review,
   `false` for a declared assurance gap, or `null` for unassessed. Retain private
   supporting references in the worksheet, not extra JSON fields.
5. Optionally review an already saved inventory using the matching mode. HunterQA
   does not collect it, enumerate hosts, inspect referenced paths or run tools.

```text
hunterqa privilege-review-catalog
hunterqa privilege-review --input /absolute/private/observations.json --out /absolute/private/review.json --authorized
hunterqa privilege-inventory-review --mode getcap-text --input /absolute/private/capabilities.txt --out /absolute/private/capability-report.json --authorized
hunterqa privilege-inventory-review --mode windows-services-json --input /absolute/private/services.json --out /absolute/private/service-report.json --authorized
```

PowerShell: `$env:HUNTERQA_APPROVED_ROOTS = 'C:\Private\HunterQA'`, with Windows
absolute paths. Linux: `export HUNTERQA_APPROVED_ROOTS=/absolute/private`.
Keep even sanitized reports and completed worksheets private.

## Linux saved getcap text

Accepts selected UTF-8/BOM text with one file per line, a path followed by named
capability clauses such as `cap_example=ep`. Supported clauses are comma-separated
`cap_` names, `=` and distinct `e`, `i`, `p` flags, separated by whitespace; an
optional trailing `[rootid=NUMBER]` is recognized as a declaration only. An explicit
empty `=` is distinguished from missing/unsupported text. Duplicate capability
names across clauses, duplicate flags, numeric/all forms, +/- forms, verbose
no-capability lines, error output and other unsupported syntax are counted as
unreviewed, never treated as proof of no privileges.

The cue covers selected identity, discretionary-access, administration, tracing,
module and file-capability-management declarations. It does not determine
process effective/permitted/inheritable sets, namespace mapping, mount policy,
bounding sets, file contents or actual user execution. A declared file capability
may be intentional or unusable in the assessed context. Empty input/all unsupported
lines produce insufficient evidence, not a clean host verdict.

## Windows saved Win32_Service JSON

Input is one service object or an array of objects from an independently saved
CIM inventory. Each requires `PathName` (string or null); selected optional fields
are `StartName`, `StartMode` and `ServiceType`. Other fields are ignored and never
exported. A synthetic example:

```json
[{"PathName":"C:\\Owned Service\\service.exe","StartName":"LocalSystem","StartMode":"Manual","ServiceType":"Own Process"}]
```

Only selected process-service type declarations and absolute drive/UNC-style
paths with a directly recognizable `.exe` prefix are considered. An unquoted
executable prefix containing whitespace is an informational candidate. Quoted
prefixes are not resolved or certified safe. Missing fields, driver/unsupported
types, relative paths, environment expansion and unresolved forms remain unknown.
A conventional LocalSystem account name is merely a declaration: token/effective
identity, file or service ACLs, directory write access, start/restart rights and
actual command-line interpretation remain unverified. Disabled services are not
automatically safe; their declared state is retained as context.

No service-control, registry, scheduled-task, token impersonation, DLL loading,
kernel exploit, UAC bypass, credential access or privilege transition is performed.
Sudo/setid/cron/systemd, token privileges, tasks, installer policy and patch status
are owner-review contracts only, with no native parser or runtime validation.

## Reports, limits and validation

Reports contain generic remediation, SHA-256 input receipts and numbered cases;
source paths, accounts, commands and private values are withheld. Findings are
`INFO`, unverified review candidates. No findings does not establish safe access.
Conservative SARIF export omits source locations. Receipts do not prove collection
integrity, owner consent or current host state.

Inputs: approved-root regular non-symlink files, explicit authorization, at most
1 MiB. JSON duplicate keys, nonfinite numbers, excessive depth/nodes and malformed
selected fields fail with content-withholding errors. Bounds: 10 observations per
skill/20 total, 1,000 getcap lines (4,096 characters/line), 1,000 service objects,
500 retained findings with explicit truncation counts. Approved-root checks reduce
accidental access; they do not isolate a hostile concurrent filesystem writer.

Owned synthetic tests cover positive/negative/unknown declarations, parser bounds,
service path context, unsupported lines, privacy, authorization, no-overwrite,
SARIF and absence of process/network execution. Real-world effectiveness remains
unverified; the seven broad readiness areas remain partial.

## References and next category

- [Upstream category](https://github.com/SnailSploit/Claude-Red/tree/main/Skills/privesc)
- [getcap](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Win32_Service](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service)
- [CreateService path quoting](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)

The next pack is [Post-Exploitation](POST_EXPLOITATION_REVIEW.md), delivered separately.
