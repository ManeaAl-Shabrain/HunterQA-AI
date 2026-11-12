# Native GPO policy review

## Pre-implementation gap review

Inspected main `63644d1` after PR81 merged, the current AD/source/report modules,
CLI and tests. No open PR existed at inspection. The two historical unmerged
branches are unchanged from the previous review and contain no new GPO parser.
The existing 370-item baseline and earlier evidence remain unchanged.

| Requirement | Existing implementation | Classification before this increment |
| --- | --- | --- |
| GPO security configuration | Directory collector counts GPO metadata only | Missing native content analysis |
| Domain authentication policy | Selected LDAP attributes and normalized declarations | Partially Implemented |
| Privileged rights | Selected normalized AD grants; no security-template rights parser | Partially Implemented |
| Evidence/report integration | Shared AD LAB/LIVE reports, history and JSON/HTML/SARIF | Already Implemented and Verified within documented scope |
| Effective GPO application | No link, inheritance, WMI/security-filter or resultant-policy engine | Missing |

Incremental plan: parse original UTF-16LE `GptTmpl.inf` and binary `Registry.pol`
without executing them; evaluate selected explicit directives; retain hashes and
unknown/unsupported counts; reuse shared AD reporting/history/export; add malformed,
positive/negative and integration tests. No network collection or policy changes.
Windows application/resultant policy requires separate real-lab validation.

Format references: [MS-GPSB security policy syntax](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/fa15485d-ae9f-456e-a08f-81f2e5725a7e)
and [MS-GPREG registry policy syntax](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpreg/5c092c22-bf6b-4e7f-b180-b20743d368f5).

## Usage

Copy an authorized machine-policy file into a private approved evidence folder.
The command reads local bytes only; it does not connect to SYSVOL or apply policy.

```bash
export HUNTERQA_APPROVED_ROOTS=/absolute/private-evidence
hunterqa assessment-review --module ad --mode LAB \
  --input-mode gpo-security-template --input /absolute/private-evidence/GptTmpl.inf \
  --out /absolute/private-evidence/new-gpo-report.json --authorized
```

For machine `Registry.pol`, use `--input-mode gpo-machine-registry`. Preserve the
original file encoding: security templates require a UTF-16LE BOM and CRLF; binary
registry policy requires PReg version 1. Text-converted exports and user-scoped
registry policies are not admitted. Selecting machine mode is an operator
assertion, not proof of the file's origin.

Add `--workspace-config /private/control/workspace.json --project-id 1` to retain
the report in an existing workspace/project. Its protected Scenario results view,
evidence hashes and JSON/HTML/SARIF exports are reused. Paths and account/SID
values are not copied into shared findings. A report records the exact input hash
and `gpo-file-rules-1`; imported LAB/LIVE evidence remains **Not Yet Verified**.

## Selected analysis

| Native directives | Review behavior |
| --- | --- |
| Password length below eight | Conservative legacy-floor candidate, not a complete modern password baseline |
| Reversible password storage | Review an explicit enabled directive |
| Complexity disabled, lockout disabled, Guest enabled | Informational context review; no universal lockout/complexity recommendation |
| Eight sensitive privilege rights | Check four fixed broad well-known SIDs; named accounts/memberships remain unresolved |
| LM compatibility, SMB required signing, LDAP client integrity, WDigest | Selected machine DWORD checks with bounded legal values |

Ordinary registry assignments retain file order; the last matching assignment
replaces an earlier one for that file only. Special deletion/ACL instructions
disable scalar evaluation and require review. Unsupported types, out-of-range
values and unknown identities are counted as unassessed, never treated as secure.
Missing directives are not interpreted as secure defaults.

Limits: 512 KiB per input, 1000 directives/instructions, bounded strings and
template lines. Duplicate selected INF keys/sections, malformed encodings,
truncated binary records and unsupported versions are rejected. No imports,
expressions, shell commands, registry writes or network calls are executed.

## Verification and remaining work

22 targeted tests passed on 13 November 2026 using original native-format
positive/negative fixtures. They cover strict encoding, every truncation of a
representative binary record, type/size limits, order/deletion uncertainty,
redaction, no-network parsing, CLI export and actual protected workspace history
with digest-tamper rejection. Existing AD/mode integration tests also passed.
These are synthetic native-file tests, not Windows GPO application validation.

Ruff passed; Bandit reported no medium/high finding in the checked application
and tools. Full regression and current CI results are recorded separately when
complete. This changes native GPO **content analysis** from missing to partially
implemented. It does not complete GPO collection or effective policy analysis.

Remaining: authorized SYSVOL acquisition, registry/user policy breadth, registry
and file ACL semantics, group membership/security descriptors, GPO links/order
across files, inheritance, WMI/security filtering, fine-grained password-policy
precedence and real Windows resultant-policy acceptance. Original AD collection
and offline normalized analysis remain available.
