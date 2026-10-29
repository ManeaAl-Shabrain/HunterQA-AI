# Infrastructure & Red Team defensive review pack

**Post-v1.3.0 development capability.** Seven category contracts provide selected
offline defensive control review. A separate PE header reader inspects selected
file declarations without loading or executing the image. This is not a complete
red-team platform or an implementation of the offensive methods named upstream.

The category vocabulary references [Claude-Red](https://github.com/SnailSploit/Claude-Red/tree/main/Skills/infrastructure).
HunterQA's implementation is original. Upstream instructions, scripts and payloads
are not imported, installed or executed.

## Coverage

| Contract | Selected defensive observations |
| --- | --- |
| `offensive-initial-access` | Attachment controls, remote-access MFA and external-service patch review |
| `offensive-advanced-redteam` | Scope verification, segmentation and detection/response exercises |
| `offensive-edr-evasion` | Tamper protection, sensor health and telemetry coverage |
| `offensive-shellcode` | Dynamic/unsigned code policies and execution telemetry |
| `offensive-keylogger-arch` | Input access, sensitive-input controls and collection detection |
| `offensive-windows-mitigations` | DEP, ASLR, CFG, CET, ACG and CIG policy review |
| `offensive-windows-boundaries` | Least privilege, integrity boundaries, sandbox and broker authorization |

These are nullable owner observations, not sensors or proof of enforcement.
No initial-access campaign, EDR evasion, shellcode generation/injection, input
capture, C2, lateral movement, persistence or boundary bypass is executed.
All seven broad readiness areas remain partial. Real-world effectiveness remains
unverified. INFO/WARNING are unverified triage cues, not CVSS or confirmed impact.

## 1. Private owner evidence

After merging and pulling, activate the development environment and refresh with
`python -m pip install -e .`. This pack adds no dependency or native tool.
Copy [the JSON template](../templates/HunterQA-infrastructure-review-template.json)
and [private worksheet](../templates/12-infrastructure-review.md) outside the
checkout. Keep approvals, evidence, source artifacts and identity mappings private.

```bash
umask 077
mkdir -p "$HOME/hunterqa-cases/infrastructure"
cp templates/HunterQA-infrastructure-review-template.json "$HOME/hunterqa-cases/infrastructure/evidence.json"
export HUNTERQA_APPROVED_ROOTS="$HOME/hunterqa-cases/infrastructure"
# Edit only the private evidence copy, using independently reviewed observations.
hunterqa infrastructure-review-catalog
hunterqa infrastructure-review \
  --input "$HOME/hunterqa-cases/infrastructure/evidence.json" \
  --out "$HOME/hunterqa-cases/infrastructure/review.json" \
  --authorized
```

The root has exactly `schema_version: 1` and `records`. Each record has exactly
`id`, `skill` and `observations`. Neutral IDs must be unique and match
`[a-z][a-z0-9-]{0,47}`. Use a full contract name from the table. The catalog and
template list the exact required fields for each contract; extra fields are rejected.
All observations must be boolean or null. False records a declared absent control
or incomplete review. Null means unknown/unassessed. Remove inapplicable records;
never mark unknown controls true to silence a cue. An untouched template reports
insufficient evidence, not a pass. Maximum ten records per contract, 70 total.

For the shellcode and keylogger-named contracts, the fields describe prevention
and detection policy review only. The reader does not determine that a program
contains shellcode, captures input or evades endpoint monitoring. A reviewed policy
does not establish effectiveness against any particular technique.

## 2. Non-loading PE header review

Use an approved local image provided by the owner. The reader accepts selected
x86 PE32 and x64/ARM64 PE32+ layouts, with 1..96 sections and at most 16 data-directory
entries. Inputs are at most 4 MiB, including normalized JSON. Larger files must be
reviewed separately; do not truncate a real image to fit the bound.

```bash
hunterqa infrastructure-pe-review \
  --input "$HOME/hunterqa-cases/infrastructure/owner-image.exe" \
  --out "$HOME/hunterqa-cases/infrastructure/pe-review.json" \
  --authorized
```

The reader checks bounded DOS/PE/COFF/optional-header and section-table layout,
rejects incompatible selected machine/magic combinations, duplicate raw-data
overlap and out-of-file section ranges. This is not complete loader validation.
No section data, names, embedded strings, imports, signatures or dependencies are
interpreted, mapped, loaded or executed; only selected scalar header fields are read.

| Header observation | What it does not establish |
| --- | --- |
| Dynamic-base and high-entropy VA bits | Actual relocation support, loaded addresses, mandatory ASLR policy or measured entropy |
| NX-compatible bit | Actual DEP policy; absence produces a cue only for the selected x86 layout |
| CFG bit | Valid instrumentation, load configuration or runtime enforcement; a set bit requires independent verification |
| AppContainer bit | Actual process token, capabilities, packaging or sandbox boundary enforcement |
| Forced-integrity bit | Valid Authenticode signature or trusted publisher |
| No-SEH bit | SafeSEH tables or SEHOP enforcement; the bit is retained without a security verdict |
| Writable/executable section characteristics | Actual process page permissions, exploitability or malicious code |

DEP is not inferred disabled for x64/ARM64 when the compatibility bit is absent.
High-entropy absence is reviewed only for 64-bit images declaring dynamic-base
support. Ordinary applications are not flagged merely for lacking AppContainer or
forced-integrity bits. CET, ACG, CIG and SEHOP are not verified from these headers.
No disassembly, emulation, malware classification or exploit validation occurs.

## Reports, boundaries and validation

Inputs require explicit authorization and approved local roots. The flag is an
operator attestation, not independently verified target-owner consent. Outputs
use the existing private/create-only writer; their approved parent must exist,
and existing reports are never overwritten. On Windows, use an access-controlled
private case directory. Input permissions remain the operator's responsibility.

Reports retain UTC time, exact input SHA-256, neutral/receipt-derived case IDs,
selected booleans, architecture and review cues with remediation. Native section
names, paths and source contents are withheld. Normalized IDs are operator-supplied:
keep them neutral. Binary case IDs change with input bytes. No real source-line
coordinates are claimed for PE files; the existing SARIF representation uses an
external-evidence placeholder. Privately map case/section indices to the source.

Runtime-enforcement and signature-verification flags remain false. A hash does
not prove provenance, consent or authenticity. At most 500 findings are retained,
with explicit truncation metadata. None of the contracts claims full automation.

```bash
hunterqa report-sarif \
  --file "$HOME/hunterqa-cases/infrastructure/pe-review.json" \
  --out "$HOME/hunterqa-cases/infrastructure/pe-review.sarif"
```

Tests use owned synthetic JSON and scalar PE headers with zero-filled data and no
executable payload. They cover architecture applicability, positive/negative and
unknown controls, malformed layouts, privacy, scope boundaries and non-overwrite.
They do not measure real-world detection rates, process mitigation effectiveness
or complete Windows/infrastructure coverage.

## Primary references and next category

- [Microsoft PE format specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Microsoft exploit-protection policy and applicability](https://learn.microsoft.com/en-us/defender-endpoint/customize-exploit-protection)

The next category now has a separate [Exploit Development assurance guide](EXPLOIT_DEVELOPMENT_REVIEW.md).
Its local evidence/log/header readers do not extend this Infrastructure pack into
exploit execution or runtime mitigation verification.
