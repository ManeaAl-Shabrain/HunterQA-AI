# HunterQA — Forensics & C2 review

Two offline assurance contracts and selected saved log checks support evidence
preservation and defensive review of authorized C2 environments. This is partial
coverage, not anti-forensic tradecraft, a C2 deployment system or an attribution
engine. Original evidence is never altered by this review.

| Upstream skill ID | Implemented review coverage | Independent evidence still needed |
| --- | --- | --- |
| `offensive-anti-forensics` | Preservation/retention/collection/time/custody observations; selected Windows audit/time event cues | Source authenticity, timeline, authorized maintenance, tampering and custody integrity |
| `offensive-c2-frameworks` | Framework inventory/access/isolation/audit/revocation observations; selected Zeek DNS metadata cues | Endpoint/network correlation, approved framework/session inventory, domain context and C2 attribution |

## Start privately

1. Record owner authorization, permitted local log/evidence scope, source,
   collection date, reviewer and approved maintenance/test baseline. A local
   acknowledgment or SHA-256 receipt does not independently prove consent or provenance.
2. Copy [the JSON template](../templates/HunterQA-forensics-review-template.json)
   and [worksheet](../templates/22-forensics-c2-review.md) outside this repository.
   Preserve originals through your organization's approved process; review copies.
3. Set `HUNTERQA_APPROVED_ROOTS` to the narrow absolute directory covering private
   inputs and output parent. Never commit filled worksheets, client logs or reports.
4. Set observations to `true` for a supported assurance review, `false` for an
   assurance gap, or `null` for unassessed. Keep supporting references privately
   in the worksheet, not extra JSON fields.
5. Select the matching saved-log mode. Use a fresh output filename; no overwrite.

```text
hunterqa forensics-review-catalog
hunterqa forensics-review --input /absolute/private/observations.json --out /absolute/private/review.json --authorized
hunterqa forensics-log-review --mode windows-events-xml --input /absolute/private/events.xml --out /absolute/private/event-report.json --authorized
hunterqa forensics-log-review --mode zeek-dns-jsonl --long-query-chars 80 --input /absolute/private/dns.jsonl --out /absolute/private/dns-report.json --authorized
```

PowerShell: `$env:HUNTERQA_APPROVED_ROOTS = 'C:\Private\HunterQA'`, with Windows
absolute paths. Linux: `export HUNTERQA_APPROVED_ROOTS=/absolute/private`.
No host collection, DNS queries, endpoint contact or tool execution occurs.

## Saved Windows event XML

Accepts one `Event` in the exact namespace
`http://schemas.microsoft.com/win/2004/08/events/event`, or an `Events` wrapper
(unqualified or in that namespace) containing such events. Raw EVTX and formatted
Event Viewer text are not supported. Selected event IDs are considered only with
both the matching provider name and `Security` channel:

| Event ID | Provider | Review cue |
| --- | --- | --- |
| 1102 | Microsoft-Windows-Eventlog | Saved audit-log clearing declaration |
| 4719 | Microsoft-Windows-Security-Auditing | Saved audit-policy change declaration |
| 4616 | Microsoft-Windows-Security-Auditing | Saved system-time change declaration |

These names/IDs are declaration matches, not authenticity verification. Maintenance,
policy administration and normal time correction can explain events. Unrelated
IDs and missing/mismatched context remain unreviewed/insufficient evidence;
unsupported wrapper elements are counted. Missing context is never assumed.

Selected duplicate singleton fields and malformed selected IDs fail with sanitized
errors. XML DTDs, entities and external references are forbidden. User/EventData,
accounts, timestamps, event-record IDs, signatures and payloads are not analyzed.
No full event-schema validation, timeline correlation or central-log comparison is
performed. No finding is not proof that evidence was preserved or no tampering occurred.

## Saved Zeek DNS JSONL

Input is UTF-8/BOM with one JSON object per line, with selected fields `query`,
`qtype_name`, `rcode_name` and optional boolean/null `rejected`. At least one of the
first three fields must be present to review a row; other rows are counted as
unsupported. Missing/null selected values remain unknown. Other fields, including
addresses, IDs, answers and payloads, are not analyzed or exported.

TXT query declarations and query strings at/above the configurable character
threshold produce informational candidates. Default: 80 characters, measured
after removing trailing dots. This is a triage setting, not a security standard.
No DNS syntax validation, entropy analysis, timing/beacon analysis, aggregation,
endpoint correlation or framework attribution is performed. Numeric `qtype` alone
is not interpreted; TSV, packet captures and wrapped JSON arrays are unsupported.

TXT and long queries are common in legitimate DNS/application workflows; a rejected
or unanswered query can still produce the same review cue. Inspect the retained
response/rejection context and compare approved activity independently. Metadata
alone does not establish a successful response, tunnel, beacon or C2 framework.
Low/slow, encrypted and missing telemetry can be missed.

## Reports, bounds and verification

Reports retain input SHA-256 receipts, source-derived case numbers, selected
boolean/count/enum declarations and coverage counts. Names, addresses, accounts,
domains, commands, timestamps and raw values are withheld. Findings are `INFO`,
unverified candidates with generic review/remediation guidance; conservative SARIF
export omits source locations. Keep even sanitized reports private.

Inputs require authorization, approved-root regular non-symlink files and at most
1 MiB. JSON/JSONL rejects duplicate keys, nonfinite numbers, excessive depth/nodes
and malformed selected fields. Bounds: 10 observations per skill/20 total;
XML 20,000 nodes/depth 40 and 1,000 wrapped elements; JSONL 1,000 lines/16,384
characters per line and query values at most 4,096 characters; 500 retained findings
with explicit truncation counts. Content-withholding errors stop invalid inputs.
Approved-root checks reduce accidental access, not hostile filesystem mutation.

No log clearing, timestamp editing, secure deletion, anti-analysis/evasion,
implant/payload generation, C2 server/listener deployment, remote tasking or
communications are implemented. Upstream skill IDs identify review topics, not
availability of those offensive operations. Evidence integrity, malicious intent,
C2 attribution and real-world effectiveness remain unverified. The seven broad
readiness areas remain partial.

Owned synthetic tests check event/provider/channel matching, DNS boundaries,
unknowns, privacy, authorization, XML/JSON protections, retention bounds,
no-overwrite, SARIF and absence of process/network execution.

## References and next category

- [Upstream category](https://github.com/SnailSploit/Claude-Red/tree/main/Skills/forensics)
- [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [Event 4719](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4719)
- [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [Zeek DNS log](https://docs.zeek.org/en/current/reference/logs/dns.html)

The next pack is [Supply Chain](SUPPLY_CHAIN_REVIEW.md), delivered separately.
