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
