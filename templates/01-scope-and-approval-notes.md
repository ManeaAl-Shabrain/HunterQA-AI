# 01 · Scope and Approval Notes

Copy this worksheet to a private case directory before filling it. It records
operational information; it is not an authorization agreement or a machine-read
permission grant. No credentials or access tokens belong here.

| Item | Fill from the actual written approval |
| --- | --- |
| Assessment name | [Organization / assessment name] |
| Organization/system owner | [Owner] |
| Written approval reference | [Reference; retain the actual document privately] |
| Operator reference | [Person conducting the assessment] |
| Exact permitted hostname(s) | [No implicit subdomain permission] |
| Permitted path prefixes | [Use / only if permission covers all paths] |
| HTTPS port | [443, or the explicitly approved port] |
| Approved method for this run | [GET or HEAD] |
| Approved test | [One bounded header/cookie observation] |
| Excluded systems/paths/actions | [Owner's exclusions, or explicitly none] |
| Start and end, with timezone | [Approved testing window] |
| Total request allowance | [Across all invocations, including retests] |
| Maximum request frequency | [Agreed interval/rate] |
| Emergency contact and stop conditions | [Owner contact and conditions] |
| Approved evidence location/retention | [Private directory and retention] |

## Before acknowledging authorization

- [ ] I hold current written permission from the responsible owner.
- [ ] The exact endpoint and method are permitted.
- [ ] Third-party services and other subdomains are not implicitly included.
- [ ] The testing window is currently valid.
- [ ] The owner's total request allowance includes this run.
- [ ] The JSON profile and targets.txt match this worksheet and the agreement.
- [ ] Any sensitive agreement/contact details stay outside GitHub.

After those checks, set `acknowledged_authorization` to `true` in the private
`profile.json`. That local acknowledgment does not independently authenticate
the owner or verify the underlying agreement.
