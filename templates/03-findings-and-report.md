# 03 · Findings and Assessment Report

Human-authored private report for a bounded header/cookie observation. Fill
actual results; do not pre-populate findings or claim a full penetration test.

## Assessment context

| Field | Actual value |
| --- | --- |
| Organization / assessment | [Fill] |
| Written approval reference | [Fill] |
| HunterQA version | [Fill] |
| Operator / reviewer | [Fill] |
| Tested endpoint and method | [Fill] |
| Testing time and timezone | [Fill] |
| Private evidence file | [e.g. header-review-001.json] |
| HTTP status or transport outcome | [Fill] |
| Selected coverage and limitations | [One endpoint; describe actual method] |

## Check observations

Use **observed**, **not observed**, **not applicable** or **not assessed**. A
missing control is an informational candidate until its relevance/impact is
independently assessed. Cookies may intentionally be readable by JavaScript;
redirects, denied responses and non-HTML endpoints need appropriate context.

| Check | Applies when | Result and evidence |
| --- | --- | --- |
| HSTS header | HTTPS response | [Fill] |
| X-Content-Type-Options | Selected response | [Fill] |
| Content-Security-Policy | GET response identified as HTML | [Fill] |
| Cookie Secure flag | Cookie issued on HTTPS response | [Fill or not applicable] |
| Cookie HttpOnly flag | Cookie issued in selected response | [Fill or not applicable] |

## Candidate record — repeat for each relevant observation

| Field | Fill using evidence |
| --- | --- |
| Candidate identifier/title | [Tool finding id and title] |
| Source severity | [Copy the actual label; basic checks are informational] |
| Verification state | [Unverified / needs review / analyst-attested decision] |
| What was observed | [Specific response condition] |
| Evidence reference | [Private file and relevant field; redact secrets] |
| Independent validation | [What was actually verified; otherwise not performed] |
| Impact | [Established impact, or unknown] |
| Recommendation | [Context-appropriate owner-reviewed action] |
| Owner/reviewer decision | [Fill; local attestation is not independent proof] |
| Retest reference | [04-retest-record.md, when performed] |

## Summary for the organization

- Approved scope: [Fill]
- Tests actually performed: [Fill]
- Relevant observations/candidates: [Fill]
- Confirmed impact, if independently established: [Fill or not established]
- Untested areas and uncertainties: [Fill]
- Recommended next authorized work: [Fill]

No finding does not establish that the site is secure. This basic observation
does not test SQL injection, XSS, access control or business logic. Keep raw
evidence private and share only through the organization's agreed channel.
