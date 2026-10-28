# HunterQA — First Authorized Configuration Review

For HunterQA v1.3.0 on Kali/Linux. These templates configure a small public HTTPS
observation; they are not permission documents or a complete penetration test.
No website requests were made while preparing these examples.

## Files to fill

1. Save HunterQA-scope-template.json as profile.json in your private case folder.
2. Save HunterQA-targets-template.txt as targets.txt in the same folder.
3. Fill program and authorization_reference with your assessment name and actual
   written approval reference. Do not put passwords or tokens in either file.
4. Replace app.company.example with the exact permitted hostname in both files.
5. Set approved path prefixes, methods and port. Use / only if permission covers
   all paths on the host; otherwise narrow it and change the target URL too.
6. Keep the initial request budget at one. Add required exclusions from the
   organization's rules. Empty exclusion lists never expand the allowlist.
7. Set acknowledged_authorization to true only after confirming actual written
   permission and the specific method/endpoint. It is false by default so the
   example cannot run before that explicit acknowledgment.

The template permits GET, which requests the selected resource. Use it only when
GET is authorized. If only HEAD is approved, change methods to ["HEAD"] and both
commands below to --method HEAD. The CSP absence check applies only to GET
responses identified as HTML. Internal/private-network targets need their own
appropriate profile; do not enable network switches merely to bypass rejection.

## Assessment notes to keep privately

| Item | Fill before testing |
| --- | --- |
| Owner/organization | [Name] |
| Written approval reference | [Reference] |
| Exact permitted targets/actions | [Hosts, paths, ports and methods] |
| Testing window and timezone | [Start / end] |
| Total request allowance | [Total across all invocations] |
| Exclusions and stop conditions | [Owner requirements] |
| Contact for problems | [Organization contact] |
| Evidence storage/retention | [Approved private location and retention] |

These notes are operational reminders, not extra JSON profile fields. The basic
profile does not automatically verify owner identity or enforce a written
testing window or a cross-run total. Check those requirements yourself.

## First run

Use the case directory and activated virtual environment from the beginner
guide. Ensure HUNTERQA_CASEDIR is the canonical absolute path to that existing
private directory, and that profile.json and targets.txt are inside it.

```bash
export HUNTERQA_APPROVED_ROOTS="$HUNTERQA_CASEDIR"

hunterqa bounty-preflight \
  --profile "$HUNTERQA_CASEDIR/profile.json" \
  --targets "$HUNTERQA_CASEDIR/targets.txt" \
  --method GET
```

Preflight is offline. Read its scope result and verify the actual permission
before running the next command, which sends the selected request:

```bash
hunterqa bounty-assess \
  --profile "$HUNTERQA_CASEDIR/profile.json" \
  --targets "$HUNTERQA_CASEDIR/targets.txt" \
  --method GET \
  --out "$HUNTERQA_CASEDIR/header-review-001.json" \
  --authorized

python -m json.tool "$HUNTERQA_CASEDIR/header-review-001.json"
```

Use a fresh output filename for each separately authorized run. The request cap
is per invocation, not a cumulative owner allowance. bounty-assess is separate
from engagement-run and the supervised workflow runner; it does not take their
fingerprint approvals or emergency-stop-file option. Do not assume a STOP file
from another command controls this basic command.

## What this check can flag

| Observation | Condition |
| --- | --- |
| HSTS not observed | HTTPS response lacks that header |
| X-Content-Type-Options not observed | Header absent from the selected response |
| CSP not observed | GET response is identified as HTML and lacks the header |
| Cookie Secure flag absent | HTTPS response issues a cookie without Secure |
| Cookie HttpOnly flag absent | Response issues a cookie without HttpOnly |

Cookies are assessed only when issued in that response. An absence observation,
redirect/denial response, or a cookie deliberately readable by JavaScript needs
context; none automatically proves an exploitable vulnerability. Results are
informational candidates with manual review required. This command does not
crawl the website, execute payloads, test SQL injection/XSS/access-control flaws,
or certify that a site with no findings is secure.

Source code, OpenAPI contracts, imported scanner evidence and other test types
require the corresponding additional inputs and specific approved workflows.
