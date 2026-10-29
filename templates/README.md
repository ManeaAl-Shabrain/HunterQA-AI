# HunterQA — Authorized Assessment Templates

**Start here for your first approved website header/cookie configuration review.**

The original three files below are the same templates previously supplied in
chat, preserved without content changes. The numbered worksheets organize the
remaining preparation, execution, reporting and retest steps.

This is a small public HTTPS observation workflow for HunterQA v1.3.0. It does
not crawl a website, execute exploit payloads or provide a complete penetration
test. The examples use the fictional `app.company.example` hostname and keep
authorization acknowledgment **false** until you fill and review the scope.

## What each file is for

| Step | File | Fill with |
| --- | --- | --- |
| Start | [HunterQA-first-configuration-review.md](HunterQA-first-configuration-review.md) | Original instructions, operational notes and exact commands |
| 1 | [01-scope-and-approval-notes.md](01-scope-and-approval-notes.md) | Real written-approval reference, permitted scope, window, limits and contact |
| 2 | [HunterQA-scope-template.json](HunterQA-scope-template.json) | Machine-readable scope; save your private copy as `profile.json` |
| 3 | [HunterQA-targets-template.txt](HunterQA-targets-template.txt) | Exact approved URL; save your private copy as `targets.txt` |
| 4 | [02-plan-and-run-checklist.md](02-plan-and-run-checklist.md) | Checks and actual run details |
| 5 | [03-findings-and-report.md](03-findings-and-report.md) | Observations, evidence, review and recommendations |
| 6 | [04-retest-record.md](04-retest-record.md) | Fresh authorization check and observed retest results |
| Optional source review | [05-web-application-review.md](05-web-application-review.md) | Evidence and reviewer decisions for all 16 Web Application contracts; 10 source cues and 6 guided-only reviews |
| Optional identity evidence | [HunterQA-identity-review-template.json](HunterQA-identity-review-template.json) | Private JWT samples and actual OAuth/OIDC web-client settings; replace all placeholders in a private copy |
| Optional identity review | [06-auth-identity-review.md](06-auth-identity-review.md) | Independent JWT/OAuth reviewer decisions, evidence limits and retest records |
| Optional AD evidence | [HunterQA-ad-review-template.json](HunterQA-ad-review-template.json) | Owner-normalized AD, SMB/LDAP, ACL, certificate, trust and hybrid declarations; null/unknown means unassessed |
| Optional AD review | [07-active-directory-review.md](07-active-directory-review.md) | Independent source verification, applicability, effective-access review and retest records |
| Optional Wireless evidence | [HunterQA-wireless-review-template.json](HunterQA-wireless-review-template.json) | Selected observations for all 14 contracts; null means unassessed, not a secure default |
| Optional Wireless review | [08-wireless-review.md](08-wireless-review.md) | Independent configuration, patch applicability, device and technology review records |
| Optional Cloud evidence | [HunterQA-cloud-review-template.json](HunterQA-cloud-review-template.json) | Selected AWS/Azure/GCP declarations across seven areas; null means unassessed |
| Optional Cloud review | [09-cloud-review.md](09-cloud-review.md) | Independent provider policy, condition, effective-access and reachability review records |

**Work on private copies outside this repository.** Do not commit filled client
profiles, agreement references, contacts, credentials, captures or reports to
GitHub. The Markdown worksheets are human records, not additional JSON fields,
CLI input schemas, legal permission documents or automatically verified grants.

## A. Install and verify

Follow [the beginner guide](https://github.com/ManeaAl-Shabrain/HunterQA-AI/blob/main/docs/AUTHORIZED_ASSESSMENT_BEGINNER_GUIDE.md) or
[Zero to Start](https://github.com/ManeaAl-Shabrain/HunterQA-AI/blob/v1.3.0/zero%20to%20start.md). Activate the virtual environment and run:

```bash
hunterqa --version
python tools/verify_release_1_3.py
```

This template folder is post-v1.3.0 documentation. The immutable v1.3.0 tag and
published archive do not contain it. Obtain the templates from this branch/current
`main` after merge, or download the folder files, while using the released tool.

## B. Make a private case and copy the templates

Run from the repository directory that contains this `templates` folder. If your
case directory exists, choose a fresh name rather than deleting prior evidence.

```bash
umask 077
mkdir ../client-assessment-001
export HUNTERQA_CASEDIR="$(realpath ../client-assessment-001)"
export HUNTERQA_APPROVED_ROOTS="$HUNTERQA_CASEDIR"

cp templates/HunterQA-scope-template.json "$HUNTERQA_CASEDIR/profile.json"
cp templates/HunterQA-targets-template.txt "$HUNTERQA_CASEDIR/targets.txt"
cp templates/HunterQA-first-configuration-review.md "$HUNTERQA_CASEDIR/INSTRUCTIONS.md"
cp templates/0*.md "$HUNTERQA_CASEDIR/"

printf 'Private case: %s\n' "$HUNTERQA_CASEDIR"
```

Keep this terminal open; a second terminal does not inherit these exported
variables automatically. `INSTRUCTIONS.md` is the unchanged original guide.

## C. Fill and review the files

1. Fill `01-scope-and-approval-notes.md` from the organization's actual approval.
2. Edit `profile.json` and replace program, approval reference and exact host.
3. Set permitted paths, port and method. `/` permits all paths on the listed host;
   use a narrower prefix when required by the agreement.
4. Change `targets.txt` to the exact approved HTTPS endpoint. Keep one URL for
   the first run and leave `max_requests` at one.
5. Apply the owner's exclusions. Empty exclusion lists never expand scope.
6. Keep GET only if GET is approved. If only HEAD is approved, set methods to
   `["HEAD"]` and change both commands below to `--method HEAD`.
7. Set `acknowledged_authorization` to `true` only after confirming written
   permission for that endpoint, method and testing window.

Never put passwords or tokens in these files. Do not add worksheet fields such
as contacts or dates to the JSON and assume they will be enforced: the basic
profile does not verify owner identity, enforce a written testing window or
track the total allowance across repeated invocations.

## D. Preflight — offline

```bash
hunterqa bounty-preflight \
  --profile "$HUNTERQA_CASEDIR/profile.json" \
  --targets "$HUNTERQA_CASEDIR/targets.txt" \
  --method GET
```

Read the result and finish the preflight part of `02-plan-and-run-checklist.md`.
If it fails, correct the actual scope/configuration; do not broaden permissions
merely to make a rejected target pass. This command makes no website request.

## E. Run the approved observation — sends traffic

Only during the approved window and after reviewing the exact endpoint/method:

```bash
hunterqa bounty-assess \
  --profile "$HUNTERQA_CASEDIR/profile.json" \
  --targets "$HUNTERQA_CASEDIR/targets.txt" \
  --method GET \
  --out "$HUNTERQA_CASEDIR/header-review-001.json" \
  --authorized
```

Use a new output name for every separately authorized run, and check that the
file does not already exist **before** sending traffic. This basic command's
output-write check occurs after assessment; an output collision is not a safe
way to prevent repeated requests. Quotas are per invocation, not a company-wide
or cumulative allowance.

`bounty-assess` is separate from `engagement-run` and the supervised workflow
runner. It has no plan-fingerprint or emergency-stop-file option. A STOP file
used by another command does not control it. Ctrl+C requests CLI interruption;
an operation already in progress may still finish and a sent request cannot be
recalled. Coordinate unexpected errors or service problems with the owner.

## F. Inspect and report

```bash
python -m json.tool "$HUNTERQA_CASEDIR/header-review-001.json"
```

Fill `03-findings-and-report.md`. The supported header/cookie checks and their
conditions are listed in the unchanged original instructions. CSP absence is
checked only for GET responses identified as HTML; cookies are checked only if
issued by the selected response. Candidates are informational and require
context, validation and human review.

Do not treat a 200 status as a vulnerability, a 403 as proof of security, missing
headers as automatically exploitable, or an empty finding list as full coverage.

## G. Retest under valid permission

Fill `04-retest-record.md` first. Recheck scope, window and the owner's remaining
total budget. Run the same permitted observation with a fresh output name such
as `header-review-002.json`, then compare the relevant evidence manually.
Missing candidates are not automatically verified repairs.

For additional test types, use [workflow contracts](https://github.com/ManeaAl-Shabrain/HunterQA-AI/blob/v1.3.0/docs/WORKFLOW_RUNNER.md),
[engagement controls](https://github.com/ManeaAl-Shabrain/HunterQA-AI/blob/v1.3.0/docs/APPROVED_ASSESSMENTS.md) or the
[complete beginner guide](https://github.com/ManeaAl-Shabrain/HunterQA-AI/blob/main/docs/AUTHORIZED_ASSESSMENT_BEGINNER_GUIDE.md).
