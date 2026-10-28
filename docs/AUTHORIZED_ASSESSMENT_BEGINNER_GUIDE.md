# Authorized Assessment — Beginner’s Guide

![HunterQA: scope, review, assess, evidence, verify and report](assets/hunterqa-cybersecurity-infographic.png)

**A practical first assessment with HunterQA v1.3.0 on Kali/Linux.**

Start with one explicitly approved URL and one small check. Confirm the setup and
review the evidence before expanding within the organization's testing plan.
Replace `app.company.example` below with the exact hostname you are authorized
to assess. Examples are instructions for your own approved environment; this
guide grants no permission and sends no traffic by itself.

[Project overview](../README.md) · [Full Kali setup](../zero%20to%20start.md) · [Workflow contracts](WORKFLOW_RUNNER.md)

## Assessment route

**Confirm scope → create a private case → review the plan → run a small check → inspect evidence → report.**

| Step | Outcome |
| --- | --- |
| 1–2 | Confirm permission and install the released version |
| 3–4 | Create private storage and an exact scope profile |
| 5–7 | Plan, review and execute one approved observation |
| 8 | Interpret the result and open the saved-assessment dashboard |
| 9–10 | Select further permitted modules and report evidence accurately |

## 1. Confirm what the organization permits

Your written agreement should identify:

| Item | Example |
| --- | --- |
| Targets | `app.company.example` |
| Allowed areas | Entire website, or only `/portal` |
| Permitted tests | HTTP observations, source review, specific validation checks |
| Testing window | Agreed dates and hours |
| Traffic limits | Total requests and request frequency |
| Contact | Person to notify if testing causes problems |
| Test accounts | Dedicated accounts, if account testing is approved |

Permission for one website does not automatically include other subdomains,
its hosting provider, or third-party services. HunterQA records your authorization
reference; it does not independently verify the agreement. This walkthrough
assumes the owner permits the exact HEAD observation you select.

## 2. Install the released version

For a fresh Kali/Linux installation:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip

git clone --branch v1.3.0 --depth 1 \
  https://github.com/ManeaAl-Shabrain/HunterQA-AI.git HunterQA-v1.3.0

cd HunterQA-v1.3.0
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'

hunterqa --version
```

Expected output:

```text
HunterQA AI 1.3.0
```

Check the installation with the included offline exercise:

```bash
python tools/verify_release_1_3.py
```

The exercise uses temporary synthetic files and sends no requests to the
organization's website. If HunterQA is already installed, activate its virtual
environment and check its version instead of cloning again.

This additional guide was published after the immutable v1.3.0 tag. Cloning that
tag retrieves the released tool; read this guide on the current documentation
branch or GitHub. Historical release assets are unchanged.

## 3. Create a private assessment folder

Keep client evidence outside the public HunterQA repository:

```bash
umask 077
mkdir ../client-assessment-001

export HUNTERQA_CASEDIR="$(realpath ../client-assessment-001)"
export HUNTERQA_APPROVED_ROOTS="$HUNTERQA_CASEDIR"

printf 'Case directory: %s\n' "$HUNTERQA_CASEDIR"
```

Keep this terminal open. These settings apply to this terminal session. Save the
printed absolute case path for use from a second terminal.

If the directory exists, choose another name, such as `client-assessment-002`.
Preserve previous evidence rather than deleting it to reuse an output name.

## 4. Record the authorized scope

Create a private profile:

```bash
nano "$HUNTERQA_CASEDIR/profile.json"
```

Paste the following and replace the organization, hostname and approval reference:

```json
{
  "program": "Organization approved assessment",
  "platform": "private",
  "authorization_reference": "Written approval reference ORG-2026-001",
  "acknowledged_authorization": true,
  "allowed_hosts": ["app.company.example"],
  "excluded_hosts": [],
  "allowed_paths": ["/"],
  "excluded_paths": [],
  "methods": ["HEAD"],
  "allowed_ports": [443],
  "max_requests": 1,
  "interval_seconds": 2,
  "lab_mode": false,
  "allow_private_network": false,
  "allow_http": false
}
```

In Nano, press **Ctrl+O**, Enter, then **Ctrl+X**.

| Field | How to use it |
| --- | --- |
| `allowed_hosts` | Exact approved hostnames, without `https://` |
| `allowed_paths` | Approved path prefixes; `/` permits any path on the listed host |
| `methods` | This first example permits only HEAD |
| `max_requests` | Keep the first check to one request per invocation |
| `interval_seconds` | Minimum interval between requests |
| Exclusion lists | Empty lists never expand the allowlist |

If only `/portal` is approved, use that prefix and test that URL instead of `/`.
Keep `/` only when it matches the actual permission. The reviewed plan below
further restricts the observation to its exact URL.

For internal/private-network systems, use a separately configured profile that
matches the documented lab/network controls. Do not change network switches
merely to bypass a rejection.

## 5. Create a small assessment plan

A HEAD request asks for response metadata without requesting the normal page
body. It is a useful first observation, not a complete vulnerability scan.

```bash
hunterqa engagement-plan \
  --profile "$HUNTERQA_CASEDIR/profile.json" \
  --url "https://app.company.example/" \
  --mode observe \
  --method HEAD \
  --ttl-minutes 30 \
  --out "$HUNTERQA_CASEDIR/plan-001.json"
```

Use an expiry that fits the owner's approved testing window. This command creates
a plan; **it does not contact the website**. If only `/portal` is approved, use
that path in the profile and URL.

## 6. Review the plan before sending traffic

```bash
hunterqa engagement-preflight \
  --profile "$HUNTERQA_CASEDIR/profile.json" \
  --plan "$HUNTERQA_CASEDIR/plan-001.json"
```

Read the hostname, exact URL, method, expiry and authorization reference. The
output includes `approval_sha256`. Copy its complete value: it identifies the
exact plan you reviewed. Editing the plan or profile requires another review.

Preflight is offline. It does not authenticate the permission document or prove
that a live target is safe to test.

## 7. Run the approved check

Replace `PASTE_APPROVAL_SHA256` with the fingerprint from preflight:

```bash
hunterqa engagement-run \
  --profile "$HUNTERQA_CASEDIR/profile.json" \
  --plan "$HUNTERQA_CASEDIR/plan-001.json" \
  --approve-plan PASTE_APPROVAL_SHA256 \
  --stop-file "$HUNTERQA_CASEDIR/STOP" \
  --out "$HUNTERQA_CASEDIR/result-001.json" \
  --authorized
```

**This command sends the request.** Run it only during the approved window.
The request budget applies per invocation; it is not an organization-wide total
across repeated runs. Track the owner's total allowance yourself and repeat
only when the agreement permits it.

To prevent further requests, use a second terminal and substitute the absolute
case path printed earlier:

```bash
touch /absolute/path/to/client-assessment-001/STOP
```

The second terminal does not automatically inherit the exported case variables.
For these separate engagement commands, an operation already in flight may
finish before stopping. The supervised workflow runner has stronger worker
cancellation controls. A sent request cannot be recalled.

## 8. Read the result

```bash
python -m json.tool "$HUNTERQA_CASEDIR/result-001.json"
```

| Result | Meaning and response |
| --- | --- |
| 200 | Endpoint responded successfully; this alone is not a vulnerability |
| 301 / 302 | Redirect observed; HunterQA stops instead of following it |
| 401 / 403 | Authentication/access restriction observed; testing stops |
| 429 | Rate limiting observed; stop and coordinate with the owner |
| 5xx | Server error observed; stop and investigate with the owner |
| Transport error | Connection, DNS, TLS or another transport problem; inconclusive |

Do not report a status code alone as a confirmed security issue. Keep a transport
or preflight failure distinct from a target vulnerability.

### View the saved assessment

In the original repository terminal, with the virtual environment active:

```bash
export HUNTERQA_ENGAGEMENT_REPORT="$HUNTERQA_CASEDIR/result-001.json"
python run.py
```

Open **http://127.0.0.1:5000/assessments**. Keep the dashboard on loopback and
press **Ctrl+C** to stop it. The saved-assessment page displays evidence; opening
it does not launch another test.

## 9. Choose the next approved module

| Available input or need | Next step |
| --- | --- |
| Organization-provided source code | `audit` for configuration/API/dependency review; `scan` for Semgrep-backed analysis |
| OpenAPI specification | `bounty-api-inventory` |
| Existing Nuclei/ZAP output | `external-import`; importing does not launch a scanner |
| Several approved steps | `workflow-setup`, `workflow-run-plan`, then explicitly approved `workflow-run` |
| Approved dedicated test accounts | Separate engagement account/browser modes, with their specific controls |
| Candidates needing validation | Human evidence review, documented impact and an independent retest |

Only if the organization supplies authorized source code, place it in the
case's `source` directory and run:

```bash
hunterqa audit \
  --project "$HUNTERQA_CASEDIR/source" \
  --out "$HUNTERQA_CASEDIR/source-review.json"
```

Scanning an empty local directory does not assess a remote website's source.
The basic audit does not need Semgrep; `scan` requires the separately installed
Semgrep executable. Use `hunterqa COMMAND --help` before selecting further modes.

Read [workflow contracts](WORKFLOW_RUNNER.md) for multi-step execution,
[engagement controls](APPROVED_ASSESSMENTS.md) for account/browser modes, and
[research interoperability](RESEARCH_WORKFLOWS.md) for imported evidence.

## 10. Report what you actually established

Your report should distinguish:

- Targets, actions and testing window approved by the organization.
- Tool version, methods, timing and steps actually performed.
- Observations and supporting private evidence.
- Findings still unverified, including uncertainty and testing limits.
- Impact independently established and remediation supported by that evidence.
- Results of a separately authorized retest.

The first observation checks your setup and scope controls. A complete security
assessment needs a defined test plan and appropriate validated evidence for its
selected areas. HunterQA does not automatically establish exploitability,
business impact, official CVE assignment or complete security coverage.

For installation, the full offline lesson and ongoing maintenance, use
[Zero to Start](../zero%20to%20start.md). For the published tool and verified
archive/checksum, use the [v1.3.0 release](https://github.com/ManeaAl-Shabrain/HunterQA-AI/releases/tag/v1.3.0).
