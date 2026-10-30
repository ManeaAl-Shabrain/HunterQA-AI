# Establish HunterQA for supported owned-lab use

**Scope:** current development source, local single operator, explicitly owned
loopback fixtures. Real-world effectiveness remains **unverified**, as requested.
The [checked feature list](FEATURE_READINESS_CHECKLIST.md) marks individual
implemented capabilities and unfinished work across all seven areas.

## What the marks mean

| Mark / result | Meaning |
| --- | --- |
| `[x]` in the feature list | A bounded capability exists in source; check its adapter contract and dependencies |
| `[ ]` in the feature list | Not implemented to the requested breadth; do not advertise or rely on it |
| `installation_ready` | Required local packages, approved roots and any configured shared ledger pass local checks |
| `supported_owned_lab_checks_passed` | Current installation checks pass and retained owned-lab results match the installed fixture/runtime and recomputed evidence |
| `production_multi_user_ready: false` | Hosted/tenant isolation, verified owner grants, OS sandboxing and distributed enforcement remain incomplete; optional local dashboard roles are separate |

All seven broad categories are still partial. A passed lab does not establish
comprehensive SQLi/XSS/SSRF/upload/traversal, JS/session/SSO coverage, AD attack
paths, broad cloud permissions coverage, or an independently measured field
detection rate. AWS has synthetic API-contract tests; no live AWS account has
validated the adapter. Published v1.3.0 artifacts are unchanged.

## 1. Install current source on Kali/Linux

Use the repository checkout containing `assessment-readiness`; the original
v1.3.0 ZIP does not contain these post-release commands.

```bash
cd HunterQA-AI
git switch main
git pull --ff-only
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev,quality]'

mkdir -p "$HOME/hunterqa-private"
chmod 700 "$HOME/hunterqa-private"
export HUNTERQA_APPROVED_ROOTS="$HOME/hunterqa-private"

hunterqa coverage-audit --format markdown
hunterqa assessment-readiness
```

The readiness command reads local configuration only. It launches no scanner,
model, browser, customer assessment or subprocess and makes no network request.
It does not read AWS environment credentials or dedicated-account credential files.
Root paths and secret values are not displayed. Semgrep and the cloud extra are
reported separately; neither is required for the fixed owned HTTP/TCP lab.

When `HUNTERQA_OPERATOR_DB` is configured, readiness also checks its public account
metadata, separate control root and persistent key configuration. It does not
attempt login or show passwords, hashes or keys. See [local operator access](OPERATOR_ACCESS.md).

Optional AWS adapter dependencies: `python -m pip install -e '.[cloud]'`.
Optional browser checks need `.[browser]` and installed Playwright Chromium.
Install or change dependencies **before** producing benchmark evidence or approving
an assessment; runtime changes require a new review and owned lab run.

## 2. Run the owned lab

```bash
hunterqa assessment-benchmark \
  --out-dir "$HOME/hunterqa-private/lab-001" --authorized
```

This command creates and closes its own `127.0.0.1` fixture server. It performs:

- Eight positive/negative application cases covering inert markup reflection,
  quote-related SQL error cues and explicit access contracts.
- Three additional workflow controls covering link/form discovery, scope and
  response-field privacy, and exact open/refused TCP connections.
- Four supervised workflows with retained protocols, manifests, journals, reports,
  result/audit hashes and per-class fixture metrics.

A normal successful run records **18 network operations**: 16 HTTP requests and
two TCP connections. It reserves 19 request units, including one unused discovery
slot. If `HUNTERQA_QUOTA_LEDGER` is configured, those shared quotas also apply;
allow sufficient remaining budget and an active-run slot. Unused reservations
are not refunded. This command never accepts a remote benchmark target.

The toy SQL database is private, in memory and query-only. Fixture HTML uses a
restrictive CSP sandbox and disables browser scripts. This benchmark does not
exercise JavaScript crawling or prove executable XSS. A separate optional
[owned-browser rendered-link crawl](BROWSER_LAB_V1_2.md#rendered-link-discovery-development-source)
has real Chromium regression tests; it does not make the seven broad areas complete.

## 3. Recompute readiness from retained evidence

```bash
hunterqa assessment-readiness \
  --benchmark-dir "$HOME/hunterqa-private/lab-001" --require-owned-lab
```

Expect `supported_owned_lab_checks_passed: true` only when all required checks and
the retained evidence pass. `--require-owned-lab` exits with code **2** otherwise;
the default inspection mode prints a report without treating missing lab evidence
as a command failure.

Readiness recomputes findings/metrics, workflow controls, audit/journal consistency
and request receipts from the four private run directories. It compares fixture
labels, fixture source and installed-runtime fingerprints. It does not trust the
saved `all_cases_matched` flag alone and never automatically starts another lab.

| Evidence state | Action |
| --- | --- |
| `integrity_checked`, `passed: true` | The recorded owned fixture baseline matches this installed runtime |
| `not_provided` | Run the owned benchmark, then supply its directory |
| `stale` | Code, fixture labels or runtime changed; use a new benchmark output directory |
| `invalid` | Missing/changed evidence or inconsistent claims; inspect retained files and rerun after resolving the cause |

Keep the whole directory, not only `benchmark.json`. Each benchmark output is
create-only. An old, interrupted or invalid run is never automatically replayed.
Readiness is retrospective evidence checking, not a live network health check.
Hashes detect inconsistency; the evidence-directory owner can forge a consistent
history. This is not a signature, independent audit or security certification.

## 4. Prepare a customer assessment separately

```bash
hunterqa assessment-readiness \
  --profile "$HOME/hunterqa-private/customer-scope.json" \
  --benchmark-dir "$HOME/hunterqa-private/lab-001"
```

This parses a private profile offline and reports its hash, GET admission and
limits without contacting targets. It does **not** verify target ownership,
credentials, customer consent or vulnerability detection effectiveness.

Follow the [beginner guide](AUTHORIZED_ASSESSMENT_BEGINNER_GUIDE.md),
[discovery guide](SCOPED_WEB_DISCOVERY.md), and
[assessment adapter contracts](ASSESSMENT_ADAPTERS.md). Customer traffic still
requires its own written authorization, exact scoped protocol, execution review,
active checkpoints and testing window. A lab pass never replaces those approvals.
