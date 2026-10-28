# Repository review — October 28, 2026

Baseline: merged `main` commit `9c9138a`, including approved assessment PR #23.
This is a maintenance and evidence-usability review, not a certification that
the entire codebase, dependency ecosystem or future deployment is defect-free.
Historical tags and published release assets remain unchanged.

## Review coverage

The review covered the application factory, routes and templates, SQLite-backed
scan/review workflows, CLI dispatch and output paths, source/dependency and
analyzer adapters, local AI calls and proposal handling, advisory matching and
quality metadata, offline API/agent/verification workflows, HTTP/browser and
assessment controls, campaign/evidence readers, release packaging, documentation,
and CI. Existing tests and targeted regressions accompany the implementation.
Static findings were reviewed in context, rather than all treated as confirmed
vulnerabilities. No external target was scanned or assessed.

## Corrected behavior

| Area | Before | After |
| --- | --- | --- |
| Local AI privacy | Several source/report/remediation clients used the default URL opener, honoring environment proxies and default redirect handling. Report generation also read an unbounded response. | One exact loopback generate endpoint, explicit empty proxy configuration, redirect rejection, bounded requests/responses and object validation. The existing read-only doctor probe already had its own narrow guard. |
| Dashboard access | Loopback binding was documented, but application routes accepted arbitrary Host headers and peer addresses. | Enforce loopback peer addresses and exact local Host names; forwarded-address headers do not override the peer. Public/proxied hosting remains unsupported. |
| Browser rendering | No CSP; a readiness label could appear without checking installed tools. | Local scripts plus a per-request nonce for evidence polling; frames/objects/base changes restricted. The header says “Local workspace,” and the sidebar describes enforced loopback access. |
| Input resilience | Non-ASCII CSRF input and malformed SARIF/agent/Semgrep coordinates could raise exceptions. Relative Semgrep paths could be resolved against the caller's working directory. | Reject invalid CSRF input without a server error; normalize bounded line coordinates, guard nested types, preserve SARIF error labels and resolve relative source paths against the project. |
| File enumeration | Configuration/dependency inventory eagerly sorted a recursive walk before most exclusions and result limits. Some reads checked size only before reading. | Prune dependency/private directories during deterministic walking; cap enumerated entries and bound reads. Exceeding the enumeration cap requests a smaller project rather than claiming a complete scan. These checks are not an OS sandbox against concurrent file replacement. |
| Dependency accuracy | Requirements names did not fully normalize runs of dots/underscores/hyphens; the simple advisory matcher could treat unresolved manifest constraints as exact versions. | Normalize PyPI names consistently and skip unresolved declarations in exact matching. `requirements.txt` now includes the already-required packaging library. |
| Advisory duplicates | Filtering withdrawn records before duplicate resolution could leave an older active copy eligible. | Resolve duplicates with withdrawal records retained, then exclude the selected withdrawn record; ambiguous conflicting records remain excluded. |
| API contract interpretation | An empty security requirement object was treated as invalid even when it represented an anonymous alternative. | Recognize anonymous/optional authentication and keep modifying operations in the manual public-write review queue. This follows the [OpenAPI security requirement definition](https://spec.openapis.org/oas/v3.1.0.html#security-requirement-object); declarations still do not prove runtime access. |
| Campaign paths | Hard-coded colon splitting broke path lists on Windows. | Use the platform path separator consistently. |
| Crash replay | Importing the POSIX resource module blocked unrelated offline commands on Windows; replay output could overwrite previous evidence with default permissions. | Import POSIX limits only where used, explicitly reject executable replay on unsupported systems, validate budgets, bound crash input reads and create output exclusively with mode 0600 on POSIX. No weaker execution fallback was added. |
| Source packages | Archive verification allowed some noncanonical path spellings and symlink metadata; the public setup guide was outside the source builder allowlist. | Reject those members and include the tracked setup guide in newly built source previews. The verifier still never extracts or executes an archive. |
| Maintenance | Unused imports and removable assert checks; limited CI tooling. | Remove dead imports, use explicit validation for model context/doctor status, add quality extras and repeatable checks. |

Two static-tool findings are explicitly documented at their call sites: HTML
rendering escapes all imported text before adding fixed tags, and scan-update
SQL column names come exclusively from a fixed allowlist with bound values.
Those narrow exceptions do not suppress checks elsewhere. Remaining low-severity
subprocess warnings concern the intentional local scanner, generated rule QA,
  release builder and explicitly authorized isolated crash replay; they are not
evidence of arbitrary model command execution.

## Added evidence workflow

- `/assessments` displays administrator-selected saved assessment metadata.
  It has no launch controls and makes no assessment requests on page load.
- `engagement-compare` compares two reports from the same exact plan/profile
  and ordered step identities. Missing status/body evidence remains unknown.
- Unknown imported fields and raw free text are not forwarded to the new view.
  Content fingerprints indicate consistency, not author identity or authenticity.
- Comparison differences do not prove a vulnerability, a fix, successful login,
  account lockout or WAF effectiveness. Interrupted coverage is called out.

See [assessment usage and limits](APPROVED_ASSESSMENTS.md) for the CLI sequence,
environment settings and existing authorization constraints.

## Verification scope

The maintenance tests cover proxy bypass prevention, redirect refusal, response
limits, loopback/Host checks, CSP nonce behavior, Unicode CSRF rejection, nested
analyzer input, name normalization, bounded file enumeration/reads, unsafe archive
members, advisory withdrawal ordering, optional API authentication, and same-plan
evidence comparison. Real Chromium exercises synthetic login responses and the
owned local dashboard, including evidence polling under CSP. POSIX CI exercises
a generated, owned exit-code fixture for private crash output and overwrite refusal.

CI runs source quality, regression, offline acceptance, real browser acceptance,
and source package verification on Ubuntu with Python 3.11 and 3.13. A separate
job validates the actual optional Semgrep executable against all 13 bundled
rules using generated positive/negative Python, JavaScript and PHP snippets;
the snippets are parsed, never executed. This follows the engine's documented
[local rule validation workflow](https://semgrep.dev/docs/writing-rules/testing-rules).
Passing these synthetic cases does not measure real-world precision or recall.
The same fixtures also pass through the production scanner adapter to verify
stable bundled rule IDs and relative file paths. Production Semgrep calls disable
version checks as well as metrics; this does not sandbox the external executable.
Dependency advisory checks use public package metadata and require internet;
they are separate from the tool's default offline research workflow.
The Python 3.11 audit also detected old runner-provided setuptools; CI upgrades
both pip and setuptools before auditing instead of ignoring those advisories.
Checkout/setup actions use their maintained v7 lines.

## Remaining limits

This review does not establish comprehensive vulnerability coverage, independent
authenticity of local evidence/permissions, or isolation against a compromised
operator account. Budget/approval attestations remain per invocation, stop-file
checks do not interrupt in-flight work, browser guards are not a firewall, and
remote form review is deliberately narrow. Optional Semgrep/Ollama/AFL++ binaries,
models, OS permissions and Kali-specific setup must be checked on the actual
workstation. No unrestricted exploit runner, evasion, credential guessing,
automatic disclosure sending, official CVE assignment or discovery guarantee
was introduced. See [security policy](../SECURITY.md).
