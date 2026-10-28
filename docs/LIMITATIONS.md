# HunterQA AI v1.2.0 — Security Limitations

Development source additionally includes [approved assessment plans](APPROVED_ASSESSMENTS.md):
bounded fixed observations, benign WAF canaries, one designated-account HTTPS
login, narrow remote browser form review, and offline reviewed handoff packages.
The v1.2-specific command limits below still apply to the original commands.
The new modes require expiring fingerprint approval and retain unverified
observations, per-invocation budgets, no evasion/guessing, no automatic
submission/official CVE allocation, and no guaranteed vulnerability discovery.

## Interpretation of results

- **No guaranteed coverage:** HunterQA cannot find every CWE, CVE,
  business-logic defect, authorization issue or novel zero-day.
- **Source/Semgrep/AI candidates:** rule matches, trust graphs and local
  Qwen hypotheses are prompts for analyst investigation, not verified
  vulnerabilities or independently established severity ratings.
- **Advisory intelligence:** OSV/CVE matching is based on supplied local
  snapshots and declared dependency metadata; no proof of runtime
  installation, reachability, current data or exploitability.
- **Sanitizer and fuzz evidence:** a crash or ASan/UBSan diagnostic can
  identify a specific controlled runtime behavior, but is not necessarily
  a security defect or remotely exploitable vulnerability.
- **API/HTTP review:** missing OpenAPI security declarations, resource ID
  routes, absent headers and changing HEAD status codes are not proof of
  broken access control or a bounty-eligible issue.
- **Synthetic benchmark:** v1.2's labeled API review-cue precision,
  recall and false-positive rate apply only to two small synthetic
  contracts, not to real vulnerability detection or zero-day accuracy.
- **Human validation:** SHA-256-linked analyst review decisions and
  reproduction notes are self-attested local evidence, not signed,
  tamper-proof third-party verification. Independent review remains vital.

## Authorization and network boundaries

- **Explicit permission required** for all security research; determine
  asset scope, allowed request methods, traffic budgets, exclusions and
  disclosure rules from the owner/program's current written terms.
- **Live bounty requests:** v1.1/v1.2 only supports bounded
  authorization-gated HEAD/GET observations. It doesn't implement
  automatic unrestricted web crawling, authenticated attacks, bypasses,
  large-scale fuzzing or submission to bounty platforms.
- **Controlled HAR HEAD replay:** uses existing sanitized approved
  captures and no credentials, cookies, request bodies or redirects;
  this is NOT equivalent to replaying an authenticated browser request.
- **Browser research:** Playwright laboratory accepts only one exact
  self-owned `127.0.0.1` service with restricted methods and optionally
  a single approved form login.
- **Browser interception is not a host firewall.** Run untrusted
  browser content in an OS/network-isolated environment. Do not assume
  route interception blocks every class of browser/network egress.
- **"Low noise" is not stealth:** no proxy/IP rotation to evade blocks,
  WAF bypass, fingerprint spoofing, monitoring evasion or retry loops.
- **No automatic AI command execution:** fixed specialist roles and
  loopback-only model review; this is not an autonomous exploit system.

## Local environment, privacy and deployment

- **Approved roots are not OS sandboxes:** an approved filesystem
  location does not safely confine a binary, fuzz target, imported
  executable project, or browser process.
- **Single-user Flask:** development server listens on loopback only;
  do not bind it publicly or run it as a hosted multi-tenant product.
- **Private outputs:** keep cookies, API keys, browser credentials,
  raw HAR, unreleased findings, customer targets and SQLite data out
  of public Git. Use private approved directories and separate
  backups.
- **Optional local tooling:** Semgrep, Ollama, Playwright and AFL++
  are not all installed by default; supported capability depends
  on actual local tools and resource availability.
- **Archive checksums:** SHA-256 detects accidental content changes,
  not independent publisher identity. Review provenance, release
  tag, license and current program authorization.

## Responsible disclosure

- Confirm a candidate using only approved test accounts/assets.
- Document reproduction and impact with minimal non-sensitive evidence.
- Follow the current program's response, submission and disclosure
  requirements; HunterQA never allocates CVEs.
- For suspected vulnerabilities in HunterQA itself, follow
  [SECURITY.md](../SECURITY.md).

See [README](../README.md), [architecture](ARCHITECTURE.md),
[verification workflow](REVIEW_V1_2.md), and
[versioning policy](VERSIONING.md).
