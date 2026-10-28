# Security Policy

## Supported versions

- **Current maintained line:** the current `main` branch (v1.2.0 code line).
- **Historical release tags:** `v1.0.0`, `v1.0.1`, and `v1.1.0` remain available for reproducibility but do not necessarily receive security backports.
- **Latest published stable:** `v1.2.0`; updates to `main` after tagging do not change the immutable `v1.2.0` archive.

## Responsible reporting

If you believe HunterQA AI contains a security vulnerability, use the repository's
**Security → Report a vulnerability** feature if enabled, or privately contact
the repository owner. Avoid posting exploit details or sensitive evidence in a
public issue before maintainers can investigate.

Provide version/commit, affected functionality, expected versus observed
behavior, minimal reproduction instructions, and security impact when possible.
Do **not** include secret tokens, private host details, unauthorized data, or
user research evidence. Maintainers should confirm and coordinate disclosure
before publicly claiming vulnerability severity or a CVE identifier.

## Authorized research boundaries

HunterQA is designed for local, explicitly authorized projects and isolated
laboratory binaries. Do not use it for unauthorized scanning. "Low-noise" means
local-first, bounded analysis, not evasion of detection or monitoring.

The dashboard is designed for loopback (`127.0.0.1`) and single-user Kali lab
operation. Do not expose the Flask development server publicly.
Application requests also enforce loopback peer addresses and exact local Host
names, ignoring forwarded-address headers. This does not make it suitable for
hosting behind a proxy. A Content Security Policy restricts scripts to local
assets and the dashboard's per-request nonce; imported evidence stays escaped.

All source-review, remediation, report-generation and agent-review Ollama calls
use the exact `http://127.0.0.1:11434/api/generate` endpoint, disable environmental
HTTP proxies and redirects, and bound request/response sizes. No remote fallback
is available. Loopback services still share the operator's local trust boundary.

The original optional Playwright browser lab permits only an owned, explicitly approved
`127.0.0.1` service; Playwright route interception is **not a network firewall**.
Use OS/network isolation for untrusted web content. Controlled HTTP HEAD replay
must follow current program automation permissions and does not forward browser
credentials or sessions. Keep session
secrets, evidence, analyst databases and local snapshots outside GitHub.

Development `engagement-run` separately permits reviewed exact-target HTTP
observations, benign WAF canaries and one dedicated-account HTTPS login per
invocation. Its narrow remote browser mode disables JavaScript and only admits
the exact start/login endpoints. Plans expire within 24 hours, bind to profile
bytes, and require explicit fingerprint approval. Limits apply per invocation;
hashes and account/isolation flags are local attestations, not independently
verified permissions. Stop files act between requests, not on in-flight work.
Private report/CVE request packages do not transmit reports or allocate CVEs.
See [approved assessment controls and remaining limits](docs/APPROVED_ASSESSMENTS.md).

Advisory and CVE matching does not establish exploitability or prove a host is
vulnerable. Neither AI analysis nor a crash report confirms a zero-day by itself.
No scanner provides comprehensive vulnerability coverage or zero false positives.

## Third-party licenses

The root MIT License applies to HunterQA-owned source. Third-party libraries,
tools, models, rules and datasets retain their separate applicable licenses,
usage terms and attribution requirements.
