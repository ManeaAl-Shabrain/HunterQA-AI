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

The optional Playwright browser lab permits only an owned, explicitly approved
`127.0.0.1` service; Playwright route interception is **not a network firewall**.
Use OS/network isolation for untrusted web content. Controlled HTTP HEAD replay
must follow current program automation permissions and does not forward browser
credentials or sessions. Keep session
secrets, evidence, analyst databases and local snapshots outside GitHub.

Advisory and CVE matching does not establish exploitability or prove a host is
vulnerable. Neither AI analysis nor a crash report confirms a zero-day by itself.
No scanner provides comprehensive vulnerability coverage or zero false positives.

## Third-party licenses

The root MIT License applies to HunterQA-owned source. Third-party libraries,
tools, models, rules and datasets retain their separate applicable licenses,
usage terms and attribution requirements.
