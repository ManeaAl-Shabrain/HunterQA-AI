# Security Policy

## Supported versions

Security maintenance targets the latest version on `main`, starting with HunterQA AI v1.0.0.

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
operation. Do not expose the Flask development server publicly. Keep session
secrets, evidence, analyst databases and local snapshots outside GitHub.

Advisory and CVE matching does not establish exploitability or prove a host is
vulnerable. Neither AI analysis nor a crash report confirms a zero-day by itself.
No scanner provides comprehensive vulnerability coverage or zero false positives.

## Third-party licenses

The root MIT License applies to HunterQA-owned source. Third-party libraries,
tools, models, rules and datasets retain their separate applicable licenses,
usage terms and attribution requirements.
