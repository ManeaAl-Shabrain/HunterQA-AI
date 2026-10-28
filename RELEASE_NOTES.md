# HunterQA AI 1.0.0 — Stable Local Research Release

**Release:** HunterQA AI 1.0.0 for local explicitly authorized Kali Linux security research.
Built as one cumulative source tree from the former ZeroScope dashboard, retaining the existing local-only workflow and analyst database.

## Consolidated capabilities

- Authorized source scans: Semgrep local rules, selected configuration and OpenAPI checks, dependency inventory and source trust graphs.
- Local optional Qwen/Ollama hypotheses, bounded batch research, evidence-linked triage, analyst review decisions and remediation proposal safety gates.
- AFL++/ASan/UBSan research evidence, bounded local replay in isolated VMs, source location and hash-based correlation.
- Offline OSV CVE intelligence with exact pinned requirements plus supported npm/Composer/Poetry/uv lockfiles, selected version intervals, conservative unknown states and alias-preserving CVE grouping.
- Research Analytics, Campaign History, Research Trends, CVE Intelligence and Audit History dashboards.
- Persisted Flask session key support, local Release Doctor, disposable-database route tests, full source archive SHA-256 validation, pull-request CI.

## Previously observed local acceptance (8.7 ancestor)

The operator confirmed **119 passing pytest tests**, **9 passing Flask routes**, **Release Doctor ready without warnings**, and **132 source files verified** after the 1.0 compatibility packaging fix, together with manual browser acceptance. Subsequent license/archive packaging changes were checked via the GitHub PR CI workflow before merge. These results indicate tested local behavior, not a security certification.

## Release readiness requirements

1. Run `bash tools/verify_release_8_6.sh` on the final branch and check the exit code.
2. Confirm all relevant GitHub pull-request CI checks pass.
3. Review the full PR against `main`, including filesystem authorization, local JSON parsers, dependency intelligence and archive scripts.
4. Back up existing local SQLite analyst history; confirm UI and single-user loopback binding.
5. Build and verify `HunterQA-AI-1.0.0-source.zip` and inspect it for sensitive files.
6. Review the MIT root license, separate third-party license obligations and `SECURITY.md` responsible-disclosure practices.
7. Tag only the reviewed `main` commit and attach the archive matching that exact commit.

## Not claimed

- 100% detection of vulnerabilities, guaranteed zero false positives, or an official CVE assignment.
- Independently proven exploitable defects from every matched advisory, sanitizer diagnostic or AI hypothesis.
- Automatic safe execution of code, secure isolation of untrusted native binaries or production multi-user readiness.
- Cryptographically authenticated advisory snapshots from user-entered acquisition timestamps.
- Installed-package attestation from a lockfile alone.

See `docs/RELEASE_1_0_CHECKLIST.md` for review, rollback and merge plan.

## Licensing

HunterQA-owned source is licensed under MIT (`LICENSE`). Third-party tools, models, dependencies and vulnerability datasets retain their original licensing conditions and usage restrictions.
