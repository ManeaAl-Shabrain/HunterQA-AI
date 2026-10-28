# HunterQA AI 1.0.0 — Candidate Release Notes

**Status: Release review candidate; not tagged or merged into \`main\`.**
Built as one cumulative source tree from the former ZeroScope dashboard, retaining the existing local-only workflow and analyst database.

## Consolidated capabilities

- Authorized source scans: Semgrep local rules, selected configuration and OpenAPI checks, dependency inventory and source trust graphs.
- Local optional Qwen/Ollama hypotheses, bounded batch research, evidence-linked triage, analyst review decisions and remediation proposal safety gates.
- AFL++/ASan/UBSan research evidence, bounded local replay in isolated VMs, source location and hash-based correlation.
- Offline OSV CVE intelligence with exact pinned requirements plus supported npm/Composer/Poetry/uv lockfiles, selected version intervals, conservative unknown states and alias-preserving CVE grouping.
- Research Analytics, Campaign History, Research Trends, CVE Intelligence and Audit History dashboards.
- Persisted Flask session key support, local Release Doctor, disposable-database route tests, full source archive SHA-256 validation, pull-request CI.

## Previously observed local acceptance (8.7 ancestor)

The operator reported **119 passing pytest tests**, **9 passing Flask routes**, **Release Doctor ready without warnings**, and **122 verified archive source files** on Kali. Manual browser acceptance was subsequently reported complete. These observations refer to the 8.7 build. The 1.0 review branch adds documentation, release tooling metadata and CI and therefore requires a new final acceptance run.

## Release readiness requirements

1. Run \`bash tools/verify_release_8_6.sh\` on the final branch and check the exit code.
2. Confirm all relevant GitHub pull-request CI checks pass.
3. Review the full PR against \`main\`, including filesystem authorization, local JSON parsers, dependency intelligence and archive scripts.
4. Back up existing local SQLite analyst history; confirm UI and single-user loopback binding.
5. Build and verify \`HunterQA-AI-1.0.0-source.zip\` and inspect it for sensitive files.
6. Verify the source project's license, third-party dependencies and disclosure/security handling.
7. Obtain explicit approval before merging, tagging or publishing a GitHub stable release.

## Not claimed

- 100% detection of vulnerabilities, guaranteed zero false positives, or an official CVE assignment.
- Independently proven exploitable defects from every matched advisory, sanitizer diagnostic or AI hypothesis.
- Automatic safe execution of code, secure isolation of untrusted native binaries or production multi-user readiness.
- Cryptographically authenticated advisory snapshots from user-entered acquisition timestamps.
- Installed-package attestation from a lockfile alone.

See \`docs/RELEASE_1_0_CHECKLIST.md\` for review, rollback and merge plan.
