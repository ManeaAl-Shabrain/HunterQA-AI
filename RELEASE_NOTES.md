# HunterQA AI — Unified source release

This is **one integrated repository**, assembled from the user's uploaded ZeroScope dashboard rather than a separate replacement application.

## Incorporated

- HunterQA branding, imports and `hunterqa` console entry point; backward import shims and non-destructive database migration.
- Original Flask project/scan workflow, local Semgrep and Qwen reporting, JSON scan exports.
- Unified source orchestrator, deterministic Docker/K8s/Terraform/OpenAPI checks, and dependency inventory saved with each scan.
- Offline advisory exact-version matcher and read-only CodeQL/SARIF adapter.
- AI source hypothesis generator and dedicated dashboard page; no automatic model-generated command execution.
- Existing legacy/integrated research JSON reader, bug-fixed AFL++ signal/filename/size normalization and strict correlation by input+binary hash.
- Local AFL++ experimental C examples, sanitized crash replay, and ASan/UBSan parsing.
- Research dashboard with fuzzer stats, sanitizer evidence, refresh, export, and proof hashes.
- Audit-history view, auto-updating scan status, single worker, CSS improvements, safe minimal Markdown rendering.
- Expanded automated tests and offline smoke checks.

## Not claimed

- Complete automatic detection across every CWE or business logic condition.
- Real-world zero-day confirmation, exploitation, live site scanning, threat evasion, or production multi-user readiness.
- Full Kali integration tests executed in this build container. Required dependencies such as Flask and Semgrep were unavailable here; run `python -m pytest -q` and `semgrep scan --config hunterqa/rules/semgrep.yml ...` on Kali before relying on results.
