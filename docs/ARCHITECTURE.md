# Architecture and evidence lifecycle

**Single codebase, separated trust boundaries.**

1. Browser receives locally bound HTML forms only. Registering a project resolves paths beneath administratively approved roots; starting a scan requires CSRF and explicit typed authorization.
2. `ScanService` queues a single worker, re-checks the scope, runs `orchestrator.scan_local_source` with fixed Semgrep arguments, then persists all normalized findings and dependency inventory to SQLite.
3. Source and configuration detections are **unverified observations**. Semgrep's `ERROR` is a rule label, not CVSS Critical.
4. An optional localhost Ollama model summarizes findings; output is never interpreted as a verified vulnerability or executable instructions.
5. Separate, CLI-only fuzzing workflows execute local approved binaries in a VM. They return crash replays, SHA-256 identifiers, sanitizer classifications and evidence for human review.
6. `research.normalize_research_report` supports both legacy `{crash, ai_analysis}` and integrated flat `{filename, attempts}` formats. The raw AI recommendation is stored only as an unverified suggestion.
7. `evidence.correlate_evidence` correlates sanitizer observations with a crash only if both *input* and *binary* hashes match; correlation is not exploitation proof.
8. `/api/research/export` delivers the normalized research snapshot with the raw source report hash, and `/api/research/evidence` supports browser refresh without executing new scans.

## How to research an unknown weakness

A new finding begins with a **hypothesis** supported by a specific source path and code flow. It is tested in an approved isolated build using non-destructive fixtures, then checked with sanitizer diagnostics, repeated reproduction, and a root-cause review. Only verified novel issues should be submitted privately to a maintainer or the relevant bug-bounty program. Do not assume novelty from absence of a CWE/CVE match.

## Research engines requiring optional external installation

- `semgrep`: active static source analyzer (required for unified full scans).
- `afl-clang-fast`/`afl-fuzz`, `clang` and sanitizers: isolated instrumented binary research, CLI only.
- CodeQL/Ghidra: not bundled, optional specialist tools. SARIF output can be imported as evidence; this project does not claim to run Ghidra automatically.
- Python `Ollama` HTTP service: local model reasoning; no cloud API is used.

## Scaling on 2 vCPUs, 5 GB RAM

Use 3B model, one scan worker, one AFL++ worker, and avoid running all of them simultaneously. The VM's virtual disk and host RAM can become bottlenecks. Keep test crash artifacts outside Git.
