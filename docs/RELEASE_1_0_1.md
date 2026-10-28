# HunterQA AI 1.0.1 — Kali Research Source Integration

**Stable local research maintenance release**, building on the already published
HunterQA AI v1.0.0. Version 1.0.0 remains intact.

## New in 1.0.1

- Integrated ten historical Kali ZeroScope research source/test files under
  `labs/research-lab/`, including AFL++ crash example, intentionally vulnerable
  use-after-free demo, sanitizer parser, crash replay and local Ollama scripts.
- Documented intentional crash and UAF test behavior in
  `labs/research-lab/README.md`.
- Source release builder now includes approved lab **source files** while
  explicitly excluding lab JSON findings, log data, binaries and private research
  evidence. This packaging rule is covered by regression tests.
- Updated `.gitignore` to exclude generated Python egg-info artifacts.
- Preserved the unified HunterQA scanner, CVE intelligence, Flask dashboard,
  Qwen analysis, triage, history, tests and all existing research engines.

## Safety and scope

The imported examples are **historical lab code**, not newly confirmed security
vulnerabilities or standalone production scanners. Never compile/run the deliberate
use-after-free sample or replay unknown binaries outside a dedicated isolated VM.
The intentionally triggered `abort()` in `fuzz_target.c` is not proof of
memory corruption or exploitation. Outputs require human verification.

Only Git-tracked source code is published. Your local Kali evidence, private
reports, stored crashes, virtual environment, SQLite databases and session
secrets are not automatically uploaded or included in the release ZIP.

## Installation

```bash
cd ~/Desktop/HunterQA-AI
git status --short
git switch main
git pull --ff-only origin main
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q
```

## Release verification

A successful release CI run is required before publishing. Source archive is
built from the tagged commit; it is checked against a per-file SHA-256 manifest.
Checksum files are supplied alongside the release ZIP. This checks file
consistency and cannot guarantee publisher authenticity or absolute security.

HunterQA is local-first and authorization-gated; it does not guarantee complete
vulnerability discovery, zero false positives or independently assign CVEs.

**License:** MIT for HunterQA-authored source, subject to external
dependencies' and datasets' separate licenses.
