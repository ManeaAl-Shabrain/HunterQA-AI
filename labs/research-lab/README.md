# HunterQA AI — Historical Kali Research Lab Sources

These source files were copied from the developer's earlier ZeroScope AI lab into
the same HunterQA AI repository for **archival, reproducible local research**.

They are examples, not additional production scanner engines. The core HunterQA
CLI and dashboard remain in `hunterqa/` and `zeroscope/`.

## File groups

- `fuzz_target.c`: intentionally calls `abort()` after a specific test input; this
  is a deliberate crash, NOT evidence of memory corruption or a zero-day.
- `uaf_test.c`: intentionally reads freed heap memory to demonstrate
  AddressSanitizer. Build or run only inside an isolated lab VM.
- `memory_test.c`: benign memory allocation/free sanity example.
- `crash_evidence.py`, `ai_crash_analyzer.py`, `validate_ai.py`: older
  source-bound crash collection, local Ollama analysis and human verification
  support. These are not interchangeable with the unified engine reports.
- `verification/`: older crash replay and sanitizer JSON integration scripts;
  `verify_crashes.py` contains lab-specific absolute paths.

## Safe use

Do not run the historical scripts directly against unknown or unauthorized
programs. Some scripts execute local compiled binaries, use legacy relative
input filenames, or overwrite JSON **within the laboratory directory**.
Review paths and use disposable fixtures before any execution. The
`uaf_test.c` source is intentionally vulnerable and must never be reused as
production logic.

The source archive includes these files but **excludes** runtime crashes,
logs, private JSON reports, compiled binaries, database files and secrets.
Those remain only on the original Kali machine unless explicitly exported.

Research findings (including sanitizer diagnostics and CVE matches) require
human review and do not independently confirm exploitation or zero-day status.
