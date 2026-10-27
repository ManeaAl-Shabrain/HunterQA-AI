# Security limitations and honesty contract

- Pattern matches, CVEs, CWE labels and AI suggestions are not independently proof of a vulnerability.
- No guarantee of discovering all known vulnerabilities or zero-days, particularly authorization/business logic flaws. Those require application-specific environments and tests.
- An intentional SIGABRT is not memory corruption. A sanitizer finding confirms a specific runtime issue in a corresponding build, not its real-world exploitability.
- `HUNTERQA_APPROVED_ROOTS` controls what can be scanned, but code executed by locally compiled binaries **is not sandboxed** by Python path checking; run replay/fuzzing only in a disposable VM with resource and network restrictions.
- Flask's development server is strictly local/single-user; not for deployment on public or corporate networks.
- Rules cover examples in Python, JS/TS and PHP plus selected config files, not all languages or CWEs. Tune and test each rule before reliance.
- Package inventories may include manifest constraints rather than resolved installed versions. The exact-match offline advisory matcher does not replace OSV/NVD vulnerability feeds.
- Optional tools, including Semgrep and Ollama, must be installed on Kali; only local parsers and artifact loaders run without them.
