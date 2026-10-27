# Phase 8.1 — Local Release Doctor

HunterQA AI's doctor command runs non-destructive, local release checks. It verifies Python, Flask, Semgrep executable presence, bundled rules, approved roots, optional project scope, and session-secret configuration. The Ollama model-list check is **opt-in** and restricted to HTTP 127.0.0.1:11434 with proxy bypass, redirect rejection and a bounded response size.

## Kali

```bash
cd ~/Desktop/HunterQA-AI
git fetch origin
git switch --track origin/feature/phase-8-1-release-doctor
source .venv/bin/activate
python -m compileall -q hunterqa
python -m pytest -q
export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"
python -m hunterqa doctor --project "$HOME/ZeroScope-AI/targets"
python -m hunterqa doctor --project "$HOME/ZeroScope-AI/targets" --check-ollama --json
```

If the branch is already tracked locally, use `git switch feature/phase-8-1-release-doctor`. Never paste your actual session secret into reports or screenshots.

The doctor does **not** run Semgrep scans, start Flask, invoke AI inference, execute source code, connect to the internet, inspect live listening sockets, or certify security. `ok` means only that a specific readiness check passed. `warning` means reduced readiness; `fail` means an essential check did not pass.

Phase 8.1 is stacked on Phase 8.0's release candidate. Do not merge blindly into main while parent PRs remain under review.
