# HunterQA AI Phase 7.7 — proposal-only AI remediation

This feature uses local Ollama to suggest a **single-line** edit and regression-test idea for a source-grounded unified triage record. It is intentionally conservative. The proposal is not applied, built, executed, or treated as a confirmed security fix.

## Usage on Kali

```bash
cd ~/Desktop/HunterQA-AI
source .venv/bin/activate
export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/research-lab:$HOME/ZeroScope-AI/targets"
python -m pytest -q

python -m hunterqa propose-fix \
  --project "$HOME/ZeroScope-AI/targets" \
  --triage "$HOME/ZeroScope-AI/research-lab/verification/hunterqa_unified_triage.json" \
  --finding FINDING_ID_FROM_TRIAGE_REPORT \
  --out "$HOME/ZeroScope-AI/research-lab/verification/hunterqa_fix_proposal.json" \
  --authorized
```

The chosen record must be a source-level `scan` or `ai` finding with a valid local source file and line number. The output includes hashes of the source report, triage report and source file, a proposed diff, a regression-test idea, and unverified status.

Review suggestions manually. **Do not apply arbitrary model output directly.** This implementation does not apply changes or run tests and is not suitable for multi-line/import-requiring repairs. A diff is shown only if the model returns a bounded single-line replacement. The generated proposal can still be incorrect or insecure.

Never point the CLI at a remote target. Avoid running it on secrets or personal content.
