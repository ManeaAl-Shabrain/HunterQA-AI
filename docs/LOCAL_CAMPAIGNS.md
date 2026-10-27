# HunterQA AI Phase 7.8 — Bounded Local Campaigns

A campaign runs selected authorized local engines sequentially and writes an evidence manifest into a **new** directory. No remote target input is accepted.

## 1. Checkout in Kali

```bash
cd ~/Desktop/HunterQA-AI
git fetch origin
git switch --track origin/feature/phase-7-8-local-campaigns
source .venv/bin/activate
python -m pytest -q
```

Phase 7.8 is a stacked change on the Phase 7.7.1 branch. Keep PRs #2 and #3 in mind when merging.

## 2. First authorized source campaign

```bash
export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"
python -m hunterqa campaign \
  --project "$HOME/ZeroScope-AI/targets" \
  --out-dir "$HOME/ZeroScope-AI/research-lab/campaign-first" \
  --authorized
python -m json.tool "$HOME/ZeroScope-AI/research-lab/campaign-first/manifest.json"
```

Each output path **must not exist before running**. Subsequent campaigns should use a new directory name.

## 3. Optional bounded local AI

```bash
python -m hunterqa campaign \
  --project "$HOME/ZeroScope-AI/targets" \
  --out-dir "$HOME/ZeroScope-AI/research-lab/campaign-ai" \
  --with-ai --ai-chunks 4 --authorized
```

This uses Qwen2.5-Coder 3B via local Ollama. The AI stage is optional because model inference can be slow on a low-RAM VM.

## 4. Optional existing sanitizer evidence (read-only)

```bash
python -m hunterqa campaign \
  --project "$HOME/ZeroScope-AI/targets" \
  --out-dir "$HOME/ZeroScope-AI/research-lab/campaign-sanitizer" \
  --sanitizer-log "$HOME/ZeroScope-AI/research-lab/uaf_sanitizer.log" \
  --authorized
```

This imports an existing diagnostic. It does NOT link sanitizer evidence to a crash unless both input and binary hashes can be correlated.

## 5. Optional crash replay in your isolated Kali VM

WARNING: this executes a preselected local binary with prior AFL++ inputs. The Python program's resource limits are NOT a sandbox. Only do this in a separately isolated VM with explicit authorization.

```bash
python -m hunterqa campaign \
  --project "$HOME/ZeroScope-AI/targets" \
  --out-dir "$HOME/ZeroScope-AI/research-lab/campaign-replay" \
  --lab "$HOME/ZeroScope-AI/research-lab" \
  --binary "$HOME/ZeroScope-AI/research-lab/fuzz_target_san" \
  --crashes "$HOME/ZeroScope-AI/research-lab/fuzz-output-v3/default/crashes" \
  --authorized
```

The resulting `manifest.json` contains separate states for scan, graph, AI, replay, sanitizer, triage, plus per-artifact SHA-256. Each stage is `skipped`, `completed`, `partial` or `failed`.

## Limitations

- This is single-process, sequential orchestration, not continuous scheduling or a full job queue.
- No automatic AFL++ fuzzing is initiated; only already-saved crashes are optionally replayed. No generated AI code is executed or auto-applied.
- JSON evidence is never proof that a vulnerability or zero-day is confirmed.
- Triage records from source and independent sanitizer logs can represent unrelated projects; no automatic claims of correlation.
- Campaign output folder must be new and within approved roots, outside scanned source.
- Results are available in campaign JSON artifacts; dashboard ingestion and audit UI are later enhancements.
