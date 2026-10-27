# HunterQA AI — Phase 7.7.1 Remediation Safety Gate

Local Qwen can generate incorrect "fixes", including `eval(expression, {"__builtins__": None})`, which is **not** a secure sandbox.

This phase adds `hunterqa/engines/patch_guard.py`. Proposed one-line Python patches are parsed as data using `ast.parse` (never executed). Known-dangerous calls such as `eval`, `exec`, `pickle.loads`, and `subprocess.run(..., shell=True)` are blocked. Rejected proposals retain the candidate for human inspection but have **no suggested diff**. Other candidate patches remain `manual_review`; absence of a dangerous AST call never confirms that a patch works or fixes a security issue. Unsupported languages require manual review.

## Kali verification

```bash
cd ~/Desktop/HunterQA-AI
source .venv/bin/activate
git fetch origin
git switch --track origin/feature/phase-7-7-1-remediation-safety-gate
python -m pytest -q

python - <<'PY'
from hunterqa.engines.patch_guard import inspect_patch_line
print(inspect_patch_line("demo.py", "return eval(expression, {'__builtins__': None})"))
PY
```

Use the existing `propose-fix` CLI to re-run the same authorized local source experiment; the JSON output now includes `safety_gate`, and `rejected_unsafe_proposal` for this unsafe example.

Important limitations: AST matching is not whole-program taint analysis, can miss aliases, reflection and cross-language issues, and cannot validate imports, semantics, correctness or exploitability. Never automatically apply or execute suggested changes. For calculator expression parsing, prefer a small allowlisted AST interpreter with operation, depth, and integer-size limits rather than unrestricted `eval`.
