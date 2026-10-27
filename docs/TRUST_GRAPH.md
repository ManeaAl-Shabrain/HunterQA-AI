# HunterQA AI: Local Python Trust Graph

Run after reviewing your approved source directory:

```bash
export HUNTERQA_APPROVED_ROOTS="$HOME/Desktop/HunterQA-AI/hunterqa"
python -m hunterqa trust-graph --project "$HOME/Desktop/HunterQA-AI/hunterqa" --out "$HOME/ZeroScope-AI/research-lab/hunterqa_trust_graph.json" --authorized
```

The graph uses Python's AST parser **without importing, executing, or contacting source projects**. It records internal direct call relationships, Flask/FastAPI-style route decorator indicators, explicit `flask.request` input references, and selected sensitive operations (`eval`, `exec`, OS shell calls, unsafe deserialization). All detections are **review candidates**, not proofs of user-controlled data flow, exploitability, or CVEs. The graph does not propagate arguments or variables across calls; `request_reference_observed` only means a request expression appeared somewhere in a call path.

Limits: Python source only; max 500 small files and 500 paths; ignores symlinks, generated directories, dynamic imports, reflection, decorators that hide call relationships, polymorphism, and any code behind indirect calls. A missing path does **not** imply the code is secure. The tool never labels a zero-day. Use within an authorized, isolated research workflow.
