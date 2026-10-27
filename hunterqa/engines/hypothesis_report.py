"""Bounded import of local AI hypothesis JSON for read-only presentation."""
from __future__ import annotations
import json
from pathlib import Path


def read_hypotheses(path: Path) -> dict:
    empty={"model":"Local Ollama", "hypotheses": [], "status":"missing"}
    if path.is_symlink() or not path.is_file():
        return empty
    try:
        if path.stat().st_size > 300_000:
            raise ValueError()
        obj=json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(obj, dict) or not isinstance(obj.get("hypotheses"), list):
            raise ValueError()
        rows=[]
        for item in obj["hypotheses"][:30]:
            if not isinstance(item, dict):
                continue
            rows.append({k: str(item.get(k, ""))[:1200] for k in (
                "file", "potential_weakness", "source_basis", "safe_validation_idea", "remediation_idea", "uncertainty")})
            rows[-1]["status"]="Unverified AI hypothesis"
        return {"model":str(obj.get("model") or "Local Ollama")[:100], "hypotheses": rows, "status":"ready"}
    except (OSError, UnicodeError, ValueError, TypeError):
        return {**empty,"status":"invalid"}
