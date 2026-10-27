"""Read-only bounded parser for AFL++ fuzzer_stats; never launches AFL++."""
from __future__ import annotations
from pathlib import Path

FIELDS={"execs_done", "execs_per_sec", "run_time", "saved_crashes", "corpus_count", "bitmap_cvg", "stability", "cycles_done", "edges_found", "last_find"}


def read_fuzzer_stats(path: str | Path) -> dict:
    p=Path(path).expanduser()
    try:
        if p.is_symlink() or not p.is_file() or p.stat().st_size > 128_000:
            return {"status":"unavailable", "metrics":{}}
        lines=p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {"status":"unavailable", "metrics":{}}
    data={}
    for line in lines[:1000]:
        if ':' not in line:
            continue
        k,v=line.split(':',1)
        k=k.strip()
        if k in FIELDS:
            data[k]=v.strip()[:60]
    return {"status":"ready" if data else "invalid", "metrics":data}
