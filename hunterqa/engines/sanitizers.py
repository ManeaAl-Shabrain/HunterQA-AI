"""Extract sanitizer facts from bounded local diagnostic logs."""
from __future__ import annotations
import re
from pathlib import Path

ASAN_CWE = {
    "heap-use-after-free": "CWE-416", "heap-buffer-overflow": "CWE-122",
    "stack-buffer-overflow": "CWE-121", "double-free": "CWE-415",
    "attempting-double-free": "CWE-415", "stack-use-after-return": "CWE-416",
    "stack-use-after-scope": "CWE-416", "global-buffer-overflow": "CWE-119",
}


def parse_sanitizer_log(log: str) -> dict:
    text = log[:200_000]
    asan = re.search(r"ERROR: AddressSanitizer:\s*([a-z-]+)", text)
    ubsan = re.search(r"(?:^|\n)([^\n]{0,300}:\d+:\d+:\s*runtime error: [^\n]{0,300})", text)
    category = asan.group(1) if asan else ("undefined-behavior" if ubsan else None)
    summary = re.search(r"SUMMARY: AddressSanitizer:\s*([^\n]+)", text)
    locs = re.findall(r"(?:^|\s|\()((?:[\w.\-/]+)\.(?:c|cc|cpp|h)):(\d+):(\d+)", text)
    locations = []
    for name, line, col in locs[:40]:
        row = {"file": Path(name).name, "line": int(line), "column": int(col)}
        if row not in locations:
            locations.append(row)
    return {
        "sanitizer": "AddressSanitizer" if asan else "UndefinedBehaviorSanitizer" if ubsan else None,
        "category": category,
        "cwe_candidate": ASAN_CWE.get(category),
        "summary": (summary.group(1) if summary else ubsan.group(1) if ubsan else "")[:2000],
        "source_locations": locations,
        "evidence_confirmed": bool(asan or ubsan),
        "security_impact": "requires_human_review",
        "zero_day_confirmed": False,
    }
