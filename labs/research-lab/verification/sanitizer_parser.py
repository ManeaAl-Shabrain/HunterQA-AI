
import json
import re
from pathlib import Path

CWE_MAP = {
    "heap-use-after-free": "CWE-416",
    "heap-buffer-overflow": "CWE-122",
    "stack-buffer-overflow": "CWE-121",
    "double-free": "CWE-415",
    "stack-use-after-return": "CWE-416",
    "stack-use-after-scope": "CWE-416",
}

def parse_sanitizer_log(log_text):
    error = re.search(
        r"ERROR: AddressSanitizer:\s*([a-z-]+)",
        log_text
    )

    summary = re.search(
        r"SUMMARY: AddressSanitizer:\s*(.+)",
        log_text
    )

    locations = re.findall(
        r"([A-Za-z0-9_.-]+\.c):(\d+):(\d+)",
        log_text
    )

    category = error.group(1) if error else None

    return {
        "sanitizer": "AddressSanitizer" if error else None,
        "category": category,
        "cwe_candidate": CWE_MAP.get(category),
        "summary": summary.group(1) if summary else None,
        "source_locations": [
            {
                "file": filename,
                "line": int(line),
                "column": int(column),
            }
            for filename, line, column in locations
        ],
        "evidence_confirmed": bool(error),
        "security_impact": "requires_human_review",
        "zero_day_confirmed": False,
    }


if __name__ == "__main__":
    log = Path("uaf_sanitizer.log").read_text(
        encoding="utf-8", errors="replace"
    )

    result = parse_sanitizer_log(log)

    output = Path("verification/sanitizer_evidence.json")
    output.write_text(
        json.dumps(result, indent=2),
        encoding="utf-8"
    )

    print(json.dumps(result, indent=2))
    print(f"\n[+] Saved: {output}")
