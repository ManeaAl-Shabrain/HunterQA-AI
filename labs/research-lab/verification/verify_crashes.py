
#!/usr/bin/env python3
"""Local crash verification for an explicitly approved lab binary."""

import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

LAB = Path.home() / "ZeroScope-AI" / "research-lab"
BINARY = LAB / "fuzz_target_san"
CRASH_DIR = LAB / "fuzz-output-v3" / "default" / "crashes"
OUTPUT = LAB / "verification" / "verified_crashes.json"

TIMEOUT = 5
MAX_INPUT = 1024 * 1024
MAX_CRASHES = 100

ASAN_CWE = {
    "heap-use-after-free": "CWE-416",
    "heap-buffer-overflow": "CWE-122",
    "stack-buffer-overflow": "CWE-121",
    "global-buffer-overflow": "CWE-119",
    "double-free": "CWE-415",
}

def classify(stderr):
    match = re.search(
        r"ERROR: AddressSanitizer:\s*([a-z-]+)",
        stderr
    )
    if match:
        category = match.group(1)
        return {
            "category": category,
            "cwe_candidate": ASAN_CWE.get(category),
            "evidence_source": "AddressSanitizer",
            "sanitizer_detected": True,
        }

    if "runtime error:" in stderr:
        return {
            "category": "undefined-behavior",
            "cwe_candidate": None,
            "evidence_source": "UndefinedBehaviorSanitizer",
            "sanitizer_detected": True,
        }

    return {
        "category": "unclassified",
        "cwe_candidate": None,
        "evidence_source": None,
        "sanitizer_detected": False,
    }


def verify(crash):
    data = crash.read_bytes()
    digest = hashlib.sha256(data).hexdigest()

    env = os.environ.copy()
    env["ASAN_OPTIONS"] = (
        "detect_leaks=0:abort_on_error=1:"
        "symbolize=1"
    )
    env["UBSAN_OPTIONS"] = (
        "print_stacktrace=1:halt_on_error=1"
    )

    attempts = []

    for _ in range(3):
        try:
            result = subprocess.run(
                [str(BINARY)],
                input=data,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=TIMEOUT,
                env=env,
                cwd=str(LAB),
                check=False,
            )

            diagnostic = result.stderr.decode(
                "utf-8", errors="replace"
            )[:16000]

            attempts.append({
                "return_code": result.returncode,
                "signal": (
                    -result.returncode
                    if result.returncode < 0 else None
                ),
                "timed_out": False,
                "diagnostic": diagnostic,
                "classification": classify(diagnostic),
            })

        except subprocess.TimeoutExpired:
            attempts.append({
                "return_code": None,
                "signal": None,
                "timed_out": True,
                "diagnostic": "",
                "classification": {
                    "category": "timeout",
                    "cwe_candidate": None,
                    "evidence_source": None,
                    "sanitizer_detected": False,
                },
            })

    signatures = [
        (
            a["return_code"],
            a["classification"]["category"],
        )
        for a in attempts
    ]

    reproducible = (
        len(set(signatures)) == 1
        and not attempts[0]["timed_out"]
        and attempts[0]["return_code"] != 0
    )

    sanitizer_confirmed = (
        reproducible
        and all(
            a["classification"]["sanitizer_detected"]
            for a in attempts
        )
    )

    first = attempts[0]["classification"]

    return {
        "filename": crash.name,
        "sha256": digest,
        "input_size": len(data),
        "attempts": attempts,
        "reproducible": reproducible,
        "sanitizer_confirmed": sanitizer_confirmed,
        "category": (
            first["category"] if reproducible
            else "inconsistent"
        ),
        "cwe_candidate": (
            first["cwe_candidate"]
            if sanitizer_confirmed else None
        ),
        "security_impact": "requires_human_review",
        "zero_day_confirmed": False,
        "verification_status": (
            "sanitizer_evidence_requires_review"
            if sanitizer_confirmed
            else "requires_source_review"
        ),
    }


def main():
    if not BINARY.is_file() or BINARY.is_symlink():
        raise SystemExit("Approved sanitized binary not found")

    if not CRASH_DIR.is_dir() or CRASH_DIR.is_symlink():
        raise SystemExit("Crash directory not found")

    crashes = sorted(
        p for p in CRASH_DIR.iterdir()
        if p.is_file()
        and not p.is_symlink()
        and p.name.startswith("id:")
        and p.stat().st_size <= MAX_INPUT
    )[:MAX_CRASHES]

    findings = [verify(crash) for crash in crashes]

    report = {
        "project": "ZeroScope AI",
        "engine": "Crash Verification + ASan/UBSan",
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "total_crashes": len(findings),
        "findings": findings,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(f"[+] Processed: {len(findings)} crashes")
    print(f"[+] Saved: {OUTPUT}")


if __name__ == "__main__":
    main()
