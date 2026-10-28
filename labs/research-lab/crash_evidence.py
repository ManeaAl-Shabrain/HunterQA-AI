import json
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime, timezone

root = Path("fuzz-output-v3/default/crashes")
crashes = sorted(root.glob("id:*"))

results = []

for crash in crashes:
    data = crash.read_bytes()

    result = subprocess.run(
        ["./fuzz_target_laf"],
        input=data,
        capture_output=True,
        timeout=5
    )

    results.append({
        "filename": crash.name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "input_size": len(data),
        "return_code": result.returncode,
        "signal": (
            -result.returncode
            if result.returncode < 0 else None
        ),
        "stderr": result.stderr.decode(
            errors="replace"
        )[:4000],
        "classification": "Unverified crash"
    })

report = {
    "project": "ZeroScope AI",
    "engine": "AFL++",
    "generated_at": datetime.now(
        timezone.utc
    ).isoformat(),
    "total_crashes": len(results),
    "crashes": results
}

Path("afl_crash_report.json").write_text(
    json.dumps(report, indent=2)
)

print(json.dumps(report, indent=2))
