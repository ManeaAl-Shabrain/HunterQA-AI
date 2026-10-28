
import json
from pathlib import Path
from datetime import datetime, timezone

BASE = Path(__file__).resolve().parent

crash_file = BASE / "verified_crashes.json"
sanitizer_file = BASE / "sanitizer_evidence.json"
output_file = BASE / "integrated_report.json"

crash_report = json.loads(crash_file.read_text())
sanitizer = json.loads(sanitizer_file.read_text())

# Preserve the existing crash verification data.
report = {
    **crash_report,
    "integration_version": "6.3",
    "integrated_at": datetime.now(timezone.utc).isoformat(),
    "sanitizer_evidence": [sanitizer],
    "summary": {
        "total_crashes": crash_report.get("total_crashes", 0),
        "sanitizer_diagnostics": int(
            sanitizer.get("evidence_confirmed", False)
        ),
        "zero_days_confirmed": 0,
        "review_required": True,
    },
}

output_file.write_text(
    json.dumps(report, indent=2),
    encoding="utf-8"
)

print("[+] Phase 6.3 integration complete")
print(f"[+] Report: {output_file}")
print(f"[+] Crashes: {report['summary']['total_crashes']}")
print(
    "[+] Sanitizer diagnostics:",
    report["summary"]["sanitizer_diagnostics"]
)
