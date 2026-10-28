
import json
from pathlib import Path

path = Path("ai_crash_report.json")
report = json.loads(path.read_text())

for finding in report["findings"]:
    crash = finding["crash"]
    ai = finding["ai_analysis"]

    signal = crash.get("signal")
    stderr = crash.get("stderr", "")

    sanitizer_evidence = any(
        marker in stderr
        for marker in (
            "ERROR: AddressSanitizer:",
            "runtime error:",
            "ERROR: LeakSanitizer:"
        )
    )

    if signal == 6 and not sanitizer_evidence:
        ai["root_cause"] = (
            "SIGABRT observed; source review required"
        )
        ai["cwe"] = None
        ai["security_impact"] = "Not established"
        ai["confidence"] = "Unverified"

        ai["evidence_validation"] = {
            "status": "insufficient_evidence",
            "reason": (
                "SIGABRT without sanitizer evidence "
                "does not establish memory corruption."
            )
        }

        finding["verification_status"] = (
            "requires_source_review"
        )

validated = Path("validated_ai_report.json")
validated.write_text(
    json.dumps(report, indent=2),
    encoding="utf-8"
)

print("[+] Validated report saved:", validated)
