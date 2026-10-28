
import json
import urllib.request
from pathlib import Path
from datetime import datetime, timezone

MODEL = "qwen2.5-coder:3b"
OLLAMA = "http://127.0.0.1:11434/api/generate"

report = json.loads(
    Path("afl_crash_report.json").read_text()
)
source = Path("fuzz_target.c").read_text()

SYSTEM = """
You are a defensive vulnerability research analyst.
Analyze only the supplied local laboratory evidence.

Rules:
- Do not invent vulnerabilities or evidence.
- Distinguish intentional aborts from memory corruption.
- Do not assign a CWE without supporting evidence.
- Do not claim a zero-day was discovered.
- Recommend safe verification and remediation.
- Return a valid JSON object only.

Required JSON fields:
root_cause, crash_type, cwe, security_impact,
evidence, verification, recommended_fix,
confidence, zero_day_confirmed
"""

def analyze(crash):
    evidence = {
        "filename": crash["filename"],
        "input_size": crash["input_size"],
        "return_code": crash["return_code"],
        "signal": crash["signal"],
        "stderr": crash["stderr"][:3000],
    }

    prompt = (
        SYSTEM
        + "\n\nC source:\n"
        + source[:12000]
        + "\n\nCrash evidence:\n"
        + json.dumps(evidence)
    )

    payload = json.dumps({
        "model": MODEL,
        "prompt": prompt,
        "format": "json",
        "stream": False,
        "options": {
            "temperature": 0,
            "num_predict": 700
        }
    }).encode("utf-8")

    request = urllib.request.Request(
        OLLAMA,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urllib.request.urlopen(
        request, timeout=240
    ) as response:
        result = json.load(response)

    analysis = json.loads(result["response"])

    if not isinstance(analysis, dict):
        raise ValueError("AI returned invalid structure")

    return analysis

results = []

for crash in report["crashes"]:
    print("[+] Analyzing:", crash["filename"])

    try:
        ai = analyze(crash)
        status = "completed"
    except Exception as exc:
        ai = {"error": str(exc)}
        status = "failed"

    results.append({
        "crash": crash,
        "ai_analysis": ai,
        "analysis_status": status,
        "verification_status": "requires_human_review"
    })

output = {
    "project": "ZeroScope AI",
    "engine": "AFL++ + Ollama",
    "model": MODEL,
    "generated_at": datetime.now(
        timezone.utc
    ).isoformat(),
    "findings": results
}

destination = Path("ai_crash_report.json")
destination.write_text(
    json.dumps(output, indent=2),
    encoding="utf-8"
)

print("[+] Saved:", destination)
