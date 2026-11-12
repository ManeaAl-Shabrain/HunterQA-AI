"""Render the reviewed requirement matrix without changing baseline classifications."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def render(data):
    lines = ["# Platform requirement gap analysis and traceability", "",
        "Baseline: `" + data["baseline_commit"] + "`; inspected before implementation on 12 November 2026. PR80 was merged; no open PRs at inspection.", "",
        "Every specification bullet has an ID, including repeated requirements. Baseline classifications are preserved separately from subsequent delivery. References identify code and relevant tests, not proof of all broad clauses. Mocks, owned TLS/protocol fixtures, real local systems and actual providers remain distinct.", "",
        "Machine-readable source: [PLATFORM_REQUIREMENTS.json](PLATFORM_REQUIREMENTS.json). See [mode contracts](ASSESSMENT_MODES.md) and [directory collection](AD_DIRECTORY_COLLECTION.md).", "",
        "| Requirement | Baseline classification | Current classification | Existing implementation | Existing tests | Evidence | Remaining baseline limitation | Incremental delivery |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    seen = set()
    for row in data["requirements"]:
        if row["id"] in seen:
            raise ValueError("Duplicate requirement")
        seen.add(row["id"])
        def links(values):
            for value in values:
                if not (ROOT / value).is_file():
                    raise ValueError("Traceability reference unavailable: " + value)
            return "; ".join("[" + value + "](../" + value + ")" for value in values)
        delivery = row["delivery_status"]
        if row.get("increment_files"):
            delivery += "; " + links(row["increment_files"]) + "; tests: " + links(row["increment_tests"])
        evidence_ids = list(dict.fromkeys(row["verification_evidence"] + row.get("increment_evidence", [])))
        if any(value not in data["evidence"] for value in evidence_ids):
            raise ValueError("Undefined verification evidence")
        cells = [row["id"] + " " + row["requirement"], row["baseline_status"], row.get("current_status", row["baseline_status"]), links(row["implementation_files"]),
            links(row["test_files"]), ", ".join(evidence_ids), row["remaining_limitations"], delivery]
        lines.append("| " + " | ".join(cell.replace("|", "\\|").replace("\n", " ") for cell in cells) + " |")
    lines += ["", "## Evidence and execution plan", "",
        "E80: [source and browser QA](https://github.com/ManeaAl-Shabrain/HunterQA-AI/actions/runs/43251307247), [actual Linux lifecycle](https://github.com/ManeaAl-Shabrain/HunterQA-AI/actions/runs/43251308535). These are the previous baseline, not proof of new changes or real providers.", "",
        "1. Preserve existing engines, data, CLI and security gates.",
        "2. Add shared source/verification contracts and actual analyzer-backed DEMO controls.",
        "3. Integrate project history, protected UI and provenance-preserving exports.",
        "4. Add bounded real read-only collection; separately validate the Samba lab and external providers.",
        "5. Extend remaining domain collection/analysis incrementally, with actual tests and explicit limits.",
        "6. Run full regression and Linux lifecycle verification, then publish current evidence and remaining gaps.", ""]
    for key, evidence in data["evidence"].items():
        if evidence.get("workflow"):
            lines += [key + ": [verification run](" + evidence["workflow"] + "), source `" + evidence["source_commit"] + "`. " + evidence.get("scope", ""), ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = json.loads((ROOT / "docs/PLATFORM_REQUIREMENTS.json").read_text(encoding="utf-8"))
    text = render(data)
    path = ROOT / "docs/PLATFORM_GAP_ANALYSIS.md"
    if args.check:
        if path.read_text(encoding="utf-8") != text:
            raise ValueError("Regenerate the platform traceability matrix")
    else:
        path.write_text(text, encoding="utf-8")
    print("Verified", len(data["requirements"]), "requirement references")


if __name__ == "__main__":
    main()
