"""HunterQA AI local research command line. No remote scan endpoints."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
from .engines.config_audit import audit_project
from .engines.dependencies import inventory, match_local_advisories
from .engines.openapi import audit_openapi
from .engines.hypotheses import checklist
from .engines.sanitizers import parse_sanitizer_log
from .engines.sarif import import_sarif
from .engines.fuzzing import verify_crashes
from .research import load_research_report


def _write_json(out: str | None, payload) -> None:
    content = json.dumps(payload, indent=2, ensure_ascii=False)
    if out:
        p = Path(out).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content + "\n", encoding="utf-8")
        print("Saved:", p)
    else:
        print(content)


def _approved_root(path: str) -> Path:
    target = Path(path).expanduser().resolve(strict=True)
    roots = os.environ.get("HUNTERQA_APPROVED_ROOTS", os.environ.get("ZEROSCOPE_APPROVED_ROOTS", ""))
    if not roots:
        raise ValueError("Set HUNTERQA_APPROVED_ROOTS to explicitly authorized local directories")
    if not target.is_dir() or not any(target.is_relative_to(Path(r).expanduser().resolve(strict=True)) for r in roots.split(os.pathsep) if r):
        raise ValueError("Target is outside approved local roots")
    return target


def main(argv=None):
    parser = argparse.ArgumentParser(prog="hunterqa", description="Local-only authorized vulnerability research")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("capabilities", help="Show research category coverage and limitations")
    ai = sub.add_parser("hypothesize", help="Local Ollama-assisted source hypotheses (never auto-confirmed)")
    ai.add_argument("--project", required=True)
    ai.add_argument("--out", required=True)
    ai.add_argument("--authorized", action="store_true")
    fix = sub.add_parser("propose-fix", help="Generate a read-only local AI patch suggestion for one triage finding")
    fix.add_argument("--project", required=True)
    fix.add_argument("--triage", required=True)
    fix.add_argument("--finding", required=True)
    fix.add_argument("--out", required=True)
    fix.add_argument("--authorized", action="store_true")
    graph = sub.add_parser("trust-graph", help="Build a local Python call graph and trust-boundary review paths")
    graph.add_argument("--project", required=True)
    graph.add_argument("--out", required=True)
    graph.add_argument("--authorized", action="store_true")
    scan = sub.add_parser("scan", help="Run unified offline Semgrep + config + API + dependency scan")
    scan.add_argument("--project", required=True)
    scan.add_argument("--out", required=True)
    scan.add_argument("--authorized", action="store_true")
    audit = sub.add_parser("audit", help="Offline source/config/dependency/OpenAPI inspection")
    audit.add_argument("--project", required=True)
    audit.add_argument("--out")
    audit.add_argument("--advisories", help="Optional local JSON array of exact-version advisories")
    s = sub.add_parser("import-sarif", help="Normalize local CodeQL / SARIF output")
    s.add_argument("--file", required=True); s.add_argument("--out")
    s = sub.add_parser("parse-sanitizer", help="Parse a local ASan/UBSan log")
    s.add_argument("--file", required=True); s.add_argument("--out")
    s = sub.add_parser("research-report", help="Normalize validated local research JSON")
    s.add_argument("--file", required=True); s.add_argument("--out")
    s = sub.add_parser("verify-crashes", help="Replay AFL++ inputs against a local approved executable")
    s.add_argument("--lab", required=True); s.add_argument("--binary", required=True)
    s.add_argument("--crashes", required=True); s.add_argument("--out", required=True)
    s.add_argument("--authorized", action="store_true", help="I have authorization and isolation in place")
    args = parser.parse_args(argv)
    if args.command == "capabilities":
        from .engines.hypotheses import checklist
        for x in checklist():
            print(f"{x['category']}: {x['status']}; {', '.join(x['questions'])}")
    elif args.command == "hypothesize":
        if not args.authorized:
            raise PermissionError("Local AI research requires --authorized")
        from .engines.ai_research import analyze_local
        _write_json(args.out, analyze_local(_approved_root(args.project)))
    elif args.command == "propose-fix":
        if not args.authorized:
            raise PermissionError("Remediation proposals require --authorized")
        from .engines.remediation import propose_remediation
        root = _approved_root(args.project)
        report = propose_remediation(root, Path(args.triage), args.finding)
        destination = Path(args.out).expanduser()
        approved_output = destination.parent.resolve(strict=True)
        _approved_root(str(approved_output))
        if destination.is_symlink() or destination.resolve() == Path(args.triage).expanduser().resolve():
            raise ValueError("Output cannot overwrite a report or use a symlink")
        _write_json(args.out, report)
    elif args.command == "trust-graph":
        if not args.authorized:
            raise PermissionError("Trust graph requires explicit --authorized acknowledgement")
        from .engines.trust_graph import build_trust_graph
        root = _approved_root(args.project)
        _write_json(args.out, build_trust_graph(root))
    elif args.command == "scan":
        if not args.authorized:
            raise PermissionError("Local scan requires explicit --authorized acknowledgement")
        from .orchestrator import scan_local_source
        root = _approved_root(args.project)
        rules = Path(__file__).resolve().parent / "rules" / "semgrep.yml"
        payload = scan_local_source(root, rules)
        payload.update({"project": str(root), "scope": "authorized local files", "zero_days_confirmed": 0})
        _write_json(args.out, payload)
    elif args.command == "audit":
        root = _approved_root(args.project)
        deps = inventory(root)
        findings = audit_project(root) + audit_openapi(root)
        if args.advisories:
            p = Path(args.advisories).expanduser().resolve(strict=True)
            if not p.is_file() or p.stat().st_size > 2_000_000:
                raise ValueError("Invalid advisory snapshot")
            adv = json.loads(p.read_text(encoding="utf-8"))
            if not isinstance(adv, list):
                raise ValueError("Advisories must be a JSON array")
            findings += match_local_advisories(deps, adv)
        _write_json(args.out, {"project": str(root), "scope": "offline local inspection",
                               "findings": findings, "dependencies": deps,
                               "manual_research": checklist(), "zero_days_confirmed": 0})
    elif args.command == "import-sarif":
        _write_json(args.out, {"engine": "sarif-import", "findings": import_sarif(Path(args.file)), "zero_days_confirmed": 0})
    elif args.command == "parse-sanitizer":
        path = Path(args.file)
        if path.is_symlink() or path.stat().st_size > 500_000:
            raise ValueError("Invalid diagnostic file")
        _write_json(args.out, parse_sanitizer_log(path.read_text(encoding="utf-8", errors="replace")))
    elif args.command == "research-report":
        _write_json(args.out, load_research_report(args.file))
    elif args.command == "verify-crashes":
        root = _approved_root(args.lab)
        result = verify_crashes(approved_lab=root, binary_path=Path(args.binary), crash_dir=Path(args.crashes),
                                output=Path(args.out), authorized=args.authorized)
        print("Replayed", result["total_crashes"], "local crash inputs. Review evidence before assigning vulnerability status.")

if __name__ == "__main__":
    main()
