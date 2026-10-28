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


def _write_bounty_output(path: str, content: str) -> None:
    """Create-only private output under explicitly approved roots."""
    output = Path(path).expanduser()
    _approved_root(str(output.parent.resolve(strict=True)))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(output, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)
    print("Saved:", output)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="hunterqa", description="Local-only authorized vulnerability research")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("capabilities", help="Show research category coverage and limitations")
    doctor = sub.add_parser("doctor", help="Read-only local release diagnostics")
    doctor.add_argument("--project")
    doctor.add_argument("--check-ollama", action="store_true")
    doctor.add_argument("--json", action="store_true")
    ai = sub.add_parser("hypothesize", help="Local Ollama-assisted source hypotheses (never auto-confirmed)")
    ai.add_argument("--project", required=True)
    ai.add_argument("--out", required=True)
    ai.add_argument("--authorized", action="store_true")
    campaign = sub.add_parser("campaign", help="Run one bounded authorized local research campaign")
    campaign.add_argument("--project", required=True)
    campaign.add_argument("--out-dir", required=True)
    campaign.add_argument("--with-ai", action="store_true")
    campaign.add_argument("--no-graph", action="store_true")
    campaign.add_argument("--ai-chunks", type=int, default=4)
    campaign.add_argument("--sanitizer-log")
    campaign.add_argument("--lab")
    campaign.add_argument("--binary")
    campaign.add_argument("--crashes")
    campaign.add_argument("--authorized", action="store_true")
    cve = sub.add_parser("cve-check", help="Match offline OSV advisories to declared exact PyPI versions")
    cve.add_argument("--project", required=True)
    cve.add_argument("--snapshot", required=True)
    cve.add_argument("--out", required=True)
    cve.add_argument("--authorized", action="store_true")
    bounty_check = sub.add_parser("bounty-preflight", help="Offline scope preflight; makes no network requests")
    bounty_check.add_argument("--profile", required=True)
    bounty_check.add_argument("--targets", required=True)
    bounty_check.add_argument("--method", choices=("HEAD", "GET"), default="HEAD")
    bounty = sub.add_parser("bounty-assess", help="Bounded authorized HEAD/GET web observations")
    bounty.add_argument("--profile", required=True)
    bounty.add_argument("--targets", required=True)
    bounty.add_argument("--method", choices=("HEAD", "GET"), default="HEAD")
    bounty.add_argument("--out", required=True)
    bounty.add_argument("--authorized", action="store_true")
    har = sub.add_parser("bounty-import-har", help="Offline read-only HAR evidence analysis")
    har.add_argument("--profile", required=True)
    har.add_argument("--har", required=True)
    har.add_argument("--out", required=True)
    har.add_argument("--authorized", action="store_true")
    bounty_export = sub.add_parser("bounty-report", help="Draft a human-reviewed Markdown bug bounty report")
    bounty_export.add_argument("--file", required=True)
    bounty_export.add_argument("--out", required=True)
    engagement = sub.add_parser("bounty-campaign", help="Unify local SAST/AI, optional OSV/HAR and approved HTTP research")
    engagement.add_argument("--project", required=True)
    engagement.add_argument("--out-dir", required=True)
    engagement.add_argument("--profile", required=True)
    engagement.add_argument("--snapshot")
    engagement.add_argument("--har")
    engagement.add_argument("--with-ai", action="store_true")
    engagement.add_argument("--with-web", action="store_true")
    engagement.add_argument("--targets")
    engagement.add_argument("--method", choices=("HEAD", "GET"), default="HEAD")
    engagement.add_argument("--authorized", action="store_true")
    api12 = sub.add_parser("bounty-api-inventory", help="Offline OpenAPI 3.x authorization and object-access review")
    api12.add_argument("--profile", required=True)
    api12.add_argument("--spec", required=True)
    api12.add_argument("--out", required=True)
    api12.add_argument("--authorized", action="store_true")
    agent12 = sub.add_parser("bounty-agent-plan", help="Build a safe, non-executing specialist-agent plan")
    agent12.add_argument("--profile", required=True)
    agent12.add_argument("--spec")
    agent12.add_argument("--targets")
    agent12.add_argument("--out", required=True)
    agent12.add_argument("--authorized", action="store_true")
    correlation12 = sub.add_parser("bounty-correlate", help="Deduplicate policy-matched local evidence with manual review")
    correlation12.add_argument("--profile", required=True)
    correlation12.add_argument("--file", action="append", required=True, help="Repeat for 1..8 verified local reports")
    correlation12.add_argument("--out", required=True)
    correlation12.add_argument("--authorized", action="store_true")
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
    elif args.command == "doctor":
        from .doctor import run_diagnostics
        result = run_diagnostics(project=args.project, check_ollama=args.check_ollama)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            for check in result["checks"]:
                print(f"[{check['status'].upper()}] {check['name']}: {check['detail']}")
            print("Overall:", result["overall"])
    elif args.command == "hypothesize":
        if not args.authorized:
            raise PermissionError("Local AI research requires --authorized")
        from .engines.ai_research import analyze_local
        _write_json(args.out, analyze_local(_approved_root(args.project)))
    elif args.command == "campaign":
        from .campaign import run_campaign
        outcome = run_campaign(
            args.project, args.out_dir, authorized=args.authorized,
            include_graph=not args.no_graph,
            include_ai=args.with_ai, ai_max_chunks=args.ai_chunks,
            sanitizer_log=args.sanitizer_log,
            replay_lab=args.lab, replay_binary=args.binary,
            replay_crashes=args.crashes,
        )
        print("Campaign:", outcome["output_directory"])
        for name, stage in outcome["stages"].items():
            print(f"  {name}: {stage['status']}")
        print("Research records:", outcome["summary"]["research_records"])
    elif args.command == "cve-check":
        if not args.authorized:
            raise PermissionError("CVE research requires explicit --authorized")
        from .engines.cve_intel import run_cve_check
        _approved_root(args.project)
        report = run_cve_check(args.project, args.snapshot)
        output = Path(args.out).expanduser()
        _approved_root(str(output.parent.resolve(strict=True)))
        if output.is_symlink() or output.exists():
            raise ValueError("Use a new output path without symlinks")
        _write_json(str(output), report)
    elif args.command == "bounty-preflight":
        from .bounty import BountyPolicy, _approved_file, MAX_TARGET_LIST
        profile = BountyPolicy.load(args.profile)
        file = _approved_file(args.targets)
        if file.stat().st_size > MAX_TARGET_LIST:
            raise ValueError("Target list exceeds size limit")
        targets = [x.strip() for x in file.read_text(encoding="utf-8").splitlines()
                   if x.strip() and not x.lstrip().startswith("#")]
        if not targets or len(targets) > profile.max_requests:
            raise ValueError("Target list exceeds explicit request budget")
        for url in targets:
            profile.authorize_url(url, args.method)
        print("PASS: all", len(targets), "targets are inside the declared program scope")
        print("No network requests were made; preflight does not prove program permission.")
    elif args.command == "bounty-assess":
        from .bounty import assess
        if not args.authorized:
            raise PermissionError("Explicit --authorized flag required for network requests")
        output = Path(args.out).expanduser()
        _approved_root(str(output.parent.resolve(strict=True)))
        if output.exists() or output.is_symlink():
            raise ValueError("Use a new output file; do not overwrite previous evidence")
        report = assess(args.profile, args.targets, authorized=True, method=args.method)
        _write_bounty_output(str(output), json.dumps(report, indent=2) + "\n")
    elif args.command == "bounty-import-har":
        from .bounty import import_har
        if not args.authorized:
            raise PermissionError("Importing program evidence requires --authorized")
        result = import_har(args.profile, args.har, authorized=True)
        _write_bounty_output(args.out, json.dumps(result, indent=2) + "\n")
    elif args.command == "bounty-report":
        from .bounty import bounty_markdown, _read_json
        evidence = _read_json(args.file, 1_000_000)
        _write_bounty_output(args.out, bounty_markdown(evidence))
    elif args.command == "bounty-campaign":
        from .bounty_campaign import run_bounty_campaign
        result = run_bounty_campaign(
            args.project, args.out_dir, args.profile, authorized=args.authorized,
            with_ai=args.with_ai, with_web=args.with_web,
            targets_path=args.targets, method=args.method,
            snapshot_path=args.snapshot, har_path=args.har,
        )
        print("Engagement saved:", result["output_directory"])
        print("Source candidates:", result["summary"]["source_candidates"])
        print("Advisory records:", result["summary"]["advisory_records"])
        print("Web observations:", result["summary"]["http_observations"])
        print("Findings require human verification before submission.")
    elif args.command == "bounty-api-inventory":
        from .api_surface_v12 import inspect_openapi
        report = inspect_openapi(args.spec, args.profile, authorized=args.authorized)
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    elif args.command == "bounty-agent-plan":
        from .agent_workflow_v12 import plan
        report = plan(args.profile, api_spec=args.spec, targets_path=args.targets,
                      authorized=args.authorized)
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    elif args.command == "bounty-correlate":
        from .agent_workflow_v12 import correlate
        report = correlate(args.profile, args.file, authorized=args.authorized)
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
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
