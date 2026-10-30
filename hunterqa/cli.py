"""HunterQA AI local research command line. No remote scan endpoints."""
from __future__ import annotations
import argparse
from importlib.metadata import PackageNotFoundError, version as package_version
import json
import os
from pathlib import Path
from .engines.config_audit import audit_project
from .engines.dependencies import inventory, match_local_advisories
from .engines.openapi import audit_openapi
from .engines.sanitizers import parse_sanitizer_log
from .engines.sarif import import_sarif
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
    try:
        installed_version = package_version("hunterqa-ai")
    except PackageNotFoundError:
        installed_version = "development (not installed)"
    parser.add_argument("--version", action="version", version="HunterQA AI " + installed_version)
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
    ai12 = sub.add_parser("bounty-ai-review", help="Local Ollama agent-role recommendations without tool execution")
    ai12.add_argument("--plan", required=True)
    ai12.add_argument("--model", choices=("qwen2.5-coder:3b", "qwen2.5-coder:7b"), default="qwen2.5-coder:3b")
    ai12.add_argument("--out", required=True)
    ai12.add_argument("--authorized", action="store_true")
    browser_lab = sub.add_parser("bounty-browser-lab", help="Owned 127.0.0.1 Playwright lab review with optional scoped login")
    browser_lab.add_argument("--profile", required=True)
    browser_lab.add_argument("--url", required=True, help="Owned 127.0.0.1 lab URL, no queries")
    browser_lab.add_argument("--login", action="store_true")
    browser_lab.add_argument("--login-post-path", help="One approved local login endpoint, e.g. /login")
    browser_lab.add_argument("--username-selector", default="#username")
    browser_lab.add_argument("--password-selector", default="#password")
    browser_lab.add_argument("--submit-selector", default="button[type=submit]")
    browser_lab.add_argument("--out", required=True)
    browser_lab.add_argument("--authorized", action="store_true")
    replay12 = sub.add_parser("bounty-replay-head", help="Safe HEAD-only replay of approved sanitized HAR evidence")
    replay12.add_argument("--profile", required=True)
    replay12.add_argument("--har-report", required=True)
    replay12.add_argument("--out", required=True)
    replay12.add_argument("--authorized", action="store_true")
    review_init = sub.add_parser("bounty-review-init", help="Create an offline, scope-matched review dossier from correlated findings")
    review_init.add_argument("--profile", required=True)
    review_init.add_argument("--correlation", required=True)
    review_init.add_argument("--out", required=True)
    review_init.add_argument("--authorized", action="store_true")
    review_decide = sub.add_parser("bounty-review-decide", help="Record one human decision to a NEW private dossier version")
    review_decide.add_argument("--profile", required=True)
    review_decide.add_argument("--dossier", required=True)
    review_decide.add_argument("--case", required=True)
    review_decide.add_argument("--decision", required=True, choices=(
        "needs_more_evidence", "not_reproducible", "false_positive", "out_of_scope",
        "analyst_validated"))
    review_decide.add_argument("--reviewer", required=True, help="3..40 character local analyst alias")
    review_decide.add_argument("--impact", default="", help="Human-authored one-line impact summary (validated only)")
    review_decide.add_argument("--reproduction", default="", help="Human-authored safe reproduction summary (validated only)")
    review_decide.add_argument("--evidence", help="Path to already saved local reproduction artifact (validated only)")
    review_decide.add_argument("--out", required=True, help="New file; prior dossier never overwritten")
    review_decide.add_argument("--authorized", action="store_true")
    review_export = sub.add_parser("bounty-review-export", help="Create a private disclosure draft for human-validated cases only")
    review_export.add_argument("--profile", required=True)
    review_export.add_argument("--dossier", required=True)
    review_export.add_argument("--out", required=True)
    review_export.add_argument("--authorized", action="store_true")
    repeat = sub.add_parser("bounty-repeatability", help="Compare two same-scope HEAD replay reports offline")
    repeat.add_argument("--profile", required=True)
    repeat.add_argument("--first", required=True)
    repeat.add_argument("--second", required=True)
    repeat.add_argument("--out", required=True)
    repeat.add_argument("--authorized", action="store_true")
    manual_proof = sub.add_parser("bounty-reproduction-note", help="Create a private analyst-attested local reproduction note")
    manual_proof.add_argument("--profile", required=True)
    manual_proof.add_argument("--case", required=True)
    manual_proof.add_argument("--reviewer", required=True)
    manual_proof.add_argument("--context", choices=("owned_local_lab", "approved_test_accounts"), required=True)
    manual_proof.add_argument("--expected", required=True)
    manual_proof.add_argument("--observed", required=True)
    manual_proof.add_argument("--out", required=True)
    manual_proof.add_argument("--attest", action="store_true", help="I personally reproduced the behavior on authorized assets")
    manual_proof.add_argument("--authorized", action="store_true")
    benchmark = sub.add_parser("bounty-benchmark", help="Score offline synthetic OpenAPI review cues against independent positive/negative labels")
    benchmark.add_argument("--profile", required=True)
    benchmark.add_argument("--pack", required=True)
    benchmark.add_argument("--out", required=True)
    abandon = sub.add_parser("workflow-abandon", help="Reconcile a crashed coordinator without replaying work")
    abandon.add_argument("--run", required=True)
    abandon.add_argument("--authorized", action="store_true")
    benchmark.add_argument("--strict", action="store_true", help="Exit nonzero if a labeled review cue is missed or a false-positive suggestion appears")
    benchmark.add_argument("--authorized", action="store_true")
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
    plan_cmd = sub.add_parser("engagement-plan", help="Create an offline assessment plan for review")
    plan_cmd.add_argument("--profile", required=True)
    plan_cmd.add_argument("--url", action="append", required=True)
    plan_cmd.add_argument("--mode", choices=("observe", "waf-canary", "auth-check", "browser"), default="observe")
    plan_cmd.add_argument("--method", choices=("GET", "HEAD", "POST"), default="GET")
    plan_cmd.add_argument("--ttl-minutes", type=int, default=60)
    plan_cmd.add_argument("--dedicated-test-account", action="store_true")
    plan_cmd.add_argument("--browser-isolated", action="store_true")
    plan_cmd.add_argument("--login-url")
    plan_cmd.add_argument("--expected-status", type=int)
    plan_cmd.add_argument("--out", required=True)
    preflight = sub.add_parser("engagement-preflight", help="Offline review of an expiring exact assessment plan")
    preflight.add_argument("--profile", required=True)
    preflight.add_argument("--plan", required=True)
    run = sub.add_parser("engagement-run", help="Execute fingerprint-approved bounded assessment steps")
    run.add_argument("--profile", required=True)
    run.add_argument("--plan", required=True)
    run.add_argument("--approve-plan", required=True)
    run.add_argument("--stop-file", required=True)
    run.add_argument("--out", required=True)
    run.add_argument("--authorized", action="store_true")
    package = sub.add_parser("engagement-package", help="Offline reviewed disclosure/CVE request handoff; does not send")
    package.add_argument("--profile", required=True)
    package.add_argument("--dossier", required=True)
    package.add_argument("--kind", choices=("disclosure", "cve-request"), required=True)
    package.add_argument("--assigned-cve")
    package.add_argument("--reviewed", action="store_true")
    package.add_argument("--authorized", action="store_true")
    package.add_argument("--out", required=True)
    comparison = sub.add_parser("engagement-compare", help="Offline comparison of two saved same-plan assessment reports")
    comparison.add_argument("--first", required=True)
    comparison.add_argument("--second", required=True)
    comparison.add_argument("--out", required=True)
    sub.add_parser("research-playbooks", help="List original non-executing research review checklists")
    workspace = sub.add_parser("research-init", help="Initialize a new private policy-bound research journal")
    workspace.add_argument("--profile", required=True)
    workspace.add_argument("--out-dir", required=True)
    workspace.add_argument("--playbook", action="append", required=True)
    workspace.add_argument("--authorized", action="store_true")
    note = sub.add_parser("research-note", help="Append an operator observation, hypothesis, negative result or next step")
    note.add_argument("--profile", required=True)
    note.add_argument("--workspace", required=True)
    note.add_argument("--kind", choices=("observation", "hypothesis", "negative-result", "next-step"), required=True)
    note.add_argument("--summary", required=True)
    note.add_argument("--evidence")
    note.add_argument("--authorized", action="store_true")
    resume = sub.add_parser("research-resume", help="Read and verify private research context; executes no tests")
    resume.add_argument("--workspace", required=True)
    external = sub.add_parser("external-import", help="Offline scoped import of existing Nuclei JSONL or ZAP traditional JSON")
    external.add_argument("--profile", required=True)
    external.add_argument("--file", required=True)
    external.add_argument("--tool", choices=("nuclei", "zap"), required=True)
    external.add_argument("--out", required=True)
    external.add_argument("--authorized", action="store_true")
    sarif_out = sub.add_parser("report-sarif", help="Export normalized candidates as SARIF 2.1.0 without source snippets or uploading")
    sarif_out.add_argument("--file", required=True)
    sarif_out.add_argument("--out", required=True)
    sub.add_parser("workflow-tools", help="List planning adapter declarations; launches no tools")
    workflow = sub.add_parser("workflow-preflight", help="Offline testing-protocol and dependency review; no execution")
    workflow.add_argument("--profile", required=True)
    workflow.add_argument("--protocol", required=True)
    workflow.add_argument("--approve-step", action="append", default=[])
    workflow.add_argument("--approve-protocol")
    workflow.add_argument("--authorized", action="store_true")
    workflow.add_argument("--out", required=True)
    setup = sub.add_parser("workflow-setup", help="Create a private starter protocol and bindings; executes nothing")
    setup.add_argument("--profile", required=True)
    setup.add_argument("--project", required=True)
    setup.add_argument("--target", action="append", required=True)
    setup.add_argument("--out-dir", required=True)
    setup.add_argument("--observe", action="store_true")
    setup.add_argument("--authorized", action="store_true")
    for name in ("workflow-run-plan", "workflow-run"):
        command = sub.add_parser(name, help="Review or execute a fixed-adapter assessment workflow")
        command.add_argument("--profile", required=True)
        command.add_argument("--protocol", required=True)
        command.add_argument("--bindings", required=True)
        if name == "workflow-run-plan":
            command.add_argument("--out", required=True)
        else:
            command.add_argument("--out-dir", required=True)
            command.add_argument("--approve-execution", required=True)
            command.add_argument("--approve-protocol")
            command.add_argument("--approve-step", action="append", default=[])
            command.add_argument("--authorized", action="store_true")
            command.add_argument("--operator", required=True)
    for name in ("workflow-status", "workflow-stop"):
        command = sub.add_parser(name, help="Inspect a durable run or request emergency stop")
        command.add_argument("--run", required=True)
    export = sub.add_parser("workflow-export", help="Create a private JSON, printable HTML or SARIF report")
    export.add_argument("--run", required=True)
    export.add_argument("--out", required=True)
    export.add_argument("--format", choices=("json", "html", "sarif"), required=True)
    review = sub.add_parser("workflow-review", help="Record an evidence-linked local analyst decision")
    review.add_argument("--run", required=True)
    review.add_argument("--finding", required=True)
    review.add_argument("--decision", choices=("confirmed", "false-positive", "needs-review"), required=True)
    review.add_argument("--reviewer", required=True)
    review.add_argument("--note", required=True)
    review.add_argument("--evidence", required=True)
    review.add_argument("--authorized", action="store_true")
    retest = sub.add_parser("workflow-compare", help="Compare evidence from two independently approved runs")
    retest.add_argument("--first", required=True)
    retest.add_argument("--second", required=True)
    retest.add_argument("--out", required=True)
    benchmark = sub.add_parser("workflow-benchmark", help="Exercise original offline positive/negative configuration fixtures")
    benchmark.add_argument("--out", required=True)
    discovery = sub.add_parser("discovery-setup", help="Plan bounded same-origin HTML discovery; sends no requests")
    discovery.add_argument("--profile", required=True)
    discovery.add_argument("--seed", action="append", required=True)
    discovery.add_argument("--out-dir", required=True)
    discovery.add_argument("--max-pages", type=int, default=5)
    discovery.add_argument("--max-depth", type=int, default=1)
    discovery.add_argument("--authorized", action="store_true")
    assessment = sub.add_parser("assessment-setup", help="Plan fixed access, service or read-only AWS checks without traffic")
    assessment.add_argument("--profile", required=True)
    assessment.add_argument("--tool", choices=("authorization-matrix", "service-enumeration", "aws-account-audit", "web-canary-check"), required=True)
    assessment.add_argument("--out-dir", required=True)
    assessment.add_argument("--input")
    assessment.add_argument("--credentials")
    assessment.add_argument("--target", action="append", default=[])
    assessment.add_argument("--authorized", action="store_true")
    coverage = sub.add_parser("coverage-audit", help="Show honest delivery and missing coverage across seven assessment areas")
    coverage.add_argument("--format", choices=("json", "markdown"), default="json")
    sub.add_parser("web-review-catalog", help="Show all 16 Web Application review contracts and execution limits")
    web_review = sub.add_parser("web-source-review", help="Offline Python web security source cues; never executes inspected code")
    web_review.add_argument("--project", required=True)
    web_review.add_argument("--out", required=True)
    web_review.add_argument("--authorized", action="store_true")
    sub.add_parser("identity-review-catalog", help="Show JWT and OAuth/OIDC offline review contracts")
    identity = sub.add_parser("identity-review", help="Review private JWT samples and OAuth/OIDC configuration offline")
    identity.add_argument("--input", required=True)
    identity.add_argument("--out", required=True)
    identity.add_argument("--authorized", action="store_true")
    sub.add_parser("ad-review-catalog", help="Show Active Directory and NetExec offline review contracts")
    ad = sub.add_parser("ad-review", help="Review owner-normalized AD policy evidence offline without directory queries")
    ad.add_argument("--input", required=True)
    ad.add_argument("--out", required=True)
    ad.add_argument("--authorized", action="store_true")
    sub.add_parser("wireless-review-catalog", help="Show all 14 offline Wireless review contracts and field schemas")
    for name in ("wireless-review", "wireless-hostapd-review"):
        wireless = sub.add_parser(name, help="Offline wireless evidence/source review; no radio access or security-tool execution")
        wireless.add_argument("--input", required=True)
        wireless.add_argument("--out", required=True)
        wireless.add_argument("--authorized", action="store_true")
    sub.add_parser("cloud-review-catalog", help="Show offline AWS/Azure/GCP evidence fields and selected native policy modes")
    for name in ("cloud-review", "cloud-policy-review"):
        cloud = sub.add_parser(name, help="Offline cloud policy review; no provider connection or credentials")
        cloud.add_argument("--input", required=True)
        cloud.add_argument("--out", required=True)
        cloud.add_argument("--authorized", action="store_true")
        if name == "cloud-policy-review":
            cloud.add_argument("--mode", choices=("aws-iam", "gcp-iam", "azure-nsg"), required=True)
    sub.add_parser("mobile-review-catalog", help="Show selected offline Android/iOS review fields and XML modes")
    for name in ("mobile-review", "mobile-config-review"):
        mobile = sub.add_parser(name, help="Offline mobile evidence/XML review; no app or device execution")
        mobile.add_argument("--input", required=True)
        mobile.add_argument("--out", required=True)
        mobile.add_argument("--authorized", action="store_true")
        if name == "mobile-config-review":
            mobile.add_argument("--mode", choices=("android-manifest", "android-network-security", "ios-info", "ios-entitlements"), required=True)
    sub.add_parser("iot-review-catalog", help="Show selected offline IoT evidence, MQTT ACL and U-Boot review contracts")
    for name in ("iot-review", "iot-config-review"):
        iot = sub.add_parser(name, help="Offline IoT evidence/source review; no hardware or network access")
        iot.add_argument("--input", required=True)
        iot.add_argument("--out", required=True)
        iot.add_argument("--authorized", action="store_true")
        if name == "iot-config-review":
            iot.add_argument("--mode", choices=("mqtt-acl", "uboot-config"), required=True)
    sub.add_parser("infrastructure-review-catalog", help="Show seven offline defensive Infrastructure review contracts")
    for name in ("infrastructure-review", "infrastructure-pe-review"):
        infra = sub.add_parser(name, help="Offline defensive evidence/PE header review; no payload or evasion execution")
        infra.add_argument("--input", required=True)
        infra.add_argument("--out", required=True)
        infra.add_argument("--authorized", action="store_true")
    sub.add_parser("exploit-dev-review-catalog", help="Show six offline exploit-development assurance contracts")
    for name in ("exploit-dev-review", "exploit-dev-artifact-review"):
        dev = sub.add_parser(name, help="Offline assurance/log/ELF review; no exploit or binary execution")
        dev.add_argument("--input", required=True)
        dev.add_argument("--out", required=True)
        dev.add_argument("--authorized", action="store_true")
        if name == "exploit-dev-artifact-review":
            dev.add_argument("--mode", choices=("sanitizer-log", "elf-headers"), required=True)
    sub.add_parser("fuzzing-review-catalog", help="Show four offline fuzzing/research review contracts")
    for name in ("fuzzing-review", "fuzzing-artifact-review"):
        fuzz = sub.add_parser(name, help="Offline campaign evidence/metrics review; no fuzzer or harness execution")
        fuzz.add_argument("--input", required=True)
        fuzz.add_argument("--out", required=True)
        fuzz.add_argument("--authorized", action="store_true")
        if name == "fuzzing-artifact-review":
            fuzz.add_argument("--mode", choices=("afl-stats", "libfuzzer-log"), required=True)
    sub.add_parser("recon-review-catalog", help="Show two offline OSINT review contracts")
    for name in ("recon-review", "recon-inventory"):
        recon = sub.add_parser(name, help="Offline reconnaissance evidence or scoped name import; no DNS or external collection")
        recon.add_argument("--input", required=True)
        recon.add_argument("--out", required=True)
        recon.add_argument("--authorized", action="store_true")
        if name == "recon-inventory":
            recon.add_argument("--scope", required=True)
            recon.add_argument("--mode", choices=("names", "ct-names-json"), default="names")
            recon.add_argument("--include-names", action="store_true", help="Include admitted canonical names in the private report")
    sub.add_parser("api-review-catalog", help="Show two offline API security and business-logic assurance contracts")
    for name in ("api-review", "api-openapi-review"):
        api = sub.add_parser(name, help="Offline API evidence/OpenAPI JSON review; no endpoint requests")
        api.add_argument("--input", required=True)
        api.add_argument("--out", required=True)
        api.add_argument("--authorized", action="store_true")
    sub.add_parser("container-review-catalog", help="Show two offline Container/Kubernetes review contracts")
    for name in ("container-review", "container-config-review"):
        container = sub.add_parser(name, help="Offline container evidence/JSON review; no daemon or cluster connection")
        container.add_argument("--input", required=True)
        container.add_argument("--out", required=True)
        container.add_argument("--authorized", action="store_true")
        if name == "container-config-review":
            container.add_argument("--mode", choices=("docker-inspect", "kubernetes"), required=True)
    sub.add_parser("cicd-review-catalog", help="Show two offline CI/CD assurance contracts")
    for name in ("cicd-review", "cicd-workflow-review"):
        cicd = sub.add_parser(name, help="Offline CI/CD observations or saved GitHub Actions JSON; no workflow execution")
        cicd.add_argument("--input", required=True)
        cicd.add_argument("--out", required=True)
        cicd.add_argument("--authorized", action="store_true")
    sub.add_parser("crypto-review-catalog", help="Show two offline Cryptography assurance contracts")
    for name in ("crypto-review", "crypto-source-review"):
        crypto = sub.add_parser(name, help="Offline cryptography observations or selected Python AST; no execution or connections")
        crypto.add_argument("--input", required=True)
        crypto.add_argument("--out", required=True)
        crypto.add_argument("--authorized", action="store_true")
    sub.add_parser("privilege-review-catalog", help="Show two offline Linux/Windows privilege assurance contracts")
    for name in ("privilege-review", "privilege-inventory-review"):
        privilege = sub.add_parser(name, help="Offline privilege evidence or saved inventory; no host enumeration or execution")
        privilege.add_argument("--input", required=True)
        privilege.add_argument("--out", required=True)
        privilege.add_argument("--authorized", action="store_true")
        if name == "privilege-inventory-review":
            privilege.add_argument("--mode", choices=("getcap-text", "windows-services-json"), required=True)
    sub.add_parser("post-exploitation-review-catalog", help="Show three offline post-exploitation assurance contracts")
    for name in ("post-exploitation-review", "post-exploitation-inventory-review"):
        post = sub.add_parser(name, help="Offline observations or saved task/flow review; no execution or transfers")
        post.add_argument("--input", required=True)
        post.add_argument("--out", required=True)
        post.add_argument("--authorized", action="store_true")
        if name == "post-exploitation-inventory-review":
            post.add_argument("--mode", choices=("windows-task-xml", "vpc-flow-text"), required=True)
            post.add_argument("--large-flow-bytes", type=int, default=10485760, help="Per-record flow review threshold; not an exfiltration verdict")
    sub.add_parser("forensics-review-catalog", help="Show two offline evidence-integrity/C2 assurance contracts")
    for name in ("forensics-review", "forensics-log-review"):
        forensic = sub.add_parser(name, help="Offline observations or saved event/DNS logs; no alteration, agents or connections")
        forensic.add_argument("--input", required=True)
        forensic.add_argument("--out", required=True)
        forensic.add_argument("--authorized", action="store_true")
        if name == "forensics-log-review":
            forensic.add_argument("--mode", choices=("windows-events-xml", "zeek-dns-jsonl"), required=True)
            forensic.add_argument("--long-query-chars", type=int, default=80, help="DNS string review threshold; not a C2 verdict")
    sub.add_parser("supply-chain-review-catalog", help="Show two offline supply-chain assurance contracts")
    for name in ("supply-chain-review", "supply-chain-config-review"):
        supply = sub.add_parser(name, help="Offline observations or saved npm/pip declarations; no registry access or installation")
        supply.add_argument("--input", required=True)
        supply.add_argument("--out", required=True)
        supply.add_argument("--authorized", action="store_true")
        if name == "supply-chain-config-review":
            supply.add_argument("--mode", choices=("npm-lock-json", "npmrc-text", "pip-conf"), required=True)
    sub.add_parser("social-review-catalog", help="Show two offline social-engineering assurance contracts")
    for name in ("social-review", "social-evidence-review"):
        social = sub.add_parser(name, help="Offline observations or saved DMARC/simulation metadata; no delivery or collection")
        social.add_argument("--input", required=True)
        social.add_argument("--out", required=True)
        social.add_argument("--authorized", action="store_true")
        if name == "social-evidence-review":
            social.add_argument("--mode", choices=("dmarc-text", "gophish-results-json"), required=True)
    sub.add_parser("network-review-catalog", help="Show one offline Layer 2/3 network assurance contract")
    for name in ("network-review", "network-config-review"):
        network = sub.add_parser(name, help="Offline observations or saved network/resolver config; no packets or host changes")
        network.add_argument("--input", required=True)
        network.add_argument("--out", required=True)
        network.add_argument("--authorized", action="store_true")
        if name == "network-config-review":
            network.add_argument("--mode", choices=("sysctl-text", "resolved-conf"), required=True)
    sub.add_parser("ai-security-review-catalog", help="Show one offline AI application assurance contract")
    for name in ("ai-security-review", "ai-security-evidence-review"):
        ai_review = sub.add_parser(name, help="Offline observations, owned saved cases or garak summaries; no model or tool calls")
        ai_review.add_argument("--input", required=True)
        ai_review.add_argument("--out", required=True)
        ai_review.add_argument("--authorized", action="store_true")
        if name == "ai-security-evidence-review":
            ai_review.add_argument("--mode", choices=("owned-cases-json", "garak-jsonl"), required=True)
    readiness = sub.add_parser("assessment-readiness", help="Read-only installation and retained owned-lab evidence checks; no assessment authorization")
    readiness.add_argument("--profile")
    readiness.add_argument("--benchmark-dir")
    readiness.add_argument("--require-owned-lab", action="store_true")
    operator_secret = sub.add_parser("operator-secret", help="Create a private persistent session-key file without displaying its value")
    operator_secret.add_argument("--out", required=True)
    operator_secret.add_argument("--authorized", action="store_true")
    for name in ("operator-init", "operator-add", "operator-update", "operator-status", "operator-audit"):
        operator = sub.add_parser(name, help="Manage opt-in local dashboard operators; not target assessment permission")
        operator.add_argument("--database", required=True)
        if name in ("operator-init", "operator-add", "operator-update"):
            operator.add_argument("--username", required=True)
            operator.add_argument("--authorized", action="store_true")
        if name == "operator-add":
            operator.add_argument("--role", choices=("viewer", "analyst", "admin"), required=True)
        if name == "operator-update":
            operator.add_argument("--role", choices=("viewer", "analyst", "admin"))
            enabled = operator.add_mutually_exclusive_group()
            enabled.add_argument("--enable", action="store_true")
            enabled.add_argument("--disable", action="store_true")
            operator.add_argument("--reset-password", action="store_true")
    assessment_benchmark = sub.add_parser("assessment-benchmark", help="Run versioned owned-loopback application controls; never a real-world accuracy score")
    assessment_benchmark.add_argument("--out-dir", required=True)
    assessment_benchmark.add_argument("--authorized", action="store_true")
    quota_init = sub.add_parser("quota-init", help="Initialize a host-local shared quota window")
    quota_init.add_argument("--ledger", required=True)
    quota_init.add_argument("--max-requests", type=int, required=True)
    quota_init.add_argument("--max-active-runs", type=int, required=True)
    quota_init.add_argument("--expires-at", required=True)
    quota_init.add_argument("--authorized", action="store_true")
    for name in ("quota-status", "quota-stop", "quota-reconcile"):
        quota_command = sub.add_parser(name, help="Inspect, stop or reconcile shared local quotas")
        quota_command.add_argument("--ledger", required=True)
        if name != "quota-status":
            quota_command.add_argument("--authorized", action="store_true")
        if name == "quota-reconcile":
            quota_command.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    if args.command == "ai-security-review-catalog":
        from .ai_security_review import catalog
        print(json.dumps({"category": "AI Security", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command in ("ai-security-review", "ai-security-evidence-review"):
        from .ai_security_review import review_file
        report = review_file(args.input, authorized=args.authorized, mode=args.mode if args.command == "ai-security-evidence-review" else "normalized")
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "network-review-catalog":
        from .network_review import catalog
        print(json.dumps({"category": "Network", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command in ("network-review", "network-config-review"):
        from .network_review import review_file
        report = review_file(args.input, authorized=args.authorized, mode=args.mode if args.command == "network-config-review" else "normalized")
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "social-review-catalog":
        from .social_engineering_review import catalog
        print(json.dumps({"category": "Social Engineering", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command in ("social-review", "social-evidence-review"):
        from .social_engineering_review import review_file
        report = review_file(args.input, authorized=args.authorized, mode=args.mode if args.command == "social-evidence-review" else "normalized")
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "supply-chain-review-catalog":
        from .supply_chain_review import catalog
        print(json.dumps({"category": "Supply Chain", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command in ("supply-chain-review", "supply-chain-config-review"):
        from .supply_chain_review import review_file
        report = review_file(args.input, authorized=args.authorized, mode=args.mode if args.command == "supply-chain-config-review" else "normalized")
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "forensics-review-catalog":
        from .forensics_review import catalog
        print(json.dumps({"category": "Forensics & C2", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command in ("forensics-review", "forensics-log-review"):
        from .forensics_review import review_file
        kwargs = {"mode": args.mode, "long_query_chars": args.long_query_chars} if args.command == "forensics-log-review" else {}
        report = review_file(args.input, authorized=args.authorized, **kwargs)
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "post-exploitation-review-catalog":
        from .post_exploitation_review import catalog
        print(json.dumps({"category": "Post-Exploitation", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command in ("post-exploitation-review", "post-exploitation-inventory-review"):
        from .post_exploitation_review import review_file
        kwargs = {"mode": args.mode, "large_flow_bytes": args.large_flow_bytes} if args.command == "post-exploitation-inventory-review" else {}
        report = review_file(args.input, authorized=args.authorized, **kwargs)
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "privilege-review-catalog":
        from .privilege_review import catalog
        print(json.dumps({"category": "Privilege Escalation", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command in ("privilege-review", "privilege-inventory-review"):
        from .privilege_review import review_file
        report = review_file(args.input, authorized=args.authorized, mode=args.mode if args.command == "privilege-inventory-review" else "normalized")
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "crypto-review-catalog":
        from .crypto_review import catalog
        print(json.dumps({"category": "Cryptography", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command in ("crypto-review", "crypto-source-review"):
        from .crypto_review import review_file
        report = review_file(args.input, authorized=args.authorized, mode="python-source" if args.command == "crypto-source-review" else "normalized")
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "cicd-review-catalog":
        from .cicd_review import catalog
        print(json.dumps({"category": "CI/CD & Pipelines", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command in ("cicd-review", "cicd-workflow-review"):
        from .cicd_review import review_file
        report = review_file(args.input, authorized=args.authorized, mode="github-actions-json" if args.command == "cicd-workflow-review" else "normalized")
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "container-review-catalog":
        from .container_review import catalog
        print(json.dumps({"category": "Containers & Kubernetes", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command in ("container-review", "container-config-review"):
        from .container_review import review_file
        report = review_file(args.input, authorized=args.authorized, mode=args.mode if args.command == "container-config-review" else "normalized")
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "api-review-catalog":
        from .api_review import catalog
        print(json.dumps({"category": "API Security", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command in ("api-review", "api-openapi-review"):
        from .api_review import review_file
        report = review_file(args.input, authorized=args.authorized, mode="openapi-json" if args.command == "api-openapi-review" else "normalized")
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "recon-review-catalog":
        from .recon_review import catalog
        print(json.dumps({"category": "Reconnaissance", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command in ("recon-review", "recon-inventory"):
        from .recon_review import inventory_file, review_file
        report = inventory_file(args.input, args.scope, authorized=args.authorized, mode=args.mode, include_names=args.include_names) if args.command == "recon-inventory" else review_file(args.input, authorized=args.authorized)
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "fuzzing-review-catalog":
        from .fuzzing_review import catalog
        print(json.dumps({"category": "Fuzzing & Vulnerability Research", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command in ("fuzzing-review", "fuzzing-artifact-review"):
        from .fuzzing_review import review_file
        report = review_file(args.input, authorized=args.authorized, mode=args.mode if args.command == "fuzzing-artifact-review" else "normalized")
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "exploit-dev-review-catalog":
        from .exploit_dev_review import catalog
        print(json.dumps({"category": "Exploit Development", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command in ("exploit-dev-review", "exploit-dev-artifact-review"):
        from .exploit_dev_review import review_file
        report = review_file(args.input, authorized=args.authorized, mode=args.mode if args.command == "exploit-dev-artifact-review" else "normalized")
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "infrastructure-review-catalog":
        from .infrastructure_review import catalog
        print(json.dumps({"category": "Infrastructure & Red Team", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command in ("infrastructure-review", "infrastructure-pe-review"):
        from .infrastructure_review import review_file
        report = review_file(args.input, authorized=args.authorized, mode="pe-headers" if args.command == "infrastructure-pe-review" else "normalized")
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "iot-review-catalog":
        from .iot_review import catalog
        print(json.dumps({"category": "IoT & Embedded", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command in ("iot-review", "iot-config-review"):
        from .iot_review import review_file
        report = review_file(args.input, authorized=args.authorized, mode=args.mode if args.command == "iot-config-review" else "normalized")
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "mobile-review-catalog":
        from .mobile_review import catalog
        print(json.dumps({"category": "Mobile", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command in ("mobile-review", "mobile-config-review"):
        from .mobile_review import review_file
        report = review_file(args.input, authorized=args.authorized, mode=args.mode if args.command == "mobile-config-review" else "normalized")
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "cloud-review-catalog":
        from .cloud_review import catalog
        print(json.dumps({"category": "Cloud", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command in ("cloud-review", "cloud-policy-review"):
        from .cloud_review import review_file
        report = review_file(args.input, authorized=args.authorized, mode=args.mode if args.command == "cloud-policy-review" else "normalized")
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "wireless-review-catalog":
        from .wireless_review import catalog
        print(json.dumps({"category": "Wireless", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command in ("wireless-review", "wireless-hostapd-review"):
        from .wireless_review import review_file, review_hostapd
        review = review_hostapd if args.command == "wireless-hostapd-review" else review_file
        report = review(args.input, authorized=args.authorized)
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "ad-review-catalog":
        from .ad_review import catalog
        print(json.dumps({"category": "Active Directory", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command == "ad-review":
        from .ad_review import review_file
        report = review_file(args.input, authorized=args.authorized)
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "identity-review-catalog":
        from .identity_review import catalog
        print(json.dumps({"category": "Auth & Identity", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command == "identity-review":
        from .identity_review import review_file
        report = review_file(args.input, authorized=args.authorized)
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "web-review-catalog":
        from .web_review import catalog
        print(json.dumps({"category": "Web Application", "skills": catalog(), "all_skills_automated": False}, indent=2))
        return
    if args.command == "web-source-review":
        if not args.authorized:
            raise PermissionError("Source review requires --authorized")
        from .web_review import review_project
        root = _approved_root(args.project)
        _write_bounty_output(args.out, json.dumps(review_project(root), indent=2, ensure_ascii=False) + "\n")
        return
    if args.command.startswith("operator-"):
        from . import operator_store
        if args.command in ("operator-init", "operator-add", "operator-update", "operator-secret") and not args.authorized:
            raise PermissionError("Local operator administration requires --authorized")
        password = None
        if args.command in ("operator-init", "operator-add") or (args.command == "operator-update" and args.reset_password):
            password = os.environ.get("HUNTERQA_OPERATOR_PASSWORD")
            if password is None:
                import getpass
                password = getpass.getpass("New local operator password: ")
                if password != getpass.getpass("Confirm password: "):
                    raise ValueError("Passwords did not match")
        if args.command == "operator-secret":
            result = operator_store.create_session_key(args.out, authorized=True)
        elif args.command == "operator-init":
            result = operator_store.initialize(args.database, args.username, password, authorized=True)
        elif args.command == "operator-add":
            result = operator_store.add_operator(args.database, args.username, args.role, password, authorized=True)
        elif args.command == "operator-update":
            result = operator_store.update_operator(args.database, args.username, role=args.role,
                active=True if args.enable else False if args.disable else None, password=password, authorized=True)
        elif args.command == "operator-audit":
            result = operator_store.audit_status(args.database)
        else:
            result = operator_store.status(args.database)
        print(json.dumps(result, indent=2))
        return
    if args.command == "assessment-readiness":
        from .assessment_readiness import assessment_readiness
        result = assessment_readiness(profile=args.profile, benchmark_dir=args.benchmark_dir)
        print(json.dumps(result, indent=2))
        if args.require_owned_lab and not result["supported_owned_lab_checks_passed"]:
            raise SystemExit(2)
        return
    if args.command == "coverage-audit":
        from .coverage_audit import coverage_audit, render_checklist
        print(render_checklist() if args.format == "markdown" else json.dumps(coverage_audit(), indent=2))
        return
    if args.command == "assessment-benchmark":
        from .assessment_benchmark import benchmark_assessments
        print(json.dumps(benchmark_assessments(args.out_dir, authorized=args.authorized), indent=2))
        return
    if args.command == "assessment-setup":
        from .assessment_setup import setup_assessment
        result = setup_assessment(args.profile, args.tool, args.out_dir, targets=args.target,
            input_file=args.input, secret_file=args.credentials, authorized=args.authorized)
        print(json.dumps(result, indent=2))
        return
    if args.command.startswith("quota-"):
        from . import shared_quota
        if args.command == "quota-init":
            result = shared_quota.initialize(args.ledger, max_requests=args.max_requests,
                max_active_runs=args.max_active_runs, expires_at=args.expires_at, authorized=args.authorized)
        elif args.command == "quota-stop":
            result = shared_quota.stop(args.ledger, authorized=args.authorized)
        elif args.command == "quota-reconcile":
            result = shared_quota.reconcile(args.ledger, args.run_id, authorized=args.authorized)
        else:
            result = shared_quota.status(args.ledger)
        print(json.dumps(result, indent=2))
        return
    if args.command == "discovery-setup":
        from .web_discovery import setup_discovery
        result = setup_discovery(args.profile, args.seed, args.out_dir,
                                 max_pages=args.max_pages, max_depth=args.max_depth, authorized=args.authorized)
        print(json.dumps(result, indent=2))
        return
    if args.command == "workflow-abandon":
        from .workflow_runner import abandon_run
        print(json.dumps(abandon_run(args.run, authorized=args.authorized), indent=2))
        return
    if args.command == "workflow-setup":
        from .workflow_runner import setup_workflow
        result = setup_workflow(args.profile, args.project, args.target, args.out_dir,
                                observe=args.observe, authorized=args.authorized)
        print(json.dumps(result, indent=2))
        return
    if args.command == "workflow-run-plan":
        from .workflow_runner import execution_plan
        _write_bounty_output(args.out, json.dumps(execution_plan(args.profile, args.protocol, args.bindings), indent=2) + "\n")
        return
    if args.command == "workflow-run":
        from .workflow_runner import run_workflow
        result = run_workflow(args.profile, args.protocol, args.bindings, args.out_dir,
                              execution_approval=args.approve_execution,
                              protocol_approval=args.approve_protocol, approved_steps=args.approve_step,
                              authorized=args.authorized, operator=args.operator)
        print(json.dumps(result, indent=2))
        return
    if args.command in ("workflow-status", "workflow-stop"):
        from .workflow_runner import stop_run
        from .workflow_results import summarize_run
        result = stop_run(args.run) if args.command == "workflow-stop" else summarize_run(args.run)
        print(json.dumps(result, indent=2))
        return
    if args.command == "workflow-export":
        from .workflow_results import export_report
        print(json.dumps(export_report(args.run, args.out, args.format), indent=2))
        return
    if args.command == "workflow-review":
        from .workflow_results import review_finding
        print(json.dumps(review_finding(args.run, args.finding, args.decision, args.reviewer,
                                        args.note, args.evidence, authorized=args.authorized), indent=2))
        return
    if args.command == "workflow-compare":
        from .workflow_results import compare_runs
        _write_bounty_output(args.out, json.dumps(compare_runs(args.first, args.second), indent=2) + "\n")
        return
    if args.command == "workflow-benchmark":
        from .workflow_benchmark import benchmark_adapters
        _write_bounty_output(args.out, json.dumps(benchmark_adapters(Path(args.out).parent), indent=2) + "\n")
        return
    if args.command == "workflow-tools":
        from .workflow_protocol import tool_catalog
        print(json.dumps({"tools": tool_catalog(), "execution_enabled": False}, indent=2))
        return
    if args.command == "workflow-preflight":
        from .workflow_protocol import compile_protocol
        result = compile_protocol(args.profile, args.protocol,
                                  approved_steps=args.approve_step,
                                  approved_fingerprint=args.approve_protocol,
                                  authorized=args.authorized)
        _write_bounty_output(args.out, json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        return
    if args.command == "research-playbooks":
        from .research_workspace import PLAYBOOKS
        print(json.dumps({"playbooks": PLAYBOOKS, "execution": "none"}, indent=2))
        return
    if args.command == "research-init":
        from .research_workspace import create_workspace
        result = create_workspace(args.profile, args.out_dir, args.playbook, authorized=args.authorized)
        print(json.dumps(result, indent=2))
        return
    if args.command == "research-note":
        from .research_workspace import append_note
        result = append_note(args.profile, args.workspace, args.kind, args.summary,
                             evidence=args.evidence, authorized=args.authorized)
        print(json.dumps(result, indent=2))
        return
    if args.command == "research-resume":
        from .research_workspace import resume_workspace
        print(json.dumps(resume_workspace(args.workspace), indent=2))
        return
    if args.command == "external-import":
        from .external_evidence import import_external
        result = import_external(args.profile, args.file, args.tool, authorized=args.authorized)
        _write_bounty_output(args.out, json.dumps(result, indent=2) + "\n")
        return
    if args.command == "report-sarif":
        from .sarif_export import export_sarif
        _write_bounty_output(args.out, json.dumps(export_sarif(args.file), indent=2) + "\n")
        return
    if args.command == "engagement-compare":
        from .assessment_evidence import compare_assessments
        report = compare_assessments(args.first, args.second)
        _write_bounty_output(args.out, json.dumps(report, indent=2) + "\n")
        return
    if args.command == "engagement-plan":
        from .engagement import create_plan
        plan = create_plan(args.profile, args.url, mode=args.mode, method=args.method,
                           ttl_minutes=args.ttl_minutes, dedicated_test_account=args.dedicated_test_account,
                           browser_isolated=args.browser_isolated, login_url=args.login_url,
                           expected_status=args.expected_status)
        _write_bounty_output(args.out, json.dumps(plan, indent=2) + "\n")
        return
    if args.command == "engagement-preflight":
        from .engagement import load_plan, digest
        _, plan = load_plan(args.profile, args.plan)
        print(json.dumps({"plan": plan, "approval_sha256": digest(plan),
                          "network_requests": 0, "approval_is_operator_attestation": True}, indent=2))
        return
    if args.command == "engagement-run":
        from .engagement import run_assessment
        # Reserve private output BEFORE traffic, so an existing/unwritable output
        # cannot cause an unrecorded repeat assessment.
        destination = Path(args.out).expanduser()
        _approved_root(str(destination.parent.resolve(strict=True)))
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(destination, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            try:
                report = run_assessment(args.profile, args.plan, args.approve_plan,
                                        args.stop_file, authorized=args.authorized)
            except Exception as exc:
                stream.write(json.dumps({"outcome": "preflight_failed", "error_type": type(exc).__name__}) + "\n")
                raise
            stream.write(json.dumps(report, indent=2) + "\n")
        print("Saved:", destination)
        return
    if args.command == "engagement-package":
        from .engagement import prepare_package
        report = prepare_package(args.profile, args.dossier, kind=args.kind,
                                 reviewed=args.reviewed, authorized=args.authorized,
                                 assigned_cve=args.assigned_cve)
        _write_bounty_output(args.out, json.dumps(report, indent=2) + "\n")
        return
    if args.command == "capabilities":
        print("Assessment coverage: run coverage-audit for the seven-area implementation inventory and explicit missing features.")
        print("Development adapters: assessment-setup; fixed web canaries, role GET contracts, TCP reachability and optional read-only AWS account APIs.")
        print("Research context: original review playbooks, private policy-bound journal, context-only resume; no tool execution.")
        print("Interoperability: offline Nuclei/ZAP evidence, conservative SARIF export, and an acknowledgment-gated source-only GitHub Action.")
        print("Approved assessments: engagement-plan/preflight/run; exact targets, expiring fingerprint approval, bounded requests.")
        print("Modes: observe, benign WAF canary, one designated-account login check, narrow remote browser form review.")
        print("Reviewed handoff: engagement-package; offline disclosure/CVE requests, no automatic sending or CVE assignment.")
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
    elif args.command == "bounty-ai-review":
        from .agent_ai_v12 import suggest_reviews
        report = suggest_reviews(args.plan, model=args.model, authorized=args.authorized)
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    elif args.command == "bounty-browser-lab":
        from .browser_lab_v12 import inspect_owned_browser
        report = inspect_owned_browser(
            args.profile, args.url, authorized=args.authorized,
            login=args.login, login_post_path=args.login_post_path,
            username_selector=args.username_selector,
            password_selector=args.password_selector,
            submit_selector=args.submit_selector,
        )
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    elif args.command == "bounty-replay-head":
        from .replay_v12 import replay_har_head
        report = replay_har_head(
            args.profile, args.har_report, authorized=args.authorized
        )
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    elif args.command == "bounty-review-init":
        from .verification_v12 import prepare_dossier
        report = prepare_dossier(args.profile, args.correlation, authorized=args.authorized)
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    elif args.command == "bounty-review-decide":
        from .verification_v12 import record_review
        report = record_review(
            args.profile, args.dossier, args.case, args.decision, args.reviewer,
            impact=args.impact, reproduction=args.reproduction,
            evidence_path=args.evidence, authorized=args.authorized,
        )
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    elif args.command == "bounty-review-export":
        from .verification_v12 import disclosure_draft
        content = disclosure_draft(args.profile, args.dossier, authorized=args.authorized)
        _write_bounty_output(args.out, content)
    elif args.command == "bounty-repeatability":
        from .repeatability_v12 import compare_head_replays
        report = compare_head_replays(args.profile, args.first, args.second,
                                      authorized=args.authorized)
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    elif args.command == "bounty-reproduction-note":
        from .verification_v12 import create_reproduction_note
        note = create_reproduction_note(
            args.profile, args.case, args.reviewer,
            args.expected, args.observed, args.context,
            attest=args.attest, authorized=args.authorized,
        )
        _write_bounty_output(args.out, json.dumps(note, indent=2, ensure_ascii=False) + "\n")
    elif args.command == "bounty-benchmark":
        from .benchmark_v12 import benchmark_gate, evaluate_pack
        report = evaluate_pack(args.profile, args.pack, authorized=args.authorized)
        _write_bounty_output(args.out, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        print("Synthetic review cue metrics:", json.dumps(report["metrics"], indent=2))
        benchmark_gate(report, fail_on_review_regression=args.strict)
        print("Review expectation gate:", "PASS" if report["golden_review_expectations_met"] else "REVIEW NEEDED")
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
        from .engines.fuzzing import verify_crashes
        root = _approved_root(args.lab)
        result = verify_crashes(approved_lab=root, binary_path=Path(args.binary), crash_dir=Path(args.crashes),
                                output=Path(args.out), authorized=args.authorized)
        print("Replayed", result["total_crashes"], "local crash inputs. Review evidence before assigning vulnerability status.")

if __name__ == "__main__":
    main()
