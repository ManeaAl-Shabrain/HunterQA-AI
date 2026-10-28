from __future__ import annotations

import json
from datetime import datetime, timezone

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, url_for

from .db import get_db
from .security import AUTHORIZATION_TEXT, csrf_token, valid_csrf, validate_project_path


bp = Blueprint("main", __name__)


@bp.app_context_processor
def inject_globals():
    return {"csrf_token": csrf_token, "authorization_text": AUTHORIZATION_TEXT}


def require_csrf():
    if not valid_csrf(request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")):
        abort(400, "Invalid form token. Refresh the page and try again.")


@bp.get("/")
def dashboard():
    db = get_db()
    stats = db.execute(
        """SELECT
             (SELECT COUNT(*) FROM projects) AS projects,
             (SELECT COUNT(*) FROM scans) AS scans,
             (SELECT COUNT(*) FROM findings) AS findings,
             (SELECT COUNT(*) FROM findings WHERE severity = 'ERROR') AS critical
        """
    ).fetchone()
    recent = db.execute(
        """SELECT scans.*, projects.name AS project_name,
                  (SELECT COUNT(*) FROM findings WHERE findings.scan_id = scans.id) AS finding_count
           FROM scans JOIN projects ON projects.id = scans.project_id
           ORDER BY scans.id DESC LIMIT 8"""
    ).fetchall()
    projects = db.execute("SELECT * FROM projects ORDER BY id DESC LIMIT 5").fetchall()
    return render_template("dashboard.html", stats=stats, recent=recent, projects=projects)


@bp.get("/projects")
def projects():
    rows = get_db().execute(
        """SELECT projects.*,
                  (SELECT COUNT(*) FROM scans WHERE scans.project_id = projects.id) AS scan_count,
                  (SELECT status FROM scans WHERE scans.project_id = projects.id ORDER BY id DESC LIMIT 1) AS last_status
           FROM projects ORDER BY projects.id DESC"""
    ).fetchall()
    return render_template("projects.html", projects=rows)


@bp.post("/projects")
def create_project():
    require_csrf()
    name = request.form.get("name", "").strip()
    if not name or len(name) > 100:
        flash("Project name is required and must be under 100 characters.", "error")
        return redirect(url_for("main.projects"))
    try:
        path = validate_project_path(request.form.get("path", ""))
        with get_db() as db:
            db.execute("INSERT INTO projects (name, path) VALUES (?, ?)", (name, str(path)))
    except (ValueError, OSError) as exc:
        flash(str(exc), "error")
    except Exception as exc:
        if "UNIQUE" in str(exc):
            flash("That local directory is already registered.", "error")
        else:
            raise
    else:
        with get_db() as db:
            db.execute("INSERT INTO audit_events(action, subject) VALUES (?, ?)", ("project_registered", str(path)[:500]))
        flash("Project added to the approved workspace.", "success")
    return redirect(url_for("main.projects"))


@bp.post("/projects/<int:project_id>/scans")
def start_scan(project_id: int):
    require_csrf()
    db = get_db()
    project = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if project is None:
        abort(404)
    try:
        validate_project_path(project["path"])
    except ValueError as exc:
        flash(f"Project authorization boundary changed: {exc}", "error")
        return redirect(url_for("main.projects"))
    confirmed = request.form.get("authorized") == "yes"
    typed = request.form.get("authorization_text", "").strip()
    if not confirmed or typed != AUTHORIZATION_TEXT:
        flash("Scan not started. Confirm authorization and enter the exact authorization statement.", "error")
        return redirect(url_for("main.projects"))
    with db:
        cursor = db.execute(
            "INSERT INTO scans (project_id, status, progress, stage, authorized_at) VALUES (?, 'queued', 0, 'Queued', ?)",
            (project_id, datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )
        scan_id = cursor.lastrowid
    with db:
        db.execute("INSERT INTO audit_events(action, subject) VALUES (?, ?)", ("scan_authorized", str(scan_id)))
    current_app.extensions["scan_service"].submit(scan_id)
    return redirect(url_for("main.scan_detail", scan_id=scan_id))


@bp.get("/scans/<int:scan_id>")
def scan_detail(scan_id: int):
    db = get_db()
    scan = db.execute(
        "SELECT scans.*, projects.name AS project_name, projects.path AS project_path FROM scans JOIN projects ON projects.id = scans.project_id WHERE scans.id = ?",
        (scan_id,),
    ).fetchone()
    if scan is None:
        abort(404)
    findings = db.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY CASE severity WHEN 'ERROR' THEN 1 WHEN 'WARNING' THEN 2 ELSE 3 END, id", (scan_id,)).fetchall()
    report = db.execute("SELECT * FROM reports WHERE scan_id = ?", (scan_id,)).fetchone()
    dependencies = db.execute("SELECT ecosystem, name, version, source FROM dependency_items WHERE scan_id = ? ORDER BY ecosystem, name LIMIT 250", (scan_id,)).fetchall()
    return render_template("scan.html", scan=scan, findings=findings, report=report, dependencies=dependencies)


@bp.get("/api/scans/<int:scan_id>/status")
def scan_status(scan_id: int):
    row = get_db().execute("SELECT id, status, progress, stage, error FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        abort(404)
    return jsonify(dict(row))


@bp.get("/findings/<int:finding_id>")
def finding_detail(finding_id: int):
    row = get_db().execute(
        "SELECT findings.*, projects.name AS project_name FROM findings JOIN scans ON scans.id = findings.scan_id JOIN projects ON projects.id = scans.project_id WHERE findings.id = ?",
        (finding_id,),
    ).fetchone()
    if row is None:
        abort(404)
    return render_template("finding.html", finding=row)


@bp.get("/scans/<int:scan_id>/report")
def report_detail(scan_id: int):
    row = get_db().execute(
        "SELECT reports.*, projects.name AS project_name FROM reports JOIN scans ON scans.id = reports.scan_id JOIN projects ON projects.id = scans.project_id WHERE reports.scan_id = ?",
        (scan_id,),
    ).fetchone()
    if row is None:
        abort(404)
    return render_template("report.html", report=row)


@bp.get("/scans/<int:scan_id>/export.json")
def export_scan(scan_id: int):
    db = get_db()
    scan = db.execute(
        "SELECT scans.*, projects.name AS project_name, projects.path AS project_path FROM scans JOIN projects ON projects.id = scans.project_id WHERE scans.id = ?",
        (scan_id,),
    ).fetchone()
    if scan is None:
        abort(404)
    findings = [dict(row) for row in db.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()]
    report = db.execute("SELECT model, content, created_at FROM reports WHERE scan_id = ?", (scan_id,)).fetchone()
    deps = [dict(x) for x in db.execute("SELECT ecosystem, name, version, source FROM dependency_items WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()]
    payload = {"schema_version": 2, "scan": dict(scan), "findings": findings, "dependency_inventory": deps, "ai_report": dict(report) if report else None, "zero_days_confirmed": 0}
    response = current_app.response_class(json.dumps(payload, indent=2, ensure_ascii=False), mimetype="application/json")
    response.headers["Content-Disposition"] = f'attachment; filename="hunterqa-scan-{scan_id}.json"'
    return response



def _research_report_path():
    """Local administrator-selected report with migration fallbacks; never user URL input."""
    from pathlib import Path
    configured = current_app.config.get("RESEARCH_REPORT_PATH")
    if configured:
        return Path(configured).expanduser()
    candidates = [
        Path.home() / "HunterQA-AI" / "research-lab" / "verification" / "integrated_report.json",
        Path.home() / "ZeroScope-AI" / "research-lab" / "verification" / "integrated_report.json",
        Path.home() / "ZeroScope-AI" / "research-lab" / "validated_ai_report.json",
    ]
    return next((p for p in candidates if p.is_file()), candidates[0])


@bp.get("/research")
def research_lab():
    from .evidence_refresh import load_evidence_snapshot
    from .research import load_research_report
    source = _research_report_path()
    snapshot = load_evidence_snapshot(source)
    report = snapshot["report"] if snapshot["status"] == "ready" else load_research_report(source)
    from pathlib import Path
    from .engines.afl_stats import read_fuzzer_stats
    stats_path = current_app.config.get("FUZZ_STATS_PATH") or (
        Path.home() / "ZeroScope-AI" / "research-lab" / "fuzz-output-v3" / "default" / "fuzzer_stats"
    )
    afl_stats = read_fuzzer_stats(stats_path)
    return render_template("research.html", report=report, evidence_hash=snapshot["sha256"],
                           evidence_status=snapshot["status"], afl_stats=afl_stats)


@bp.get("/api/research/evidence")
def research_evidence():
    from .evidence_refresh import load_evidence_snapshot
    snapshot = load_evidence_snapshot(_research_report_path())
    report = snapshot["report"]
    return jsonify({
        "status": snapshot["status"], "sha256": snapshot["sha256"],
        "findings_count": len(report["findings"]) if report else 0,
        "sanitizer_count": len(report["sanitizer_evidence"]) if report else 0,
        "zero_days_confirmed": 0,
    })


@bp.get("/api/research/export")
def export_research_evidence():
    from .evidence_refresh import load_evidence_snapshot
    snapshot = load_evidence_snapshot(_research_report_path())
    if snapshot["status"] != "ready":
        return jsonify({"error": "Evidence unavailable"}), 404
    payload = {
        "schema_version": 2, "project": "HunterQA AI",
        "source_report_sha256": snapshot["sha256"],
        "evidence": snapshot["report"], "zero_day_confirmed": False,
    }
    response = current_app.response_class(json.dumps(payload, indent=2), mimetype="application/json")
    response.headers["Content-Disposition"] = 'attachment; filename="hunterqa-evidence.json"'
    return response


@bp.get("/capabilities")
def capabilities():
    from .engines.hypotheses import checklist
    return render_template("capabilities.html", categories=checklist())


@bp.get("/audit")
def audit_history():
    rows = get_db().execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 100").fetchall()
    return render_template("audit.html", events=rows)


@bp.get("/hypotheses")
def hypotheses():
    from pathlib import Path
    from .engines.hypothesis_report import read_hypotheses
    path = current_app.config.get("HYPOTHESES_REPORT_PATH") or (
        Path.home() / "ZeroScope-AI" / "research-lab" / "hypotheses.json"
    )
    return render_template("hypotheses.html", report=read_hypotheses(Path(path)))

@bp.get("/triage")
def triage_dashboard():
    from pathlib import Path
    from .engines.triage_view import read_triage_report
    from .engines.triage_review import decorate_records

    configured = current_app.config.get("TRIAGE_REPORT_PATH")

    report_path = configured or (
        Path.home()
        / "ZeroScope-AI"
        / "research-lab"
        / "verification"
        / "hunterqa_unified_triage.json"
    )

    report = decorate_records(read_triage_report(report_path), get_db())

    source = request.args.get("source", "all")
    status = request.args.get("status", "all")
    review = request.args.get("review", "all")

    valid_sources = set(report["by_source"])
    valid_statuses = set(report["by_status"])
    valid_review = set(report["by_review"])

    if source != "all" and source not in valid_sources:
        source = "all"

    if status != "all" and status not in valid_statuses:
        status = "all"

    if review != "all" and review not in valid_review:
        review = "all"

    visible = [
        finding
        for finding in report["findings"]
        if (source == "all" or finding["source"] == source)
        and (status == "all" or finding["status"] == status)
        and (review == "all" or finding["analyst_status"] == review)
    ]

    return render_template(
        "triage.html",
        report=report,
        findings=visible[:200],
        selected_source=source,
        selected_status=status,
        selected_review=review,
        truncated=len(visible) > 200,
    )

@bp.post("/triage/review/<record_id>")
def update_triage_review(record_id: str):
    """CSRF-protected local analyst decision; never modifies source evidence."""
    from pathlib import Path
    from .engines.triage_view import read_triage_report
    from .engines.triage_review import change_review

    require_csrf()
    if len(record_id) > 100:
        abort(404)

    path = current_app.config.get("TRIAGE_REPORT_PATH") or (
        Path.home() / "ZeroScope-AI" / "research-lab"
        / "verification" / "hunterqa_unified_triage.json"
    )
    report = read_triage_report(path)
    if report["status"] != "ready":
        abort(409, "Triage evidence is unavailable")

    candidates = [x for x in report["findings"] if x["id"] == record_id]
    if len(candidates) != 1:
        abort(404)

    try:
        change_review(
            get_db(), candidates[0],
            request.form.get("review_status", ""),
            request.form.get("note", ""),
        )
        flash("Review decision saved with audit history.", "success")
    except ValueError as error:
        flash(str(error), "error")
    return redirect(url_for("main.triage_dashboard"))


@bp.get("/campaigns")
def campaign_history():
    """Read-only view of administrator-approved local campaign artifacts."""
    from pathlib import Path
    from .engines.campaign_history import (
        read_campaign_history, compare_campaigns, public_history,
    )

    roots = current_app.config.get("APPROVED_ROOTS") or []
    if isinstance(roots, str):
        roots = roots.split(":")
    selected_root = current_app.config.get("CAMPAIGN_HISTORY_ROOT") or (
        Path.home() / "ZeroScope-AI" / "research-lab"
    )
    history = read_campaign_history(selected_root, roots)
    left = request.args.get("left", "")
    right = request.args.get("right", "")
    comparison = (
        compare_campaigns(history, left, right)
        if left and right else None
    )
    return render_template(
        "campaigns.html", history=public_history(history),
        comparison=comparison, selected_left=left, selected_right=right,
    )


@bp.get("/trends")
def campaign_trends_dashboard():
    """Read-only longitudinal summaries of local approved campaigns."""
    from pathlib import Path
    from .engines.campaign_history import read_campaign_history
    from .engines.campaign_trends import build_campaign_trends

    roots = current_app.config.get("APPROVED_ROOTS") or []
    selected_root = current_app.config.get("CAMPAIGN_HISTORY_ROOT") or (
        Path.home() / "ZeroScope-AI" / "research-lab"
    )
    history = read_campaign_history(selected_root, roots)
    trends = build_campaign_trends(history)
    return render_template("trends.html", trends=trends)


@bp.get("/analytics")
def research_analytics_dashboard():
    """Read-only evidence analytics and analyst history."""
    from pathlib import Path
    from .engines.triage_view import read_triage_report
    from .engines.triage_review import decorate_records
    from .engines.research_analytics import build_research_analytics

    report_path = current_app.config.get("TRIAGE_REPORT_PATH") or (
        Path.home() / "ZeroScope-AI" / "research-lab" /
        "verification" / "hunterqa_unified_triage.json"
    )
    report = decorate_records(read_triage_report(report_path), get_db())
    analytics = build_research_analytics(report, get_db())
    return render_template("analytics.html", analytics=analytics)


@bp.get("/cve-intelligence")
def cve_intelligence():
    """Read-only administrator-selected local CVE evidence; never browser file paths."""
    from pathlib import Path
    from .engines.cve_intel import read_cve_report
    filename = current_app.config.get("CVE_REPORT_PATH") or (
        Path.home() / "ZeroScope-AI" / "research-lab" /
        "verification" / "hunterqa_cve_intelligence.json"
    )
    return render_template("cve_intelligence.html", report=read_cve_report(filename))


@bp.get("/bounty")
def bounty_dashboard():
    """Read-only local authorized bounty assessment evidence; never scans on page load."""
    from .bounty import read_bounty_report, METHOD_CATALOG
    report = read_bounty_report(current_app.config.get("BOUNTY_REPORT_PATH"))
    return render_template("bounty.html", report=report, methods=METHOD_CATALOG)


@bp.get("/agent-lab")
def agent_lab_dashboard():
    """Administrator-selected local evidence only; no remote agent runs on GET."""
    from .agent_workflow_v12 import dashboard_summary, SKILLS
    summary = dashboard_summary(
        current_app.config.get("AGENT_PLAN_PATH"),
        current_app.config.get("API_SURFACE_REPORT_PATH"),
        current_app.config.get("AGENT_CORRELATION_REPORT_PATH"),
    )
    from .browser_lab_v12 import read_browser_summary
    from .replay_v12 import read_replay_summary
    browser = read_browser_summary(current_app.config.get("BROWSER_LAB_REPORT_PATH"))
    replay = read_replay_summary(current_app.config.get("HEAD_REPLAY_REPORT_PATH"))
    from .verification_v12 import read_review_summary
    review = read_review_summary(current_app.config.get("REVIEW_DOSSIER_PATH"))
    return render_template("agent_lab.html", summary=summary, skills=SKILLS,
                           browser=browser, replay=replay, review=review)
