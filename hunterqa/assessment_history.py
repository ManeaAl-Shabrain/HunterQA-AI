"""Completed CLI assessment evidence in the existing workspace/project database."""
from contextlib import closing
import hashlib
from pathlib import Path

from .bounty import _approved_file
from .db import connect
from .source_files import read_bounded


def prepare(config, output, project_id=None):
    from . import create_app
    app = create_app({"WORKSPACE_CONFIG": str(config)})
    root = Path(app.config["WORKSPACE_ROOT"]) / "assessments"
    output = Path(output).expanduser()
    if not output.is_absolute() or ".." in output.parts or not output.parent.resolve(strict=True).is_relative_to(root):
        raise ValueError("Workspace reports must remain under its assessment root")
    if output.exists() or output.is_symlink():
        raise FileExistsError("Choose a new report output")
    if project_id is not None:
        with closing(connect(app.config["DATABASE"])) as db:
            if type(project_id) is not int or not 1 <= project_id < 2**63 or not db.execute("SELECT id FROM projects WHERE id=?", (project_id,)).fetchone():
                raise ValueError("Select a project belonging to this workspace")
    return {"database": app.config["DATABASE"], "operator_database": app.config["OPERATOR_DATABASE"], "workspace_id": app.config["WORKSPACE_ID"],
        "root": str(root), "project_id": project_id}


def record(binding, output, report):
    from .operator_store import audit_event
    path = _approved_file(output)
    if not path.resolve().is_relative_to(Path(binding["root"])):
        raise ValueError("Report escaped the workspace")
    digest = hashlib.sha256(read_bounded(path, 1048576)).hexdigest()
    status = "stopped" if report.get("stopped") else "recorded"
    kind = report["engine"]
    if kind == "unified-assessment-review":
        from .assessment_modes import load_report
        checked = load_report(path)
        kind += ":" + checked["execution_source"] + ":" + checked["module"]
    audit_event(binding["operator_database"], "os-admin-recorded-assessment", binding["workspace_id"])
    with closing(connect(binding["database"])) as db, db:
        cursor = db.execute("INSERT INTO assessment_runs(project_id,kind,status,report_file,report_sha256,approval_sha256) VALUES(?,?,?,?,?,?)",
            (binding["project_id"], kind, status, str(path), digest, report.get("approval_sha256")))
    return cursor.lastrowid


def history(database):
    with closing(connect(database)) as db:
        return [dict(row) for row in db.execute("SELECT r.id,r.kind,r.status,r.created_at,r.report_sha256,p.name AS project_name FROM assessment_runs r LEFT JOIN projects p ON r.project_id=p.id ORDER BY r.id DESC LIMIT 100")]


def report_file(database, run_id):
    with closing(connect(database)) as db:
        row = db.execute("SELECT report_file,report_sha256 FROM assessment_runs WHERE id=?", (run_id,)).fetchone()
    if row is None:
        raise ValueError("Saved assessment unavailable")
    path = _approved_file(row["report_file"])
    if hashlib.sha256(read_bounded(path, 1048576)).hexdigest() != row["report_sha256"]:
        raise ValueError("Recorded report changed")
    return path


def saved(database, run_id):
    from .scenario_reports import summary
    try:
        return summary(report_file(database, run_id))
    except (ValueError, OSError):
        return {"status": "unavailable", "rows": [], "engine": None}
