"""Actual separate app processes and adversarial workspace configuration controls."""
import json
import multiprocessing
import os
from pathlib import Path

import pytest

from hunterqa import create_app, operator_store, workspace
from hunterqa.db import connect
from hunterqa.scanner import ScanService

PASSWORD = "Owned-workspace-password-123!"


@pytest.fixture
def spaces(tmp_path, monkeypatch):
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    monkeypatch.setenv("HUNTERQA_OPERATOR_ROOT", str(control))
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    monkeypatch.delenv("HUNTERQA_WORKSPACE_CONFIG", raising=False)
    monkeypatch.delenv("HUNTERQA_OIDC_CONFIG", raising=False)
    monkeypatch.delenv("HUNTERQA_OPERATOR_SESSION_KEY_FILE", raising=False)
    monkeypatch.setattr(workspace, "_ACTIVE", None)
    monkeypatch.setattr(operator_store, "HASH_METHOD", "pbkdf2:sha256:1000")
    roots, configs = [], []
    for name in ("alpha", "bravo"):
        root = tmp_path / name
        root.mkdir(mode=0o700)
        result = workspace.initialize(name, root, "admin", PASSWORD, authorized=True)
        roots.append(root)
        configs.append(Path(result["config_file"]))
    return control, roots, configs


class Service:
    def __init__(self):
        self.submitted = []
    def submit(self, scan_id):
        self.submitted.append(scan_id)


def _login(client):
    client.get("/login")
    with client.session_transaction() as session:
        csrf = session["csrf_token"]
    return client.post("/login", data={"username": "admin", "password": PASSWORD, "csrf_token": csrf})


def _process_probe(config, other_root, foreign_session, result):
    try:
        from hunterqa.db import get_db
        from hunterqa.security import AUTHORIZATION_TEXT
        app = create_app({"WORKSPACE_CONFIG": config, "TESTING": True, "SCAN_SERVICE": Service()})
        client = app.test_client()
        if foreign_session:
            with client.session_transaction() as session:
                session.update(foreign_session)
            original = client.get("/api/scans/1/status").status_code
            with client.session_transaction() as session:
                session.update(foreign_session)
                session["operator_instance"] = app.config["WORKSPACE_IDENTITY"]
            changed = client.get("/api/scans/1/status").status_code
            result.put({"foreign_cookie": original, "foreign_token": changed})
            return
        assert _login(client).status_code == 302
        own = "private-" + app.config["WORKSPACE_ID"]
        with app.app_context():
            with get_db() as db:
                db.execute("INSERT INTO projects(id,name,path) VALUES(1,?,?)", (own, str(Path(app.config["APPROVED_ROOTS"][0]))))
                db.execute("INSERT INTO scans(id,project_id,status) VALUES(1,1,'completed')")
                db.execute("INSERT INTO findings(id,scan_id,rule_id,title,severity,cwe,file_path,line_start,line_end,message) VALUES(1,1,'owned',?,'INFO','CWE-0','owned.py',1,1,?)", (own, own))
                db.execute("INSERT INTO reports(scan_id,model,content) VALUES(1,'owned',?)", (own,))
        urls = ("/projects", "/scans/1", "/api/scans/1/status", "/findings/1", "/scans/1/report", "/scans/1/export.json",
            "/audit", "/research", "/api/research/evidence", "/api/research/export", "/triage", "/campaigns", "/trends",
            "/cve-intelligence", "/bounty", "/agent-lab", "/assessments", "/workflows", "/hypotheses", "/analytics")
        statuses, leaked = {}, False
        foreign_marker = "private-bravo" if own == "private-alpha" else "private-alpha"
        for url in urls:
            response = client.get(url)
            statuses[url] = response.status_code
            leaked |= foreign_marker.encode() in response.data
        with client.session_transaction() as session:
            session_data = dict(session)
            csrf = session["csrf_token"]
        client.post("/projects", data={"name": "foreign", "path": str(other_root), "csrf_token": csrf})
        client.post("/projects/1/scans", data={"csrf_token": csrf, "authorized": "yes", "authorization_text": AUTHORIZATION_TEXT})
        with app.app_context():
            rows = get_db().execute("SELECT name FROM projects ORDER BY id").fetchall()
        result.put({"workspace": app.config["WORKSPACE_ID"], "statuses": statuses, "leaked": leaked,
            "names": [r[0] for r in rows], "submitted": app.extensions["scan_service"].submitted,
            "session": session_data, "cookie_name": app.config["SESSION_COOKIE_NAME"]})
    except BaseException as exc:
        result.put({"error_type": type(exc).__name__, "message": str(exc)[:200]})


def _probe(config, other_root, foreign_session=None):
    context = multiprocessing.get_context("spawn")
    result = context.Queue()
    process = context.Process(target=_process_probe, args=(str(config), str(other_root), foreign_session, result))
    process.start()
    try:
        value = result.get(timeout=40)
        process.join(10)
        assert not process.is_alive() and process.exitcode == 0
        assert "error_type" not in value, value
        return value
    finally:
        if process.is_alive():
            process.terminate()
            process.join(5)
        result.close()


def test_distinct_process_databases_routes_workers_and_sessions_do_not_cross(spaces):
    _, roots, configs = spaces
    left = _probe(configs[0], roots[1] / "assessments")
    right = _probe(configs[1], roots[0] / "assessments")
    assert left["names"] == ["private-alpha"] and right["names"] == ["private-bravo"]
    assert left["submitted"] == right["submitted"] == [2]
    assert not left["leaked"] and not right["leaked"]
    assert all(status in (200, 404, 400) for status in left["statuses"].values()), left["statuses"]
    assert all(status in (200, 404, 400) for status in right["statuses"].values()), right["statuses"]
    assert left["cookie_name"] != right["cookie_name"]
    cross = _probe(configs[1], roots[0], left["session"])
    assert cross == {"foreign_cookie": 401, "foreign_token": 401}


def test_workspace_replaces_ambient_evidence_roots_secrets_and_disables_shared_ai(spaces, monkeypatch):
    _, roots, configs = spaces
    for key in workspace.REPORTS:
        monkeypatch.setenv("HUNTERQA_" + key.removesuffix("_PATH"), str(roots[1] / "private-bravo.json"))
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(roots[1]))
    app = create_app({"WORKSPACE_CONFIG": str(configs[0]), "TESTING": True, "SCAN_SERVICE": Service()})
    assert app.config["APPROVED_ROOTS"] == [str(roots[0] / "assessments")]
    assert os.environ["HUNTERQA_APPROVED_ROOTS"] == str(roots[0] / "assessments")
    assert all(Path(app.config[key]).is_relative_to(roots[0]) for key in workspace.REPORTS)
    monkeypatch.setattr("hunterqa.scanner.generate", lambda *a, **k: pytest.fail("Workspace data reached shared AI"))
    assert "Shared local AI is disabled" in ScanService(app)._create_report([])


def test_two_workspaces_or_legacy_fallback_in_one_process_rejected(spaces):
    _, _, configs = spaces
    create_app({"WORKSPACE_CONFIG": str(configs[0]), "TESTING": True, "SCAN_SERVICE": Service()})
    with pytest.raises(ValueError, match="own process"):
        create_app({"WORKSPACE_CONFIG": str(configs[1]), "TESTING": True})
    with pytest.raises(ValueError, match="legacy"):
        create_app({"TESTING": True})


@pytest.mark.parametrize("key,value", [("SECRET_KEY", "wrong"), ("DATABASE", "other.sqlite3"),
    ("APPROVED_ROOTS", ["other"]), ("OPERATOR_DATABASE", "other.sqlite3"), ("RESEARCH_REPORT_PATH", "other.json")])
def test_workspace_protected_configuration_cannot_be_overridden(spaces, key, value):
    with pytest.raises(ValueError, match="cannot be overridden"):
        create_app({"WORKSPACE_CONFIG": str(spaces[2][0]), "TESTING": True, key: value})


def test_populated_or_bound_database_cannot_silently_change_workspace(spaces, monkeypatch):
    _, roots, configs = spaces
    app = create_app({"WORKSPACE_CONFIG": str(configs[0]), "TESTING": True, "SCAN_SERVICE": Service()})
    with connect(app.config["DATABASE"]) as db:
        db.execute("UPDATE dashboard_workspace SET workspace_id='bravo'")
    monkeypatch.setattr(workspace, "_ACTIVE", None)
    with pytest.raises(ValueError, match="belongs to a different"):
        create_app({"WORKSPACE_CONFIG": str(configs[0]), "TESTING": True})
    # Removing a manifest cannot turn its database into an unauthenticated legacy app.
    monkeypatch.setattr(workspace, "_ACTIVE", None)
    with pytest.raises(ValueError, match="belongs to a different"):
        create_app({"TESTING": True, "DATABASE": str(roots[0] / "state/dashboard.sqlite3")})


def test_foreign_workspace_report_root_rejected(spaces):
    _, roots, configs = spaces
    data = json.loads(configs[0].read_text())
    data["reports"]["TRIAGE_REPORT_PATH"] = str(roots[1] / "assessments/evidence/private.json")
    configs[0].write_text(json.dumps(data))
    with pytest.raises(ValueError, match="assessment root"):
        workspace.load(configs[0])


def test_duplicate_and_nested_roots_not_registered(spaces, tmp_path):
    _, roots, _ = spaces
    extra = tmp_path / "empty"
    extra.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="overlaps"):
        workspace.initialize("alpha", extra, "admin", PASSWORD, authorized=True)
    nested = roots[0] / "assessments" / "nested"
    nested.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="overlaps"):
        workspace.initialize("nested", nested, "admin", PASSWORD, authorized=True)


def test_workspace_requires_authorization_and_empty_private_root(spaces, tmp_path):
    root = tmp_path / "kept"
    root.mkdir(mode=0o700)
    (root / "keep.txt").write_text("retain")
    with pytest.raises(PermissionError):
        workspace.initialize("new-space", root, "admin", PASSWORD)
    with pytest.raises(ValueError, match="empty"):
        workspace.initialize("new-space", root, "admin", PASSWORD, authorized=True)
    assert (root / "keep.txt").read_text() == "retain"


def test_invalid_administrator_input_does_not_create_workspace_files(spaces, tmp_path):
    root = tmp_path / "new-empty"
    root.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="password"):
        workspace.initialize("new-empty", root, "admin", "short", authorized=True)
    assert list(root.iterdir()) == [] and not (spaces[0] / "new-empty").exists()
