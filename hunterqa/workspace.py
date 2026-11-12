"""Private per-process workspaces; application separation is not an OS sandbox."""
from __future__ import annotations

import json
import hashlib
import os
import re
import threading
from pathlib import Path

from . import operator_store as operators
from .bounty import _decode_json
from .doctor import _root_is_safe
from .engagement import digest
from .source_files import read_bounded

ID = re.compile(r"[a-z][a-z0-9-]{2,47}\Z")
REPORTS = ("SCENARIO_REPORT_PATH", "RESEARCH_REPORT_PATH", "TRIAGE_REPORT_PATH", "CVE_REPORT_PATH", "BOUNTY_REPORT_PATH",
    "AGENT_PLAN_PATH", "API_SURFACE_REPORT_PATH", "AGENT_CORRELATION_REPORT_PATH", "BROWSER_LAB_REPORT_PATH",
    "HEAD_REPLAY_REPORT_PATH", "REVIEW_DOSSIER_PATH", "BENCHMARK_REPORT_PATH", "ENGAGEMENT_REPORT_PATH",
    "ENGAGEMENT_BASELINE_PATH", "HYPOTHESES_REPORT_PATH", "FUZZ_STATS_PATH")
_ACTIVE = None
_LOCK = threading.RLock()


def _root(value):
    path = Path(value).expanduser()
    if (not _root_is_safe(path) or ".." in path.parts or path.drive.startswith("\\\\")
            or any((p / ".git").exists() for p in (path, *path.parents))):
        raise ValueError("Workspace requires an existing private absolute directory outside Git without symlinks")
    if os.name == "posix" and (path.stat().st_mode & 0o077 or path.stat().st_uid != os.geteuid()):
        raise ValueError("Workspace directory requires owner-only mode 0700")
    return path.resolve(strict=True)


def _registry():
    path = operators.control_root() / "workspace-registry.sqlite3"
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
    except FileExistsError:
        pass
    return path


def initialize(workspace_id, root, username, password, *, authorized=False):
    if _ACTIVE is not None:
        raise ValueError("Initialize additional workspaces in a separate administration process")
    if authorized is not True:
        raise PermissionError("Workspace initialization requires --authorized")
    if not isinstance(workspace_id, str) or not ID.fullmatch(workspace_id):
        raise ValueError("Workspace ID must be 3..48 lowercase ASCII letters, digits or hyphens")
    operators._name(username)
    if not isinstance(password, str) or not 14 <= len(password) <= 256 or "\x00" in password:
        raise ValueError("Use a password of 14..256 characters without NUL")
    root = _root(root)
    control = operators.control_root()
    if root.is_relative_to(control) or control.is_relative_to(root) or any(root.iterdir()):
        raise ValueError("Use an empty workspace outside the operator control directory")
    _registry()
    with operators.database(control / "workspace-registry.sqlite3", write=True) as db:
        db.execute("CREATE TABLE IF NOT EXISTS workspaces(id TEXT PRIMARY KEY, root TEXT UNIQUE NOT NULL)")
        rows = db.execute("SELECT id,root FROM workspaces").fetchall()
        if len(rows) >= 32 or any(workspace_id == r[0] or root.is_relative_to(Path(r[1])) or Path(r[1]).is_relative_to(root) for r in rows):
            raise ValueError("Workspace ID or directory overlaps an existing registration")
        private = control / workspace_id
        private.mkdir(mode=0o700)
        for name in ("state", "assessments"):
            (root / name).mkdir(mode=0o700)
        for name in ("evidence", "workflow", "history"):
            (root / "assessments" / name).mkdir(mode=0o700)
        # Existing ambient assessment roots must not affect this new identity store.
        operators.validate_separation([str(root / "assessments")])
        prior = os.environ.get("HUNTERQA_APPROVED_ROOTS")
        try:
            os.environ["HUNTERQA_APPROVED_ROOTS"] = str(root / "assessments")
            operators.initialize(private / "operators.sqlite3", username, password, authorized=True)
            with operators.database(private / "operators.sqlite3", write=True) as identities:
                identities.execute("CREATE TABLE operator_workspace(id INTEGER PRIMARY KEY CHECK(id=1), workspace_id TEXT NOT NULL)")
                identities.execute("INSERT INTO operator_workspace VALUES(1,?)", (workspace_id,))
        finally:
            if prior is None:
                os.environ.pop("HUNTERQA_APPROVED_ROOTS", None)
            else:
                os.environ["HUNTERQA_APPROVED_ROOTS"] = prior
        operators.create_session_key(private / "session.key", authorized=True)
        operators.create_session_key(private / "edge.key", authorized=True)
        config = {"schema_version": 1, "workspace_id": workspace_id, "root": str(root), "reports": {}, "oidc_config": None,
            "public_origin": None, "edge_key_file": None}
        path = private / "workspace.json"
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(config, indent=2) + "\n")
        db.execute("INSERT INTO workspaces VALUES (?,?)", (workspace_id, str(root)))
    return {"workspace_id": workspace_id, "config_file": str(path), "operator_database": str(private / "operators.sqlite3"),
        "secrets_displayed": False, "os_isolation_verified": False}


def _load(path):
    global _ACTIVE
    if not path:
        if _ACTIVE is not None:
            raise ValueError("A workspace process cannot fall back to legacy shared mode")
        return None
    config_path = operators._path(path)
    data = _decode_json(read_bounded(config_path, 32768))
    required = {"schema_version", "workspace_id", "root", "reports", "oidc_config"}
    if (not isinstance(data, dict) or not required <= set(data) or set(data) - required - {"public_origin", "edge_key_file", "auth_config"}
            or type(data["schema_version"]) is not int or data["schema_version"] != 1
            or not isinstance(data["workspace_id"], str) or not ID.fullmatch(data["workspace_id"])):
        raise ValueError("Invalid private workspace configuration")
    workspace_id, root = data["workspace_id"], _root(data["root"])
    private = operators.control_root() / workspace_id
    if config_path != private / "workspace.json":
        raise ValueError("Workspace configuration must stay in its own control directory")
    with operators.database(operators.control_root() / "workspace-registry.sqlite3") as db:
        row = db.execute("SELECT root FROM workspaces WHERE id=?", (workspace_id,)).fetchone()
        if row is None or Path(row[0]) != root:
            raise ValueError("Workspace directory differs from its private registration")
    for name in ("state", "assessments", "assessments/evidence", "assessments/workflow", "assessments/history"):
        _root(root / name)
    reports = data["reports"]
    if not isinstance(reports, dict) or set(reports) - set(REPORTS):
        raise ValueError("Invalid workspace evidence bindings")
    settings = {key: str(root / "assessments" / "evidence" / (key.lower() + ".json")) for key in REPORTS}
    for key, value in reports.items():
        candidate = Path(value)
        if not candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError("Workspace evidence must use absolute paths")
        parent = candidate if candidate.is_dir() else candidate.parent
        if not _root(parent).is_relative_to(root / "assessments") or candidate.is_symlink():
            raise ValueError("Workspace evidence must remain under its assessment root")
        settings[key] = str(candidate)
    identity = operators.status(private / "operators.sqlite3")["instance"]
    settings.update(WORKSPACE_ID=workspace_id, WORKSPACE_ROOT=str(root), WORKSPACE_IDENTITY=identity,
        WORKSPACE_CONFIG=str(config_path), DATABASE=str(root / "state" / "dashboard.sqlite3"),
        APPROVED_ROOTS=[str(root / "assessments")], OPERATOR_DATABASE=str(private / "operators.sqlite3"),
        SECRET_KEY=operators.read_session_key(private / "session.key"),
        WORKFLOW_RUN_PATH=str(root / "assessments" / "workflow"), CAMPAIGN_HISTORY_ROOT=str(root / "assessments" / "history"),
        LOCAL_AI_ENABLED=False, OIDC_CONFIG="", AUTH_CONFIG="", WORKSPACE_PUBLIC_ORIGIN=None, DEBUG=False)
    if data.get("auth_config") is not None:
        selected = operators._path(data["auth_config"])
        if selected.parent != private or data["oidc_config"] is not None:
            raise ValueError("Unified authentication policy must belong to this workspace and replace legacy OIDC")
        settings["AUTH_CONFIG"] = str(selected)
    if data["oidc_config"] is not None:
        selected = operators._path(data["oidc_config"])
        if selected.parent != private:
            raise ValueError("OIDC configuration must belong to this workspace")
        settings["OIDC_CONFIG"] = str(selected)
    if data.get("public_origin") is not None:
        from .trusted_edge import public_origin
        settings["WORKSPACE_PUBLIC_ORIGIN"] = public_origin(data["public_origin"])
        selected = operators._path(data.get("edge_key_file") or "")
        if selected.parent != private or not (settings["OIDC_CONFIG"] or settings["AUTH_CONFIG"]):
            raise ValueError("HTTPS edge requires this workspace's private key and OIDC configuration")
        settings.update(WORKSPACE_EDGE_KEY=operators.read_session_key(selected), SESSION_COOKIE_SECURE=True)
    elif data.get("edge_key_file") is not None:
        raise ValueError("Configure an edge key and HTTPS origin together")
    signature = digest({"config": data, "identity": identity, "session": hashlib.sha256(settings["SECRET_KEY"].encode()).hexdigest(),
        "edge": hashlib.sha256(settings.get("WORKSPACE_EDGE_KEY", "").encode()).hexdigest()})
    if _ACTIVE not in (None, signature):
        raise ValueError("Run each workspace in its own process; configuration cannot change in place")
    database = Path(settings["DATABASE"])
    if database.is_symlink():
        raise ValueError("Symlinked workspace database rejected")
    if not database.exists():
        fd = os.open(database, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
    if not database.is_file() or (os.name == "posix" and database.stat().st_mode & 0o077):
        raise ValueError("Workspace database must be private and regular")
    _ACTIVE = signature
    os.environ["HUNTERQA_APPROVED_ROOTS"] = str(root / "assessments")
    return settings


def load(path):
    with _LOCK:
        return _load(path)


def bind_database(app):
    from .db import get_db
    with app.app_context():
        with get_db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS dashboard_workspace(id INTEGER PRIMARY KEY CHECK(id=1), workspace_id TEXT NOT NULL, identity_instance TEXT NOT NULL)")
            row = db.execute("SELECT workspace_id,identity_instance FROM dashboard_workspace WHERE id=1").fetchone()
            expected = (app.config.get("WORKSPACE_ID"), app.config.get("WORKSPACE_IDENTITY"))
            if row:
                if tuple(row) != expected:
                    raise ValueError("Dashboard database belongs to a different workspace or identity store")
            elif expected[0]:
                tables = ("projects", "scans", "findings", "reports", "triage_reviews", "audit_events", "assessment_runs")
                # Table names come only from the fixed schema allowlist above.
                if any(db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] for table in tables):  # nosec B608
                    raise ValueError("Do not silently adopt populated legacy data into a workspace")
                db.execute("INSERT INTO dashboard_workspace VALUES(1,?,?)", expected)
