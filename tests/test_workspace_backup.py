"""Private recovery, rollback safety, archive adversaries and real CLI flows."""
from contextlib import closing, contextmanager
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import threading
import zipfile

import pytest

from hunterqa import create_app, operator_store as operators, workspace
from hunterqa import workspace_backup as recovery
from hunterqa.db import connect
from hunterqa.workspace_server import lease
from hunterqa.workspace_server import recover
from tests import test_workspaces as workspace_tests
from tests import test_workspace_edge as edge_tests

RECOVERED_PASSWORD = "Recovered-workspace-password-123!"


@contextmanager
def running_dashboard(app, port=0):
    from werkzeug.serving import make_server
    server = make_server("127.0.0.1", port, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)

@pytest.fixture
def prepared(tmp_path, monkeypatch):
    spaces = workspace_tests.spaces.__wrapped__(tmp_path, monkeypatch)
    app = create_app({"WORKSPACE_CONFIG": str(spaces[2][0]), "TESTING": True})
    root, private = spaces[1][0], spaces[0] / "alpha"
    evidence = root / "assessments" / "evidence" / "owned.json"
    evidence.write_text('{"owned":true}', encoding="utf-8")
    empty = root / "assessments" / "empty"
    empty.mkdir(mode=0o700)
    with closing(connect(app.config["DATABASE"])) as db, db:
        db.execute("INSERT INTO projects(id,name,path) VALUES(1,'retained',?)", (str(root / "assessments"),))
        db.execute("INSERT INTO scans(id,project_id,status) VALUES(1,1,'completed')")
        db.execute("INSERT INTO reports(scan_id,model,content) VALUES(1,'owned','retained review')")
    directory = tmp_path / "backups"
    directory.mkdir(mode=0o700)
    return spaces, app, root, private, directory / "private.zip"


def make_backup(prepared):
    spaces, _, _, _, archive = prepared
    result = recovery.backup(str(spaces[2][0]), archive, authorized=True)
    return result["sha256"]


def retire(prepared, monkeypatch):
    _, _, root, private, _ = prepared
    root.rename(root.with_name("alpha-retired"))
    root.mkdir(mode=0o700)
    private.rename(private.with_name("alpha-retired"))
    monkeypatch.setattr(workspace, "_ACTIVE", None)


def rewrite(prepared, mutate):
    archive = prepared[-1]
    with zipfile.ZipFile(archive) as stream:
        rows = {info.filename: stream.read(info) for info in stream.infolist()}
    mutate(rows)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as stream:
        for name, raw in rows.items():
            stream.writestr(name, raw)
    return hashlib.sha256(archive.read_bytes()).hexdigest()


def test_private_archive_round_trip_disables_accounts_and_rotates_keys(prepared, monkeypatch):
    spaces, app, root, private, archive = prepared
    identity = operators.status(private / "operators.sqlite3")["instance"]
    old_keys = {name: (private / name).read_bytes() for name in ("session.key", "edge.key")}
    user, status, instance, token = operators.authenticate(private / "operators.sqlite3", "admin", workspace_tests.PASSWORD, "127.0.0.1")
    assert status == "ok" and user and instance == identity
    sha = make_backup(prepared)
    assert recovery.check(archive, sha)["integrity_valid"]
    assert not recovery.check(archive, sha)["owner_authenticity_proven"]
    assert os.name != "posix" or archive.stat().st_mode & 0o077 == 0
    retire(prepared, monkeypatch)
    result = recovery.restore(archive, sha, "alpha", root, authorized=True)
    assert result["accounts_disabled"] and result["sessions_revoked"] and not result["production_ready"]
    with operators.database(private / "operators.sqlite3") as db:
        new_identity = db.execute("SELECT instance FROM identity").fetchone()[0]
        assert new_identity != identity
        assert db.execute("SELECT COUNT(*) FROM operators WHERE active=1").fetchone()[0] == 0
    with pytest.raises(ValueError, match="active administrator"):
        operators.status(private / "operators.sqlite3")
    assert operators.session_operator(private / "operators.sqlite3", token, instance) is None
    for name, old in old_keys.items():
        assert (private / name).read_bytes() != old
    assert (root / "assessments/evidence/owned.json").read_text() == '{"owned":true}'
    assert (root / "assessments/empty").is_dir()
    with pytest.raises(ValueError, match="different password"):
        operators.update_operator(private / "operators.sqlite3", "admin", active=True, authorized=True)
    with pytest.raises(ValueError, match="different password"):
        operators.update_operator(private / "operators.sqlite3", "admin", active=True, password=workspace_tests.PASSWORD, authorized=True)
    operators.update_operator(private / "operators.sqlite3", "admin", active=True, password=RECOVERED_PASSWORD, authorized=True)
    restored = operators.status(private / "operators.sqlite3")
    restored_app = create_app({"WORKSPACE_CONFIG": str(spaces[2][0]), "TESTING": True})
    client = restored_app.test_client()
    client.get("/login")
    with client.session_transaction() as session:
        csrf = session["csrf_token"]
    assert client.post("/login", data={"username": "admin", "password": RECOVERED_PASSWORD, "csrf_token": csrf}).status_code == 302
    with closing(connect(restored_app.config["DATABASE"])) as db:
        assert db.execute("SELECT content FROM reports").fetchone()[0] == "retained review"
        assert db.execute("SELECT identity_instance FROM dashboard_workspace").fetchone()[0] == restored["instance"]
    assert operators.audit_status(private / "operators.sqlite3")["events"] >= 4


def test_backup_refuses_a_running_supported_server(prepared):
    spaces, _, root, _, archive = prepared
    with lease(root), pytest.raises(RuntimeError, match="already served"):
        recovery.backup(str(spaces[2][0]), archive, authorized=True)
    assert not archive.exists()


def test_pending_work_must_be_resolved_before_offline_backup(prepared):
    spaces, app, _, _, archive = prepared
    with closing(connect(app.config["DATABASE"])) as db, db:
        db.execute("UPDATE scans SET status='running'")
    with pytest.raises(ValueError, match="interrupted"):
        recovery.backup(str(spaces[2][0]), archive, authorized=True)
    assert not archive.exists()


def test_offline_recovery_requires_authorization_and_supported_server_exclusion(prepared):
    spaces, app, root, _, _ = prepared
    config = str(spaces[2][0])
    with closing(connect(app.config["DATABASE"])) as db, db:
        db.execute("UPDATE scans SET status='running'")
    with pytest.raises(PermissionError):
        recover(config)
    with lease(root), pytest.raises(RuntimeError, match="already served"):
        recover(config, authorized=True)
    result = recover(config, authorized=True)
    assert result["scans_marked_failed"] == 1 and result["scans_replayed"] == result["network_requests"] == 0
    assert recover(config, authorized=True)["scans_marked_failed"] == 0
    assert make_backup(prepared)


def test_real_cli_recovery_unblocks_offline_backup(prepared):
    spaces, app, _, _, archive = prepared
    with closing(connect(app.config["DATABASE"])) as db, db:
        db.execute("UPDATE scans SET status='queued'")
    command = [sys.executable, "-m", "hunterqa"]
    recovered = subprocess.run(command + ["workspace-recover", "--config", str(spaces[2][0]), "--authorized"],
        capture_output=True, text=True, timeout=30, check=True)
    assert json.loads(recovered.stdout)["scans_marked_failed"] == 1
    copied = subprocess.run(command + ["workspace-backup", "--config", str(spaces[2][0]), "--out", str(archive), "--authorized"],
        capture_output=True, text=True, timeout=30, check=True)
    assert json.loads(copied.stdout)["integrity_valid"]


@pytest.mark.parametrize("operation", ["backup", "restore"])
def test_explicit_administration_authorization(prepared, operation):
    spaces, _, root, _, archive = prepared
    with pytest.raises(PermissionError):
        if operation == "backup":
            recovery.backup(str(spaces[2][0]), archive)
        else:
            recovery.restore(archive, "0" * 64, "alpha", root)


@pytest.mark.parametrize("kind", ["control", "data", "foreign-data", "relative", "existing"])
def test_backup_destination_separation_and_no_overwrite(prepared, kind):
    spaces, _, root, private, archive = prepared
    selected = {"control": private / "backup.zip", "data": root / "backup.zip",
        "foreign-data": spaces[1][1] / "backup.zip", "relative": Path("backup.zip"), "existing": archive}[kind]
    if kind == "existing":
        archive.write_bytes(b"keep")
    with pytest.raises((ValueError, FileExistsError)):
        recovery.backup(str(spaces[2][0]), selected, authorized=True)
    if kind == "existing":
        assert archive.read_bytes() == b"keep"


@pytest.mark.parametrize("digest", [None, "", "0" * 64, "A" * 64, "a" * 63])
def test_archive_requires_separately_retained_exact_digest(prepared, digest):
    make_backup(prepared)
    with pytest.raises(ValueError):
        recovery.check(prepared[-1], digest)


@pytest.mark.parametrize("name", ["../escape", "/absolute", "data/../escape", "data//escape", "data/x\\escape", "data/evil:ads", "data/CON", "data/con.txt", "data/trailing.", "data/nul\x00bad", "control/../../escape", "alien/file"])
def test_unsafe_archive_paths_are_rejected(name):
    with pytest.raises(ValueError):
        recovery._name(name)


@pytest.mark.parametrize("kind", ["digest", "unlisted", "missing", "directory-case", "file-case", "control-extra", "workspace-id"])
def test_manifest_and_member_adversaries(prepared, kind):
    make_backup(prepared)

    def mutate(rows):
        manifest = json.loads(rows["manifest.json"])
        if kind == "digest":
            rows["data/assessments/evidence/owned.json"] = b"changed"
        elif kind == "unlisted":
            rows["data/assessments/extra"] = b"extra"
        elif kind == "missing":
            rows.pop("control/session.key")
        elif kind == "directory-case":
            manifest["directories"].append("data/ASSESSMENTS")
        elif kind == "file-case":
            rows["CONTROL/session.key"] = b"extra"
        elif kind == "control-extra":
            raw = b"not configured"
            rows["control/extra.secret"] = raw
            manifest["files"].append({"name": "control/extra.secret", "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        else:
            manifest["workspace_id"] = "bravo"
        rows["manifest.json"] = json.dumps(manifest).encode()

    sha = rewrite(prepared, mutate)
    with pytest.raises(ValueError):
        recovery.check(prepared[-1], sha)


@pytest.mark.parametrize("kind", ["compressed", "symlink", "duplicate", "oversize"])
def test_zip_transport_adversaries(prepared, kind, monkeypatch):
    make_backup(prepared)
    archive = prepared[-1]
    if kind == "oversize":
        monkeypatch.setattr(recovery, "MAX_FILE", 1)
    else:
        with zipfile.ZipFile(archive) as source:
            rows = [(i.filename, source.read(i)) for i in source.infolist()]
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED if kind == "compressed" else zipfile.ZIP_STORED) as target:
            for name, raw in rows:
                if kind == "symlink" and name == "control/session.key":
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    target.writestr(info, raw)
                else:
                    target.writestr(name, raw)
            if kind == "duplicate":
                with pytest.warns(UserWarning):
                    target.writestr(rows[0][0], rows[0][1])
    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    with pytest.raises(ValueError):
        recovery.check(archive, sha)


@pytest.mark.parametrize("kind", ["wrong-id", "wrong-root", "existing-control", "nonempty-root", "selected-process"])
def test_restore_does_not_overwrite_or_relocate(prepared, monkeypatch, kind):
    sha = make_backup(prepared)
    _, _, root, private, archive = prepared
    if kind != "selected-process":
        retire(prepared, monkeypatch)
    if kind == "existing-control":
        private.mkdir(mode=0o700)
        (private / "keep").write_text("keep")
    if kind == "nonempty-root":
        (root / "keep").write_text("keep")
    selected = root
    if kind == "wrong-root":
        selected = root.with_name("different")
        selected.mkdir(mode=0o700)
    with pytest.raises(ValueError):
        recovery.restore(archive, sha, "bravo" if kind == "wrong-id" else "alpha", selected, authorized=True)
    if kind in ("existing-control", "nonempty-root"):
        assert ((private if kind == "existing-control" else root) / "keep").read_text() == "keep"


def test_bad_sqlite_content_fails_before_publication(prepared, monkeypatch):
    make_backup(prepared)

    def mutate(rows):
        name, raw = "data/state/dashboard.sqlite3", b"not sqlite"
        rows[name] = raw
        manifest = json.loads(rows["manifest.json"])
        for row in manifest["files"]:
            if row["name"] == name:
                row.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        rows["manifest.json"] = json.dumps(manifest).encode()

    sha = rewrite(prepared, mutate)
    retire(prepared, monkeypatch)
    _, _, root, private, archive = prepared
    with pytest.raises(sqlite3.DatabaseError):
        recovery.restore(archive, sha, "alpha", root, authorized=True)
    assert not private.exists() and not list(root.iterdir())


@pytest.mark.parametrize("kind", ["identity-trigger", "dashboard-trigger", "view"])
@pytest.mark.parametrize("phase", ["backup", "restore"])
def test_active_database_schema_is_rejected_before_restore_publication(prepared, monkeypatch, tmp_path, kind, phase):
    make_backup(prepared)
    sql = {"identity-trigger": "CREATE TRIGGER revive AFTER UPDATE ON operators BEGIN UPDATE operators SET active=1; END",
        "dashboard-trigger": "CREATE TRIGGER revive AFTER UPDATE ON dashboard_workspace BEGIN UPDATE scans SET status='queued'; END",
        "view": "CREATE VIEW unexpected AS SELECT * FROM scans"}[kind]
    if phase == "backup":
        spaces, app, _, private, archive = prepared
        source = private / "operators.sqlite3" if kind == "identity-trigger" else Path(app.config["DATABASE"])
        with closing(sqlite3.connect(source)) as db, db:
            db.execute(sql)
        output = archive.with_name("rejected.zip")
        with pytest.raises(ValueError, match="triggers or views"):
            recovery.backup(str(spaces[2][0]), output, authorized=True)
        assert not output.exists()
        return

    def mutate(rows):
        name = "control/operators.sqlite3" if kind == "identity-trigger" else "data/state/dashboard.sqlite3"
        altered = tmp_path / "altered.sqlite3"
        altered.write_bytes(rows[name])
        with closing(sqlite3.connect(altered)) as db, db:
            db.execute(sql)
        raw = altered.read_bytes()
        rows[name] = raw
        manifest = json.loads(rows["manifest.json"])
        for row in manifest["files"]:
            if row["name"] == name:
                row.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        rows["manifest.json"] = json.dumps(manifest).encode()

    sha = rewrite(prepared, mutate)
    retire(prepared, monkeypatch)
    _, _, root, private, archive = prepared
    with pytest.raises(ValueError, match="triggers or views"):
        recovery.restore(archive, sha, "alpha", root, authorized=True)
    assert not private.exists() and not list(root.iterdir())


def test_real_cli_backup_check_restore_and_reenable(prepared, monkeypatch):
    spaces, _, root, private, archive = prepared
    command = [sys.executable, "-m", "hunterqa"]

    def run(*args):
        env = dict(os.environ, HUNTERQA_OPERATOR_PASSWORD=RECOVERED_PASSWORD) if args[0] == "operator-update" else dict(os.environ)
        output = subprocess.run(command + list(map(str, args)), capture_output=True, text=True, check=True, timeout=30, env=env)
        assert workspace_tests.PASSWORD not in output.stdout
        assert RECOVERED_PASSWORD not in output.stdout
        return json.loads(output.stdout)

    result = run("workspace-backup", "--config", spaces[2][0], "--out", archive, "--authorized")
    assert run("workspace-backup-check", "--backup", archive, "--sha256", result["sha256"])["integrity_valid"]
    retire(prepared, monkeypatch)
    restored = run("workspace-restore", "--backup", archive, "--sha256", result["sha256"], "--workspace-id", "alpha", "--root", root, "--authorized")
    assert restored["accounts_disabled"]
    blocked = subprocess.run(command + ["workspace-check", "--config", str(spaces[2][0])], capture_output=True, text=True, timeout=30)
    assert blocked.returncode != 0 and "active administrator" in blocked.stderr
    run("operator-update", "--database", private / "operators.sqlite3", "--username", "admin", "--enable", "--reset-password", "--authorized")
    assert run("workspace-check", "--config", spaces[2][0])["startup_configuration_valid"]


@pytest.mark.parametrize("kind", ["modified", "added", "directory"])
def test_changed_evidence_cannot_produce_a_valid_backup(prepared, monkeypatch, kind):
    spaces, _, root, _, archive = prepared
    original = zipfile.ZipFile.writestr
    changed = False

    def altering(stream, name, raw, *args, **kwargs):
        nonlocal changed
        result = original(stream, name, raw, *args, **kwargs)
        if not changed and name == "data/assessments/evidence/owned.json":
            changed = True
            if kind == "modified":
                (root / "assessments/evidence/owned.json").write_text("modified")
            elif kind == "added":
                (root / "assessments/evidence/added.json").write_text("added")
            else:
                (root / "assessments/added").mkdir(mode=0o700)
        return result

    monkeypatch.setattr(zipfile.ZipFile, "writestr", altering)
    with pytest.raises(ValueError, match="changed"):
        recovery.backup(str(spaces[2][0]), archive, authorized=True)
    assert changed
    with pytest.raises(ValueError, match="manifest missing"):
        recovery.check(archive, hashlib.sha256(archive.read_bytes()).hexdigest())


def test_hardlinked_evidence_is_not_followed(prepared):
    spaces, _, root, _, archive = prepared
    original = root / "assessments/evidence/owned.json"
    os.link(original, original.with_name("linked.json"))
    with pytest.raises(ValueError, match="without links"):
        recovery.backup(str(spaces[2][0]), archive, authorized=True)
    assert not archive.exists()


def test_wal_commits_are_snapshotted_without_copying_sidecars(prepared, tmp_path):
    _, app, _, _, archive = prepared
    with closing(connect(app.config["DATABASE"])) as writer:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        writer.execute("UPDATE reports SET content='committed in WAL'")
        writer.commit()
        make_backup(prepared)
    with zipfile.ZipFile(archive) as source:
        assert not any(name.endswith(("-wal", "-shm", "-journal")) for name in source.namelist())
        copy = tmp_path / "owned-snapshot.sqlite3"
        copy.write_bytes(source.read("data/state/dashboard.sqlite3"))
    with closing(connect(str(copy))) as db:
        assert db.execute("SELECT content FROM reports").fetchone()[0] == "committed in WAL"
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_recovery_keeps_oidc_dependencies_but_clears_attempts_and_rotates_custom_edge(prepared, monkeypatch):
    spaces, _, root, private, archive = prepared
    config, _ = edge_tests.configured(spaces)
    custom = private / "custom-edge.key"
    operators.create_session_key(custom, authorized=True)
    data = json.loads(config.read_text())
    data["edge_key_file"] = str(custom)
    config.write_text(json.dumps(data))
    monkeypatch.setattr(workspace, "_ACTIVE", None)
    app = create_app({"WORKSPACE_CONFIG": str(config), "TESTING": True})
    client = app.test_client()
    key = custom.read_text().strip()
    origin, headers = "https://alpha.example.test", edge_tests.headers(key)
    client.get("/login", base_url=origin, headers=headers)
    with client.session_transaction(base_url=origin) as session:
        csrf = session["csrf_token"]
    assert client.post("/oidc/start", base_url=origin, headers=headers, data={"csrf_token": csrf}).status_code == 302
    oidc_secret = (private / "client.secret").read_bytes()
    with operators.database(private / "operators.sqlite3") as db:
        assert db.execute("SELECT COUNT(*) FROM operator_oidc_attempts").fetchone()[0] == 1
    sha = make_backup(prepared)
    retire(prepared, monkeypatch)
    recovery.restore(archive, sha, "alpha", root, authorized=True)
    assert custom.read_text().strip() != key
    assert (private / "client.secret").read_bytes() == oidc_secret
    assert json.loads(config.read_text()) == data
    with operators.database(private / "operators.sqlite3") as db:
        assert db.execute("SELECT COUNT(*) FROM operator_oidc_attempts").fetchone()[0] == 0
    operators.update_operator(private / "operators.sqlite3", "admin", active=True, password=RECOVERED_PASSWORD, authorized=True)
    restored = create_app({"WORKSPACE_CONFIG": str(config), "TESTING": True})
    assert restored.test_client().get("/login", base_url=origin, headers=headers).status_code == 403
    assert restored.test_client().get("/login", base_url=origin, headers=edge_tests.headers(custom.read_text().strip())).status_code == 200


@pytest.mark.parametrize("kind", ["entry-count", "directory-size", "trailing-bytes"])
def test_zip_directory_preflight_rejects_allocation_abuse(prepared, kind):
    import struct
    make_backup(prepared)
    archive = prepared[-1]
    raw = bytearray(archive.read_bytes())
    offset = raw.rfind(b"PK\x05\x06")
    if kind == "entry-count":
        struct.pack_into("<HH", raw, offset + 8, 65535, 65535)
    elif kind == "directory-size":
        struct.pack_into("<I", raw, offset + 12, 200_000_000)
    else:
        raw.extend(b"unlisted trailing data")
    archive.write_bytes(raw)
    with pytest.raises(ValueError, match="ZIP directory"):
        recovery.check(archive, hashlib.sha256(raw).hexdigest())


@pytest.mark.skipif(os.environ.get("HUNTERQA_ENGAGEMENT_BROWSER_CI") != "1", reason="Opt-in owned Chromium recovery flow")
def test_restored_workspace_rejects_old_browser_session_and_allows_reviewed_admin(prepared, monkeypatch):
    pytest.importorskip("playwright.sync_api")
    from playwright.sync_api import sync_playwright, expect
    spaces, app, root, private, archive = prepared
    sha = make_backup(prepared)
    with sync_playwright() as driver:
        browser = driver.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={"width": 390, "height": 844})
            with running_dashboard(app) as (base, port):
                page.goto(base + "/projects")
                page.get_by_label("Username", exact=True).fill("admin")
                page.get_by_label("Password", exact=True).fill(workspace_tests.PASSWORD)
                page.get_by_role("button", name="Sign in", exact=True).click()
                page.goto(base + "/projects")
                expect(page.get_by_role("heading", name="retained", exact=True)).to_be_visible()
            retire(prepared, monkeypatch)
            recovery.restore(archive, sha, "alpha", root, authorized=True)
            operators.update_operator(private / "operators.sqlite3", "admin", active=True, password=RECOVERED_PASSWORD, authorized=True)
            restored = create_app({"WORKSPACE_CONFIG": str(spaces[2][0]), "TESTING": True})
            with running_dashboard(restored, port) as (base, _):
                # Same browser and host retain the old signed session across recovery.
                page.goto(base + "/projects")
                expect(page.get_by_role("heading", name="Sign in to HunterQA")).to_be_visible()
                assert page.request.get(base + "/api/scans/1").status == 401
                page.get_by_label("Username", exact=True).fill("admin")
                page.get_by_label("Password", exact=True).fill(RECOVERED_PASSWORD)
                page.get_by_role("button", name="Sign in", exact=True).click()
                page.goto(base + "/scans/1")
                page.get_by_role("link", name="Read AI report", exact=True).click()
                expect(page.get_by_text("retained review", exact=False)).to_be_visible()
                assert page.locator("body").evaluate("el => el.scrollWidth <= window.innerWidth")
                page.get_by_role("button", name="Sign out", exact=True).click()
                expect(page.get_by_role("heading", name="Sign in to HunterQA")).to_be_visible()
        finally:
            browser.close()
