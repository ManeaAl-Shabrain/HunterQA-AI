"""Bounded offline workspace recovery. The private backup custodian is trusted."""
from __future__ import annotations

from contextlib import closing, contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import sqlite3
import stat
import struct
import tempfile
import time
import uuid
import zipfile

from . import operator_store as operators, workspace
from .bounty import _decode_json
from .engagement import utcnow
from .source_files import read_bounded
from .workspace_server import lease, recover_interrupted

MAX_FILES = 2000
MAX_FILE = 64_000_000
MAX_TOTAL = 256_000_000
MAX_MANIFEST = 1_000_000
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
REQUIRED_DIRS = {"data/state", "data/assessments", "data/assessments/evidence", "data/assessments/workflow", "data/assessments/history", "control"}
REQUIRED_FILES = {"data/state/dashboard.sqlite3", "control/operators.sqlite3", "control/workspace.json", "control/session.key", "control/edge.key"}
CONTROL_FILES = {"operators.sqlite3", "workspace.json", "session.key", "edge.key"}


def _name(value):
    if not isinstance(value, str) or len(value.encode("utf-8")) > 1024:
        raise ValueError("Invalid backup member name")
    path = PurePosixPath(value)
    if (path.as_posix() != value or path.is_absolute() or not path.parts or path.parts[0] not in {"data", "control"}
            or any(p in (".", "..") or p.endswith((".", " ")) or len(p) > 240
                or p.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10))}
                for p in path.parts)
            or any(ord(c) < 32 or ord(c) == 127 or c in '\\:<>"|?*' for c in value)):
        raise ValueError("Unsafe backup member name")
    return value


def _regular(path):
    info = path.stat(follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or getattr(info, "st_file_attributes", 0) & 0x400):
        raise ValueError("Backup accepts regular files without links or reparse points")
    if os.name == "posix" and info.st_uid != os.geteuid():
        raise ValueError("Backup file must belong to this OS account")
    return info


def _external(value, *, existing):
    path = Path(value).expanduser()
    if not path.is_absolute() or ".." in path.parts or not path.name:
        raise ValueError("Use an absolute backup path in a private directory")
    parent = workspace._root(path.parent)
    selected = parent / path.name
    control = operators.control_root()
    if selected.is_relative_to(control):
        raise ValueError("Keep backups outside the operator control root")
    registry = control / "workspace-registry.sqlite3"
    if registry.exists():
        with operators.database(registry) as db:
            for row in db.execute("SELECT root FROM workspaces"):
                if selected.is_relative_to(Path(row[0])):
                    raise ValueError("Keep backups outside every registered workspace")
    if existing:
        info = _regular(selected)
        if info.st_size > MAX_TOTAL + MAX_MANIFEST + 2_000_000 or (os.name == "posix" and info.st_mode & 0o077):
            raise ValueError("Backup must be bounded and owner-private")
    elif selected.exists() or selected.is_symlink():
        raise FileExistsError("Choose a new backup filename")
    return selected


def _walk(root, prefix):
    directories, files, seen = {prefix}, [], set()
    for base, dirs, names in os.walk(root, followlinks=False):
        for name in sorted(dirs + names):
            path = Path(base) / name
            relative = _name(prefix + "/" + path.relative_to(root).as_posix())
            key = relative.casefold()
            if key in seen or len(seen) >= MAX_FILES:
                raise ValueError("Backup path collision or entry limit exceeded")
            seen.add(key)
            info = path.stat(follow_symlinks=False)
            if path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("Linked backup directory rejected")
            if stat.S_ISDIR(info.st_mode):
                directories.add(relative)
            else:
                _regular(path)
                files.append((relative, path))
    return directories, files


def _signature(path):
    info = _regular(path)
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _snapshot(source, destination):
    _write(destination, b"")
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True, timeout=5)) as incoming:
        page_size = incoming.execute("PRAGMA page_size").fetchone()[0]
        if incoming.execute("PRAGMA page_count").fetchone()[0] * page_size > MAX_FILE:
            raise ValueError("Database snapshot exceeds the backup file limit")
        end = time.monotonic() + 10

        def bounded(status, remaining, total):
            if total * page_size > MAX_FILE or time.monotonic() >= end:
                raise ValueError("Database snapshot size or time limit exceeded")

        with closing(sqlite3.connect(destination)) as outgoing:
            incoming.backup(outgoing, pages=256, progress=bounded, sleep=0.05)
            if outgoing.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ValueError("Database snapshot failed integrity checking")


def _control_names(config, private):
    selected = set(CONTROL_FILES)
    if config.get("edge_key_file") is not None:
        selected.add(operators._path(config["edge_key_file"]).name)
    if config["oidc_config"] is not None:
        from .operator_oidc import load_config
        oidc = operators._path(config["oidc_config"])
        if oidc.parent != private:
            raise ValueError("OIDC configuration belongs to another workspace")
        data, _, _ = load_config(oidc)
        selected.add(oidc.name)
        if data["client_secret_file"] is not None:
            selected.add(operators._path(data["client_secret_file"]).name)
    return selected


def backup(config, output, *, authorized=False):
    if authorized is not True:
        raise PermissionError("Workspace backup requires --authorized")
    settings = workspace.load(config)
    root, private = Path(settings["WORKSPACE_ROOT"]), Path(config).parent
    output = _external(output, existing=False)
    with lease(root):
        from . import create_app
        app = create_app({"WORKSPACE_CONFIG": str(config)})
        data = _decode_json(read_bounded(Path(config), 32768))
        names = _control_names(data, private)
        with operators.database(private / "operators.sqlite3", write=True):
            with closing(sqlite3.connect(settings["DATABASE"], timeout=5)) as db:
                db.execute("BEGIN IMMEDIATE")
                if db.execute("SELECT COUNT(*) FROM scans WHERE status IN ('queued','running')").fetchone()[0]:
                    raise ValueError("Resolve interrupted scans before creating an offline backup")
                if app.config["WORKSPACE_IDENTITY"] != db.execute("SELECT identity_instance FROM dashboard_workspace WHERE id=1").fetchone()[0]:
                    raise ValueError("Workspace identity binding differs")
                directories, entries = _walk(root, "data")
                directories.add("control")
                excluded = {"data/state/server.lock", *(f"data/state/dashboard.sqlite3{s}" for s in ("-wal", "-shm", "-journal"))}
                entries = [(name, path) for name, path in entries if name not in excluded]
                entries += [("control/" + name, private / name) for name in sorted(names)]
                before = {name: _signature(path) for name, path in entries}
                if any(row[2] > MAX_FILE for row in before.values()) or sum(row[2] for row in before.values()) > MAX_TOTAL:
                    raise ValueError("Workspace files exceed backup bounds")
                with tempfile.TemporaryDirectory(prefix="backup-stage-", dir=operators.control_root()) as temporary:
                    stage = Path(temporary)
                    snapshots = {"data/state/dashboard.sqlite3": stage / "dashboard.sqlite3", "control/operators.sqlite3": stage / "operators.sqlite3"}
                    for member, destination in snapshots.items():
                        _snapshot(dict(entries)[member], destination)
                    manifest = {"schema_version": 1, "kind": "hunterqa-private-workspace-backup", "created_at": utcnow().isoformat(),
                        "workspace_id": settings["WORKSPACE_ID"], "root": str(root), "control": str(private),
                        "identity": settings["WORKSPACE_IDENTITY"], "directories": sorted(directories), "files": []}
                    fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
                    total = 0
                    with os.fdopen(fd, "wb") as stream:
                        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
                            for name, original in sorted(entries):
                                name = _name(name)
                                raw = read_bounded(snapshots.get(name, original), MAX_FILE)
                                total += len(raw)
                                if total > MAX_TOTAL or len(manifest["files"]) >= MAX_FILES:
                                    raise ValueError("Workspace backup size or file limit exceeded")
                                archive.writestr(name, raw)
                                manifest["files"].append({"name": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
                            if before != {name: _signature(path) for name, path in entries} or _walk(root, "data")[0] != directories - {"control"}:
                                raise ValueError("Workspace changed during backup; do not use this archive")
                            current = {name for name, _ in _walk(root, "data")[1] if name not in excluded}
                            if current != {name for name, _ in entries if name.startswith("data/")}:
                                raise ValueError("Workspace contents changed during backup")
                            raw_manifest = json.dumps(manifest, sort_keys=True).encode("utf-8")
                            if len(raw_manifest) > MAX_MANIFEST:
                                raise ValueError("Backup manifest exceeds its size limit")
                            archive.writestr("manifest.json", raw_manifest)
                        stream.flush()
                        os.fsync(stream.fileno())
    result = check(output, _digest(output))
    result.update(backup_file=str(output), contains_private_secrets=True, encrypted=False, offline_snapshot=True,
        writer_quiescence_required=True)
    return result


def _digest(path):
    with path.open("rb") as stream:
        return _stream_digest(stream)


def _stream_digest(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1_048_576), b""):
        digest.update(chunk)
    return digest.hexdigest()


@contextmanager
def _verified(backup_file, sha256):
    if not isinstance(sha256, str) or not SHA256.fullmatch(sha256):
        raise ValueError("Supply the separately retained lowercase archive SHA-256")
    path = _external(backup_file, existing=True)
    # Hash and parse the same open file, rather than reopening a checked path.
    with path.open("rb") as stream:
        if _stream_digest(stream) != sha256:
            raise ValueError("Archive SHA-256 differs")
        _preflight_zip(stream)
        stream.seek(0)
        with zipfile.ZipFile(stream) as archive:
            yield archive, _inspect(archive)


def _preflight_zip(stream):
    """Bound the directory before ZipFile allocates one object per entry."""
    end = stream.seek(0, os.SEEK_END)
    stream.seek(max(0, end - 65557))
    tail = stream.read(65557)
    offset = tail.rfind(b"PK\x05\x06")
    if offset < 0 or len(tail) - offset < 22:
        raise ValueError("Backup ZIP directory is missing")
    _, disk, start_disk, disk_count, count, size, start, comment = struct.unpack("<4s4H2IH", tail[offset:offset + 22])
    if (disk or start_disk or disk_count != count or not 1 <= count <= MAX_FILES + 1
            or size > (MAX_FILES + 1) * 2048 or len(tail) - offset != 22 + comment
            or start + size != end - len(tail) + offset):
        raise ValueError("Unsupported or oversized ZIP directory")


def _inspect(archive):
    infos = archive.infolist()
    if not 1 <= len(infos) <= MAX_FILES + 1:
        raise ValueError("Backup entry count outside bounds")
    members, folded, total = {}, set(), 0
    for info in infos:
        if info.filename != "manifest.json":
            _name(info.filename)
        limit = MAX_MANIFEST if info.filename == "manifest.json" else MAX_FILE
        if (info.filename in members or info.filename.casefold() in folded or info.is_dir() or info.file_size > limit
                or info.compress_type != zipfile.ZIP_STORED or info.flag_bits & 1
                or stat.S_IFMT(info.external_attr >> 16) not in (0, stat.S_IFREG)):
            raise ValueError("Unsafe, duplicate, compressed or oversized backup member")
        members[info.filename] = info
        folded.add(info.filename.casefold())
        total += info.file_size
    if total > MAX_TOTAL + MAX_MANIFEST or "manifest.json" not in members:
        raise ValueError("Backup size exceeded or manifest missing")
    manifest = _decode_json(archive.read("manifest.json"))
    fields = {"schema_version", "kind", "created_at", "workspace_id", "root", "control", "identity", "directories", "files"}
    if (not isinstance(manifest, dict) or set(manifest) != fields or type(manifest["schema_version"]) is not int
            or manifest["schema_version"] != 1 or manifest["kind"] != "hunterqa-private-workspace-backup"
            or not isinstance(manifest["workspace_id"], str) or not workspace.ID.fullmatch(manifest["workspace_id"])
            or not all(isinstance(manifest[k], str) and 1 <= len(manifest[k]) <= 4096 for k in ("root", "control", "identity", "created_at"))
            or not isinstance(manifest["files"], list) or not isinstance(manifest["directories"], list)
            or len(manifest["directories"]) > MAX_FILES or len(manifest["files"]) > MAX_FILES
            or not re.fullmatch(r"[a-f0-9]{32}", manifest["identity"])
            or any(not Path(manifest[k]).is_absolute() or ".." in Path(manifest[k]).parts for k in ("root", "control"))):
        raise ValueError("Invalid workspace backup manifest")
    directories = set()
    for name in manifest["directories"]:
        _name(name)
        if name in directories or name in members or name.casefold() in folded:
            raise ValueError("Backup directory collision")
        directories.add(name)
        folded.add(name.casefold())
    if not REQUIRED_DIRS <= directories or "data" not in directories:
        raise ValueError("Required workspace directories missing")
    expected = set()
    for row in manifest["files"]:
        if not isinstance(row, dict) or set(row) != {"name", "size", "sha256"}:
            raise ValueError("Invalid backup file declaration")
        name = _name(row["name"])
        if (name in expected or name not in members or type(row["size"]) is not int or row["size"] != members[name].file_size
                or not isinstance(row["sha256"], str) or not SHA256.fullmatch(row["sha256"])
                or str(PurePosixPath(name).parent) not in directories):
            raise ValueError("Backup manifest and members differ")
        if hashlib.sha256(archive.read(name)).hexdigest() != row["sha256"]:
            raise ValueError("Backup file digest differs")
        expected.add(name)
    if expected != set(members) - {"manifest.json"} or not REQUIRED_FILES <= expected:
        raise ValueError("Backup has missing or unlisted files")
    if any(str(PurePosixPath(name).parent) not in directories for name in directories - {"data", "control"}):
        raise ValueError("Backup directory parent missing")
    config = _decode_json(archive.read("control/workspace.json"))
    required = {"schema_version", "workspace_id", "root", "reports", "oidc_config"}
    if (not isinstance(config, dict) or not required <= set(config) or set(config) - required - {"public_origin", "edge_key_file"}
            or type(config["schema_version"]) is not int or config["schema_version"] != 1
            or config.get("workspace_id") != manifest["workspace_id"] or config.get("root") != manifest["root"]
            or not isinstance(config["reports"], dict) or set(config["reports"]) - set(workspace.REPORTS)
            or (config["oidc_config"] is not None and not isinstance(config["oidc_config"], str))):
        raise ValueError("Backup configuration differs from its workspace declaration")
    private = Path(manifest["control"])
    allowed = {"control/" + name for name in CONTROL_FILES}
    if config.get("edge_key_file") is not None:
        edge = Path(config["edge_key_file"])
        if edge.parent != private:
            raise ValueError("Backup edge key escapes its workspace")
        allowed.add("control/" + edge.name)
    if config.get("oidc_config") is not None:
        oidc = Path(config["oidc_config"])
        if oidc.parent != private:
            raise ValueError("Backup OIDC path escapes its workspace")
        allowed.add("control/" + oidc.name)
        if "control/" + oidc.name not in expected:
            raise ValueError("Backup is missing its OIDC configuration")
        settings = _decode_json(archive.read("control/" + oidc.name))
        if not isinstance(settings, dict) or "client_secret_file" not in settings:
            raise ValueError("Invalid backup OIDC settings")
        if settings["client_secret_file"] is not None:
            secret = Path(settings["client_secret_file"])
            if secret.parent != private:
                raise ValueError("Backup client secret escapes its workspace")
            allowed.add("control/" + secret.name)
    if {name for name in expected if name.startswith("control/")} != allowed:
        raise ValueError("Backup control dependency set differs")
    return manifest


def check(backup_file, sha256):
    with _verified(backup_file, sha256) as (_, manifest):
        pass
    return {"engine": "workspace-backup-integrity", "schema_version": 1, "workspace_id": manifest["workspace_id"],
        "sha256": sha256, "files": len(manifest["files"]), "integrity_valid": True, "owner_authenticity_proven": False,
        "network_requests": 0, "production_ready": False}


def _write(path, raw):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def restore(backup_file, sha256, workspace_id, root, *, authorized=False):
    if authorized is not True:
        raise PermissionError("Workspace restore requires --authorized")
    if workspace._ACTIVE is not None:
        raise ValueError("Restore in a separate administration process")
    result = check(backup_file, sha256)
    root, control = workspace._root(root), operators.control_root()
    with _verified(backup_file, sha256) as (archive, manifest):
        private = control / workspace_id if isinstance(workspace_id, str) and workspace.ID.fullmatch(workspace_id) else None
        if (private is None or workspace_id != manifest["workspace_id"] or str(root) != manifest["root"]
                or str(private) != manifest["control"] or private.exists() or private.is_symlink() or any(root.iterdir())
                or root.is_relative_to(control) or control.is_relative_to(root)):
            raise ValueError("Restore requires the original workspace paths, missing control directory and empty data root")
        workspace._registry()
        with operators.database(control / "workspace-registry.sqlite3", write=True) as registry:
            registry.execute("CREATE TABLE IF NOT EXISTS workspaces(id TEXT PRIMARY KEY, root TEXT UNIQUE NOT NULL)")
            rows = registry.execute("SELECT id,root FROM workspaces").fetchall()
            if (len(rows) >= 32 and not any(row[0] == workspace_id for row in rows)) or any(
                    (row[0] == workspace_id and Path(row[1]) != root) or (row[0] != workspace_id and
                    (root.is_relative_to(Path(row[1])) or Path(row[1]).is_relative_to(root))) for row in rows):
                raise ValueError("Restored workspace overlaps a private registration")
            with tempfile.TemporaryDirectory(prefix="restore-control-", dir=control) as staged_control:
                with tempfile.TemporaryDirectory(prefix="restore-data-", dir=root.parent) as staged_data:
                    stages = {"control": Path(staged_control), "data": Path(staged_data)}
                    for name in sorted(manifest["directories"], key=lambda v: (v.count("/"), v)):
                        parts = PurePosixPath(name).parts
                        stages[parts[0]].joinpath(*parts[1:]).mkdir(mode=0o700, exist_ok=True)
                    for row in manifest["files"]:
                        parts = PurePosixPath(row["name"]).parts
                        raw = archive.read(row["name"])
                        if hashlib.sha256(raw).hexdigest() != row["sha256"]:
                            raise ValueError("Backup changed during recovery")
                        _write(stages[parts[0]].joinpath(*parts[1:]), raw)
                    _reset_recovered_identity(stages, manifest, sha256)
                    # No existing data is overwritten. An interrupted publication
                    # leaves the archive intact; inspect paths before retrying.
                    if any(root.iterdir()) or private.exists():
                        raise ValueError("Restore destinations changed during validation")
                    root.rmdir()  # Only the explicitly authorized empty directory.
                    os.rename(staged_data, root)
                    os.rename(staged_control, private)
                    registry.execute("INSERT OR IGNORE INTO workspaces VALUES(?,?)", (workspace_id, str(root)))
    result.update(restored=True, config_file=str(private / "workspace.json"), accounts_disabled=True, sessions_revoked=True,
        session_and_edge_keys_rotated=True, original_paths_required=True, deployment_review_required=True)
    return result


def _reset_recovered_identity(stages, manifest, source_sha256):
    identity_file = stages["control"] / "operators.sqlite3"
    dashboard = stages["data"] / "state" / "dashboard.sqlite3"
    instance = uuid.uuid4().hex
    operators.status(identity_file)
    operators.audit_status(identity_file)
    with operators.database(identity_file, write=True) as db:
        db.execute("PRAGMA trusted_schema=OFF")
        if (db.execute("PRAGMA quick_check").fetchone()[0] != "ok"
                or db.execute("SELECT instance FROM identity").fetchone()[0] != manifest["identity"]
                or db.execute("SELECT workspace_id FROM operator_workspace WHERE id=1").fetchone()[0] != manifest["workspace_id"]):
            raise ValueError("Recovered identity database does not match the workspace")
        db.execute("UPDATE identity SET instance=?", (instance,))
        db.execute("UPDATE operators SET active=0,version=version+1")
        db.execute("CREATE TABLE IF NOT EXISTS operator_recovery_pending(user_id INTEGER PRIMARY KEY REFERENCES operators(id))")
        db.execute("INSERT OR IGNORE INTO operator_recovery_pending SELECT id FROM operators")
        db.execute("DELETE FROM operator_sessions")
        db.execute("DELETE FROM login_limits")
        if db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='operator_oidc_attempts'").fetchone():
            db.execute("DELETE FROM operator_oidc_attempts")
        operators._event(db, "workspace-restored-accounts-disabled", manifest["workspace_id"], backup_sha256=source_sha256)
    with closing(sqlite3.connect(dashboard)) as db, db:
        db.execute("PRAGMA trusted_schema=OFF")
        binding = db.execute("SELECT workspace_id,identity_instance FROM dashboard_workspace WHERE id=1").fetchone()
        if db.execute("PRAGMA quick_check").fetchone()[0] != "ok" or binding != (manifest["workspace_id"], manifest["identity"]):
            raise ValueError("Recovered dashboard does not match its identity store")
        db.execute("UPDATE dashboard_workspace SET identity_instance=? WHERE id=1", (instance,))
    from types import SimpleNamespace
    recover_interrupted(SimpleNamespace(config={"DATABASE": str(dashboard)}))
    recovered_config = _decode_json(read_bounded(stages["control"] / "workspace.json", 32768))
    rotate = {"session.key", "edge.key"}
    if recovered_config.get("edge_key_file") is not None:
        rotate.add(Path(recovered_config["edge_key_file"]).name)
    for name in sorted(rotate):
        selected = stages["control"] / name
        with selected.open("wb") as stream:
            stream.write(secrets.token_hex(32).encode("ascii") + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
