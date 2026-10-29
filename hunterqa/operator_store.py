"""Local dashboard identities. The control-directory OS owner is trusted.

No remote identity provider, assessment permission grant or tenant isolation.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import hashlib
import sqlite3
import time
import uuid
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash

from .doctor import _root_is_safe
from .engagement import digest, utcnow
from .source_files import read_bounded

ROLES = ("viewer", "analyst", "admin")
NAME = re.compile(r"[a-z][a-z0-9_.-]{2,63}\Z", re.ASCII)
HASH_METHOD = "pbkdf2:sha256:1000000"
MAX_AUDIT = 100_000
SESSION_SECONDS = 8 * 60 * 60


def control_root():
    raw = os.environ.get("HUNTERQA_OPERATOR_ROOT", "")
    root = Path(raw).expanduser()
    if not raw or root.drive.startswith("\\\\") or not _root_is_safe(root):
        raise ValueError("Set HUNTERQA_OPERATOR_ROOT to an existing absolute private directory without symlinks")
    package = Path(__file__).resolve().parent
    if root.resolve().is_relative_to(package) or any((parent / ".git").exists() for parent in (root, *root.parents)):
        raise ValueError("Operator control root must stay outside Git checkouts and the installed package")
    if os.name == "posix" and (root.stat().st_mode & 0o077 or root.stat().st_uid != os.geteuid()):
        raise ValueError("Operator control root must be owned by this OS account with mode 0700")
    return root.resolve(strict=True)


def validate_separation(approved_roots):
    root = control_root()
    entries = approved_roots if isinstance(approved_roots, (list, tuple)) else approved_roots.split(os.pathsep)
    for value in entries:
        if not str(value).strip():
            continue
        source = Path(value).expanduser().resolve(strict=True)
        if root.is_relative_to(source) or source.is_relative_to(root):
            raise ValueError("Operator control root and assessment/source roots must not overlap")


def _path(path, *, existing=True):
    root = control_root()
    candidate = Path(path).expanduser()
    if not candidate.is_absolute() or not candidate.is_relative_to(root) or candidate == root or ".." in candidate.parts:
        raise ValueError("Operator database must be within its private control root")
    current = root
    for part in candidate.relative_to(root).parts:
        current /= part
        if current.is_symlink():
            raise ValueError("Symlinked operator database component rejected")
    resolved = candidate.resolve(strict=existing)
    if not resolved.is_relative_to(root):
        raise ValueError("Operator database must be within its private control root")
    if existing:
        if not resolved.is_file() or resolved.stat().st_size > 64_000_000:
            raise ValueError("Invalid or oversized operator database")
        if os.name == "posix" and (resolved.stat().st_mode & 0o077 or resolved.stat().st_uid != os.geteuid()):
            raise ValueError("Operator database must be owned by this OS account with mode 0600")
    return resolved


def create_session_key(path, *, authorized=False):
    if not authorized:
        raise PermissionError("Session key creation requires --authorized")
    destination = _path(path, existing=False)
    if not destination.parent.is_dir():
        raise ValueError("Create the private session-key parent first")
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(secrets.token_hex(32).encode("ascii") + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    return {"created": True, "secret_file": str(destination), "secret_value_displayed": False}


def read_session_key(path):
    raw = read_bounded(_path(path), 66)
    if not re.fullmatch(rb"[a-f0-9]{64}(?:\r?\n)?", raw):
        raise ValueError("Session key file must contain one generated 64-character hexadecimal key")
    return raw.decode("ascii").strip()


@contextmanager
def database(path, *, write=False):
    connection = sqlite3.connect(_path(path).as_uri() + ("?mode=rw" if write else "?mode=ro"), uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def _name(value):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ValueError("Username must be 3..64 lowercase ASCII letters, digits, dots, underscores or hyphens")
    return value


def _password(value):
    if not isinstance(value, str) or not 14 <= len(value) <= 256 or "\x00" in value:
        raise ValueError("Use a password of 14..256 characters without NUL")
    return generate_password_hash(value, method=HASH_METHOD)


@lru_cache(maxsize=1)
def dummy_hash():
    return generate_password_hash("not-an-authenticatable-operator", method=HASH_METHOD)


def _event(db, action, subject, **details):
    last = db.execute("SELECT seq, value, sha256 FROM operator_audit ORDER BY seq DESC LIMIT 1").fetchone()
    if last and digest(json.loads(last["value"])) != last["sha256"]:
        raise ValueError("Operator audit head is inconsistent")
    seq = last["seq"] + 1 if last else 1
    if seq > MAX_AUDIT:
        raise ValueError("Operator audit capacity reached; preserve and rotate through OS administration")
    value = {"seq": seq, "time": utcnow().isoformat(), "action": action,
             "subject": subject, "details": details, "previous": last["sha256"] if last else "0" * 64}
    db.execute("INSERT INTO operator_audit VALUES (?, ?, ?)", (seq, json.dumps(value), digest(value)))


def initialize(path, username, password, *, authorized=False):
    if not authorized:
        raise PermissionError("Operator initialization requires --authorized")
    _name(username)
    password_hash = _password(password)
    validate_separation(os.environ.get("HUNTERQA_APPROVED_ROOTS", ""))
    destination = _path(path, existing=False)
    if not destination.parent.is_dir():
        raise ValueError("Create the private operator database parent first")
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.close(fd)
    with database(destination, write=True) as db:
        db.executescript("""
            CREATE TABLE identity (instance TEXT PRIMARY KEY);
            CREATE TABLE operators (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL,
                version INTEGER NOT NULL);
            CREATE TABLE login_limits (key TEXT PRIMARY KEY, started REAL NOT NULL, count INTEGER NOT NULL);
            CREATE TABLE operator_sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
                version INTEGER NOT NULL, issued REAL NOT NULL, expires REAL NOT NULL);
            CREATE TABLE operator_audit (seq INTEGER PRIMARY KEY, value TEXT NOT NULL, sha256 TEXT NOT NULL);
        """)
        db.execute("INSERT INTO identity VALUES (?)", (uuid.uuid4().hex,))
        db.execute("INSERT INTO operators VALUES (1, ?, ?, 'admin', 1, 1)", (username, password_hash))
        _event(db, "os-admin-initialized", username, role="admin", active=True)
    return status(destination)


def add_operator(path, username, role, password, *, authorized=False):
    if not authorized:
        raise PermissionError("Operator creation requires --authorized")
    _name(username)
    if role not in ROLES:
        raise ValueError("Unsupported operator role")
    password_hash = _password(password)
    with database(path, write=True) as db:
        if db.execute("SELECT COUNT(*) FROM operators").fetchone()[0] >= 256:
            raise ValueError("Operator limit reached")
        db.execute("INSERT INTO operators(username,password_hash,role,active,version) VALUES (?, ?, ?, 1, 1)",
                   (username, password_hash, role))
        _event(db, "os-admin-added-operator", username, role=role, active=True)
    return status(path)


def update_operator(path, username, *, role=None, active=None, password=None, authorized=False):
    if not authorized:
        raise PermissionError("Operator updates require --authorized")
    _name(username)
    if (role is not None and role not in ROLES) or (active is not None and type(active) is not bool):
        raise ValueError("Invalid operator update")
    if role is None and active is None and password is None:
        raise ValueError("Select a role, enabled state or password reset")
    password_hash = _password(password) if password is not None else None
    with database(path, write=True) as db:
        row = db.execute("SELECT * FROM operators WHERE username=?", (username,)).fetchone()
        if row is None:
            raise ValueError("Unknown operator")
        new_role, new_active = role if role is not None else row["role"], int(active) if active is not None else row["active"]
        if row["role"] == "admin" and row["active"] and (new_role != "admin" or not new_active):
            if db.execute("SELECT COUNT(*) FROM operators WHERE role='admin' AND active=1").fetchone()[0] <= 1:
                raise ValueError("Cannot disable or demote the last active administrator")
        db.execute("UPDATE operators SET role=?,active=?,password_hash=?,version=version+1 WHERE id=?",
                   (new_role, new_active, password_hash or row["password_hash"], row["id"]))
        db.execute("DELETE FROM operator_sessions WHERE user_id=?", (row["id"],))
        _event(db, "os-admin-updated-and-revoked-sessions", username,
            old_role=row["role"], new_role=new_role, old_active=bool(row["active"]),
            new_active=bool(new_active), password_reset=password is not None)
    return status(path)


def _public(row):
    if row["role"] not in ROLES or row["active"] not in (0, 1) or row["version"] < 1:
        raise ValueError("Invalid operator record")
    return {key: row[key] for key in ("id", "username", "role", "active", "version")}


def status(path):
    with database(path) as db:
        instance = db.execute("SELECT instance FROM identity").fetchall()
        if len(instance) != 1 or not re.fullmatch(r"[a-f0-9]{32}", instance[0][0]):
            raise ValueError("Invalid operator database identity")
        users = [_public(row) for row in db.execute("SELECT id,username,role,active,version FROM operators ORDER BY id LIMIT 257")]
        if not 1 <= len(users) <= 256 or not any(u["role"] == "admin" and u["active"] for u in users):
            raise ValueError("An active administrator is required")
        return {"instance": instance[0][0], "operators": users,
                "trust": "Local dashboard roles; OS/control-directory owner is trusted; no tenant or assessment authorization"}


def _token_hash(token):
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        return None
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def session_operator(path, token, instance):
    token_hash = _token_hash(token)
    if token_hash is None:
        return None
    with database(path) as db:
        identity = db.execute("SELECT instance FROM identity").fetchone()
        if not identity or identity[0] != instance:
            return None
        record = db.execute("SELECT * FROM operator_sessions WHERE token_hash=?", (token_hash,)).fetchone()
        now = time.time()
        if record is None or not record["issued"] <= now < record["expires"] or record["expires"] - record["issued"] > SESSION_SECONDS:
            return None
        row = db.execute("SELECT id,username,role,active,version FROM operators WHERE id=?", (record["user_id"],)).fetchone()
        if row is None or not row["active"] or row["version"] != record["version"]:
            return None
        return _public(row)


def authenticate(path, username, password, peer):
    name = username if isinstance(username, str) and NAME.fullmatch(username) else "<invalid>"
    bounded = isinstance(password, str) and len(password) <= 256 and "\x00" not in password
    now = time.time()
    with database(path, write=True) as db:
        db.execute("DELETE FROM login_limits WHERE started<?", (now - 600,))
        keys = [("all", 200), (digest("peer:" + peer), 60), (digest("user:" + name), 10)]
        for key, maximum in keys:
            row = db.execute("SELECT count FROM login_limits WHERE key=?", (key,)).fetchone()
            if row and row[0] >= maximum:
                _event(db, "login-throttled", name)
                return None, "throttled", None, None
        for key, _ in keys:
            db.execute("INSERT INTO login_limits VALUES (?, ?, 1) ON CONFLICT(key) DO UPDATE SET count=count+1", (key, now))
        row = db.execute("SELECT * FROM operators WHERE username=?", (name,)).fetchone()
        expected = row["password_hash"] if row else dummy_hash()
        matched = check_password_hash(expected, password if bounded else "invalid-bounded-password")
        if not row or not row["active"] or not bounded or not matched:
            _event(db, "login-failed", name)
            return None, "failed", None, None
        user = _public(row)
        instance = db.execute("SELECT instance FROM identity").fetchone()[0]
        db.execute("DELETE FROM operator_sessions WHERE expires<=?", (now,))
        old = db.execute("SELECT token_hash FROM operator_sessions WHERE user_id=? ORDER BY issued DESC LIMIT -1 OFFSET 7", (user["id"],)).fetchall()
        for record in old:
            db.execute("DELETE FROM operator_sessions WHERE token_hash=?", (record[0],))
        token = secrets.token_urlsafe(32)
        db.execute("INSERT INTO operator_sessions VALUES (?, ?, ?, ?, ?)",
                   (_token_hash(token), user["id"], user["version"], now, now + SESSION_SECONDS))
        _event(db, "login-succeeded", user["username"])
        return user, "ok", instance, token


def revoke_session(path, token):
    token_hash = _token_hash(token)
    if token_hash is None:
        return
    with database(path, write=True) as db:
        row = db.execute("SELECT username FROM operators JOIN operator_sessions ON operators.id=operator_sessions.user_id WHERE token_hash=?", (token_hash,)).fetchone()
        db.execute("DELETE FROM operator_sessions WHERE token_hash=?", (token_hash,))
        if row:
            _event(db, "logged-out", row[0])


def audit_event(path, action, subject):
    with database(path, write=True) as db:
        _event(db, action, subject)


def audit_status(path):
    with database(path) as db:
        previous, count = "0" * 64, 0
        for row in db.execute("SELECT * FROM operator_audit ORDER BY seq LIMIT 100001"):
            count += 1
            value = json.loads(row["value"])
            if (count > MAX_AUDIT or row["seq"] != count or value["seq"] != count
                    or value["previous"] != previous or digest(value) != row["sha256"]):
                raise ValueError("Operator audit chain is inconsistent")
            previous = row["sha256"]
    return {"events": count, "head_sha256": previous,
            "trust": "Consistency check only; a database owner can forge history"}
