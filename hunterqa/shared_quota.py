"""Atomic host-local reservations shared by cooperating workflow coordinators.

The database owner remains trusted. This is not a tenant authorization service.
"""
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .bounty import _approved_file
from .engagement import _expiry, digest, utcnow
from .workflow_protocol import _fields, _integer
from .workflow_store import approved_directory


@contextmanager
def _database(path):
    path = _approved_file(path)
    if path.stat().st_size > 16_000_000:
        raise ValueError("Quota ledger exceeds size limit")
    db = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=5)
    try:
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("BEGIN IMMEDIATE")
        yield db
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def initialize(path, *, max_requests, max_active_runs, expires_at, authorized=False):
    if not authorized:
        raise PermissionError("Quota initialization requires --authorized")
    _integer(max_requests, 1, 1_000_000, "max_requests")
    _integer(max_active_runs, 1, 64, "max_active_runs")
    if not 0 < (_expiry(expires_at) - utcnow()).total_seconds() <= 86_400:
        raise ValueError("Quota window must expire within 24 hours")
    destination = Path(path).expanduser().absolute()
    parent = approved_directory(destination.parent)
    destination = parent / destination.name
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    with _database(destination) as db:
        db.executescript("""
            CREATE TABLE configuration (id INTEGER PRIMARY KEY CHECK(id=1),
                max_requests INTEGER NOT NULL, max_active_runs INTEGER NOT NULL,
                expires_at TEXT NOT NULL, stopped INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE reservations (run_id TEXT PRIMARY KEY,
                requests INTEGER NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL);
        """)
        db.execute("INSERT INTO configuration VALUES (1, ?, ?, ?, 0)",
                   (max_requests, max_active_runs, expires_at))
    return status(destination)


def _configuration(db):
    row = db.execute("SELECT max_requests, max_active_runs, expires_at, stopped FROM configuration WHERE id=1").fetchone()
    if row is None:
        raise ValueError("Invalid quota configuration")
    _integer(row[0], 1, 1_000_000, "max_requests")
    _integer(row[1], 1, 64, "max_active_runs")
    _expiry(row[2])
    if row[3] not in (0, 1):
        raise ValueError("Invalid quota stop state")
    return {"max_requests": row[0], "max_active_runs": row[1], "expires_at": row[2]}, bool(row[3])


def status(path):
    with _database(path) as db:
        config, stopped = _configuration(db)
        charged, active = db.execute("SELECT COALESCE(SUM(requests),0), COALESCE(SUM(state='active'),0) FROM reservations").fetchone()
        reservations = [{"run_id": row[0], "requests": row[1], "created_at": row[2]} for row in
            db.execute("SELECT run_id, requests, created_at FROM reservations WHERE state='active' ORDER BY created_at LIMIT 64")]
    return {"configuration": config, "configuration_sha256": digest(config),
            "charged_requests": charged, "active_runs": active,
            "active_reservations": reservations,
            "stopped": stopped, "expired": utcnow() >= _expiry(config["expires_at"]),
            "trust": "Cooperating local coordinators; database owner is trusted; no refunds"}


def configured_review():
    value = os.environ.get("HUNTERQA_QUOTA_LEDGER")
    if not value:
        return None
    path = _approved_file(value)
    snapshot = status(path)
    if snapshot["stopped"] or snapshot["expired"]:
        raise PermissionError("Shared quota ledger is stopped or expired")
    return {"path": str(path), "configuration_sha256": snapshot["configuration_sha256"]}


def reserve(review, run_id, requests):
    _fields(review, ("path", "configuration_sha256"), "quota review")
    _integer(requests, 0, 40, "run reservation")
    with _database(review["path"]) as db:
        config, stopped = _configuration(db)
        if digest(config) != review["configuration_sha256"] or stopped or utcnow() >= _expiry(config["expires_at"]):
            raise PermissionError("Shared quota configuration changed, stopped or expired")
        charged, active = db.execute("SELECT COALESCE(SUM(requests),0), COALESCE(SUM(state='active'),0) FROM reservations").fetchone()
        if charged + requests > config["max_requests"] or active >= config["max_active_runs"]:
            raise PermissionError("Shared request or active-run quota exhausted")
        db.execute("INSERT INTO reservations VALUES (?, ?, 'active', ?)", (run_id, requests, utcnow().isoformat()))


def check(review, run_id):
    with _database(review["path"]) as db:
        config, stopped = _configuration(db)
        row = db.execute("SELECT state FROM reservations WHERE run_id=?", (run_id,)).fetchone()
        return (digest(config) == review["configuration_sha256"] and not stopped
                and utcnow() < _expiry(config["expires_at"]) and row == ("active",))


def release(review, run_id):
    with _database(review["path"]) as db:
        db.execute("UPDATE reservations SET state='released' WHERE run_id=? AND state='active'", (run_id,))


def stop(path, *, authorized=False):
    if not authorized:
        raise PermissionError("Shared quota stop requires --authorized")
    with _database(path) as db:
        db.execute("UPDATE configuration SET stopped=1 WHERE id=1")
    return status(path)


def reconcile(path, run_id, *, authorized=False):
    """Explicit operator recovery; only after confirming the coordinator is dead."""
    if not authorized:
        raise PermissionError("Quota reconciliation requires --authorized")
    release({"path": str(_approved_file(path))}, run_id)
    return status(path)
