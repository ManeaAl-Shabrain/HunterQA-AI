"""Private durable run records. Hash links detect edits, not owner forgery."""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .bounty import _approved_file
from .engagement import digest, utcnow


def approved_directory(path):
    candidate = Path(path).expanduser().absolute()
    if candidate.is_symlink():
        raise ValueError("Symlinked directory rejected")
    resolved = candidate.resolve(strict=True)
    for value in os.environ.get("HUNTERQA_APPROVED_ROOTS", "").split(os.pathsep):
        if not value:
            continue
        root = Path(value).expanduser().resolve(strict=True)
        if root.is_dir() and resolved.is_dir() and resolved.is_relative_to(root):
            current = root
            for part in candidate.relative_to(root).parts:
                current = current / part
                if current.is_symlink():
                    raise ValueError("Symlinked directory component rejected")
            return resolved
    raise ValueError("Directory is outside approved local roots")


def private_write(path, value):
    raw = (json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False) + "\n").encode()
    if len(raw) > 2_000_000:
        raise ValueError("Workflow artifact exceeds size limit")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


@contextmanager
def run_lock(run):
    path = approved_directory(run) / "coordinator.lock"
    if path.is_symlink():
        raise ValueError("Symlinked coordinator lock rejected")
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    if os.fstat(fd).st_size == 0:
        os.write(fd, b"0")
    os.lseek(fd, 0, os.SEEK_SET)
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise ValueError("Run coordinator/reviewer lock is held") from None
    try:
        yield
    finally:
        if os.name == "nt":
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


class Store:
    def __init__(self, run, *, create=False, readonly=False):
        self.run = approved_directory(run)
        path = self.run / "run.sqlite3"
        if create:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        path = _approved_file(path)
        if path.stat().st_size > 64_000_000:
            raise ValueError("Workflow database exceeds size limit")
        self.db = sqlite3.connect(path.as_uri() + ("?mode=ro" if readonly else "?mode=rw"), uri=True)
        self.db.row_factory = sqlite3.Row
        if create:
            self.db.executescript("""
                CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE steps (id TEXT PRIMARY KEY, tool TEXT, state TEXT,
                    result TEXT, error TEXT);
                CREATE TABLE events (seq INTEGER PRIMARY KEY, value TEXT NOT NULL,
                    fingerprint TEXT NOT NULL);
                CREATE TABLE reviews (finding TEXT PRIMARY KEY, value TEXT NOT NULL);
            """)
            self.db.commit()

    def close(self):
        self.db.close()

    def meta(self, key, value=None):
        if value is not None:
            with self.db:
                self.db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, json.dumps(value)))
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def event(self, kind, **details):
        last = self.db.execute("SELECT seq, fingerprint FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        value = {"seq": last[0] + 1 if last else 1, "time": utcnow().isoformat(),
                 "kind": kind, "details": details, "previous": last[1] if last else "0" * 64}
        if value["seq"] > 2000:
            raise ValueError("Workflow event limit exceeded")
        with self.db:
            self.db.execute("INSERT INTO events VALUES (?, ?, ?)",
                            (value["seq"], json.dumps(value), digest(value)))

    def audited_meta(self, key, value, kind, **details):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, json.dumps(value)))
            self.event(kind, **details)

    def verify(self):
        previous, count = "0" * 64, 0
        for row in self.db.execute("SELECT * FROM events ORDER BY seq LIMIT 2001"):
            count += 1
            value = json.loads(row["value"])
            if (count > 2000 or row["seq"] != count or value.get("seq") != count
                    or value.get("previous") != previous or digest(value) != row["fingerprint"]):
                raise ValueError("Workflow audit chain mismatch")
            previous = row["fingerprint"]
        return count, previous

    def state(self, step, status, *, result=None, error=None):
        with self.db:
            self.db.execute("UPDATE steps SET state=?, result=?, error=? WHERE id=?",
                            (status, json.dumps(result) if result is not None else None, error, step))
            self.event("step-state", step=step, state=status,
                       result_sha256=digest(result) if result is not None else None, error_type=error)

    def steps(self):
        return [dict(row) for row in self.db.execute("SELECT * FROM steps ORDER BY id LIMIT 65")]

    def check_results(self):
        from .bounty import _read_json
        latest = {}
        for row in self.db.execute("SELECT value FROM events ORDER BY seq LIMIT 2001"):
            value = json.loads(row[0])
            if value["kind"] == "step-state":
                latest[value["details"]["step"]] = value["details"]
        for step in self.steps():
            recorded = latest.get(step["id"])
            if recorded:
                result = json.loads(step["result"]) if step["result"] else None
                if (recorded["state"] != step["state"] or recorded["error_type"] != step["error"]
                        or recorded["result_sha256"] != (digest(result) if result is not None else None)):
                    raise ValueError("Workflow result does not match audit record")
                if result is not None:
                    artifact = _read_json(self.run / f"{step['id']}.result.json", 2_000_000)
                    if digest(artifact) != digest(result):
                        raise ValueError("Worker artifact does not match recorded result")
            elif step["state"] != "pending" or step["result"] is not None:
                raise ValueError("Workflow step lacks audit record")
