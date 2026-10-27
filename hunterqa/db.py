from __future__ import annotations
import sqlite3
from pathlib import Path
import click
from flask import Flask, current_app, g

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    path TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'queued',
    progress INTEGER NOT NULL DEFAULT 0 CHECK(progress BETWEEN 0 AND 100),
    stage TEXT NOT NULL DEFAULT 'Queued', error TEXT,
    authorized_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TEXT, finished_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL, title TEXT NOT NULL,
    severity TEXT NOT NULL, cwe TEXT NOT NULL,
    file_path TEXT NOT NULL, line_start INTEGER NOT NULL, line_end INTEGER NOT NULL,
    message TEXT NOT NULL, code TEXT NOT NULL DEFAULT '',
    engine TEXT NOT NULL DEFAULT 'semgrep',
    verification_status TEXT NOT NULL DEFAULT 'unverified'
);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL UNIQUE REFERENCES scans(id) ON DELETE CASCADE,
    model TEXT NOT NULL, content TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS dependency_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, source TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL, subject TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS triage_reviews (
    finding_id TEXT PRIMARY KEY,
    evidence_sha256 TEXT NOT NULL,
    analyst_status TEXT NOT NULL DEFAULT 'new'
        CHECK(analyst_status IN ('new','in_review','confirmed','false_positive','remediated')),
    note TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS triage_review_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL,
    old_status TEXT NOT NULL,
    new_status TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_triage_review_events_finding
    ON triage_review_events(finding_id);

"""


def connect(path: str) -> sqlite3.Connection:
    db = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(_error=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_database(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as db:
        db.executescript(SCHEMA)
        # Incremental, non-destructive migration of existing user's ZeroScope DB.
        cols = {row["name"] for row in db.execute("PRAGMA table_info(findings)")}
        if "engine" not in cols:
            db.execute("ALTER TABLE findings ADD COLUMN engine TEXT NOT NULL DEFAULT 'semgrep'")
        if "verification_status" not in cols:
            db.execute("ALTER TABLE findings ADD COLUMN verification_status TEXT NOT NULL DEFAULT 'unverified'")


@click.command("init-db")
def init_db_command() -> None:
    init_database(current_app.config["DATABASE"])
    click.echo("Initialized the HunterQA database.")


def init_app(app: Flask) -> None:
    init_database(app.config["DATABASE"])
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
