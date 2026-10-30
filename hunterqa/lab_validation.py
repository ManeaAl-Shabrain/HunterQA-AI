"""Fixed, in-process SQL impact demonstration on original synthetic data only."""
from __future__ import annotations

import hashlib
import sqlite3
from contextlib import closing
from pathlib import Path

from .bounty import _read_json
from .engagement import digest, utcnow
from .workflow_store import approved_directory, private_write

LABELS = Path(__file__).parent / "fixtures" / "sql-impact-v1.json"
INPUTS = {"baseline": "missing", "negative": "missing' AND 1=0 -- ",
          "legitimate": "visible", "probe": "missing' OR owner='owner' -- "}
FOREIGN = "HUNTERQA_SYNTHETIC_FOREIGN_ROW"
OWN = "HUNTERQA_SYNTHETIC_OWN_ROW"


def _labels():
    import json
    return json.loads(LABELS.read_bytes())


def _query(db, mode, value):
    # The vulnerable variant is intentionally restricted to this in-memory toy.
    # There is no target, query, payload, executable or data-source input API.
    prefix = "SELECT marker FROM records WHERE owner='viewer' AND name="
    query = prefix + "?" if mode == "bound" else prefix + "'" + value + "'"
    rows = db.execute(query, (value,) if mode == "bound" else ()).fetchall()
    return rows, hashlib.sha256(query.encode()).hexdigest()


def _observations(labels):
    with closing(sqlite3.connect(":memory:")) as db:
        db.execute("CREATE TABLE records (owner TEXT, name TEXT, marker TEXT)")
        db.executemany("INSERT INTO records VALUES (?, ?, ?)",
                       [("viewer", "visible", OWN), ("owner", "private", FOREIGN)])
        db.commit()
        db.execute("PRAGMA query_only=ON")
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 4096)
        db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 4096)
        db.set_progress_handler(lambda: 1, 10000)
        # Fixed SELECTs can read only this toy table after initialization.
        db.set_authorizer(lambda action, *args: sqlite3.SQLITE_OK
                          if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ)
                          else sqlite3.SQLITE_DENY)
        observations = []
        for case in labels["cases"]:
            rows, query_hash = _query(db, case["mode"], INPUTS[case["variant"]])
            observations.append({"id": case["id"], "rows": len(rows),
                "foreign_read": any(row == (FOREIGN,) for row in rows),
                "query_sha256": query_hash, "result_sha256": digest(rows)})
        return observations


def _measure(labels, observations):
    if not isinstance(observations, list) or len(observations) != len(labels["cases"]):
        raise ValueError("Invalid owned SQL observations")
    cases, tp, fp, fn = [], 0, 0, 0
    for expected, observed in zip(labels["cases"], observations):
        if (not isinstance(observed, dict) or set(observed) != {"id", "rows", "foreign_read", "query_sha256", "result_sha256"}
                or observed["id"] != expected["id"] or type(observed["rows"]) is not int
                or not 0 <= observed["rows"] <= 2 or type(observed["foreign_read"]) is not bool
                or any(not isinstance(observed[key], str) or len(observed[key]) != 64
                    or any(c not in "0123456789abcdef" for c in observed[key])
                    for key in ("query_sha256", "result_sha256"))):
            raise ValueError("Invalid owned SQL observation fields")
        predicted, truth = observed["foreign_read"], expected["expected_foreign_read"]
        tp += int(predicted and truth)
        fp += int(predicted and not truth)
        fn += int(not predicted and truth)
        cases.append({"id": expected["id"], "matched": observed["rows"] == expected["expected_rows"]
                      and predicted == truth})
    matched = all(case["matched"] for case in cases)
    return {"cases": cases, "all_cases_matched": matched,
            "true_positives": tp, "false_positives": fp, "false_negatives": fn,
            "impact_demonstrated_in_owned_fixture": matched and tp == 1 and fp == fn == 0,
            "scope": "original in-memory fixture only"}


def validate_owned_sql(out_dir, *, authorized=False):
    if not authorized:
        raise PermissionError("Owned SQL validation requires --authorized")
    root = Path(out_dir).expanduser().absolute()
    approved_directory(root.parent)
    root.mkdir(mode=0o700)
    labels = _labels()
    private_write(root / "ground-truth.json", labels)
    observations = _observations(labels)
    private_write(root / "observations.json", observations)
    report = {"engine": "hunterqa_owned_sql_impact", "schema_version": 1,
        "generated_at": utcnow().isoformat(), "fixture_version": labels["fixture_version"],
        "fixture_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "labels_sha256": hashlib.sha256(LABELS.read_bytes()).hexdigest(),
        "observations_sha256": digest(observations), **_measure(labels, observations),
        "network_requests": 0, "external_tools_executed": 0,
        "real_world_effectiveness": "unverified", "customer_findings_confirmed": 0,
        "limitations": ["Eight fixed cases on two synthetic rows; no external target or user-supplied query/payload",
            "Demonstrates a cross-owner row read only in the intentionally vulnerable toy, compared with its parameterized control",
            "Does not validate the HTTP SQL-error scanner, authentication, a customer vulnerability or general SQLi coverage",
            "Local hash consistency is not independent provenance; the evidence-directory owner is trusted"]}
    private_write(root / "validation.json", report)
    return report


def verify_owned_sql(directory):
    """Check local receipts and replay deterministic fixed cases, never a target."""
    root = approved_directory(directory)
    report = _read_json(root / "validation.json", 65536)
    observations = _read_json(root / "observations.json", 65536)
    labels = _labels()
    if (not isinstance(report, dict) or report.get("engine") != "hunterqa_owned_sql_impact"
            or type(report.get("schema_version")) is not int or report["schema_version"] != 1
            or report.get("fixture_version") != labels["fixture_version"]
            or report.get("fixture_source_sha256") != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            or report.get("labels_sha256") != hashlib.sha256(LABELS.read_bytes()).hexdigest()
            or _read_json(root / "ground-truth.json", 65536) != labels
            or report.get("observations_sha256") != digest(observations)):
        raise ValueError("Owned SQL evidence is stale or inconsistent")
    if (any(type(report.get(key)) is not int or report[key] != 0 for key in
            ("network_requests", "external_tools_executed", "customer_findings_confirmed"))
            or report.get("real_world_effectiveness") != "unverified"):
        raise ValueError("Owned SQL evidence overstates its scope")
    measured = _measure(labels, observations)
    if any(digest(report.get(key)) != digest(value) for key, value in measured.items()):
        raise ValueError("Owned SQL evidence claims do not match observations")
    if digest(observations) != digest(_observations(labels)):
        raise ValueError("Owned SQL observations do not match deterministic local replay")
    return {"status": "integrity_checked_and_locally_replayed",
            "passed": measured["all_cases_matched"], **measured,
            "network_requests": 0, "real_world_effectiveness": "unverified",
            "trust": "Local consistency and original fixture replay only; not an independent audit"}
